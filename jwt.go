package traefik_jwt_plugin

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// map of cancel  functions for background refresh. whe a new configuration is loaded, the old background refresh with the same name is cancelled
var backgroundRefreshCancel map[string]context.CancelFunc = make(map[string]context.CancelFunc)

// Config the plugin configuration.
type Config struct {
	OpaUrl             string
	OpaAllowField      string
	OpaBody            bool
	OpaDebugMode       bool
	PayloadFields      []string
	Required           bool
	Keys               []string
	ForceRefreshKeys   bool
	Alg                string
	OpaHeaders         map[string]string
	JwtHeaders         map[string]string
	JwksHeaders        map[string]string
	OpaResponseHeaders map[string]string
	OpaHttpStatusField string
	JwtCookieKey       string
	JwtQueryKey        string
}

// CreateConfig creates a new OPA Config
func CreateConfig() *Config {
	return &Config{
		Required:      true, // default to Authorization JWT header is required
		OpaAllowField: "allow",
		OpaBody:       true,
	}
}

// JwtPlugin contains the runtime config
type JwtPlugin struct {
	httpClient         *http.Client
	next               http.Handler
	opaUrl             string
	opaAllowField      string
	opaBody            bool
	opaDebugMode       bool
	payloadFields      []string
	required           bool
	jwkEndpoints       []*url.URL
	keys               map[string]interface{}
	alg                string
	opaHeaders         map[string]string
	jwtHeaders         map[string]string
	jwksHeaders        map[string]string
	opaResponseHeaders map[string]string
	opaHttpStatusField string
	jwtCookieKey       string
	jwtQueryKey        string

	name            string
	keysLock        sync.RWMutex
	forceRefreshCmd chan chan<- struct{}
	cancelCtx       context.Context
}

// LogEvent contains a single log entry
type LogEvent struct {
	Level   string    `json:"level"`
	Msg     string    `json:"msg"`
	Time    time.Time `json:"time"`
	Network Network   `json:"network"`
	URL     string    `json:"url"`
	Sub     string    `json:"sub"`
}

type Network struct {
	Client `json:"client"`
}

type Client struct {
	IP   string `json:"ip"`
	Port int    `json:"port"`
}

type JwtHeader struct {
	Alg  string   `json:"alg"`
	Kid  string   `json:"kid"`
	Typ  string   `json:"typ"`
	Cty  string   `json:"cty"`
	Crit []string `json:"crit"`
}

type JWT struct {
	Plaintext []byte
	Signature []byte
	Header    JwtHeader
	Payload   map[string]interface{}
}

var supportedHeaderNames = map[string]struct{}{"alg": {}, "kid": {}, "typ": {}, "cty": {}, "crit": {}}

// Key is a JSON web key returned by the JWKS request.
type Key struct {
	Kid string   `json:"kid"`
	Kty string   `json:"kty"`
	Alg string   `json:"alg"`
	Use string   `json:"use"`
	X5c []string `json:"x5c"`
	X5t string   `json:"x5t"`
	N   string   `json:"n"`
	E   string   `json:"e"`
	K   string   `json:"k,omitempty"`
	X   string   `json:"x,omitempty"`
	Y   string   `json:"y,omitempty"`
	D   string   `json:"d,omitempty"`
	P   string   `json:"p,omitempty"`
	Q   string   `json:"q,omitempty"`
	Dp  string   `json:"dp,omitempty"`
	Dq  string   `json:"dq,omitempty"`
	Qi  string   `json:"qi,omitempty"`
	Crv string   `json:"crv,omitempty"`
}

// Keys represents a set of JSON web keys.
type Keys struct {
	// Keys is an array of JSON web keys.
	Keys []Key `json:"keys"`
}

// PayloadInput is the input payload
type PayloadInput struct {
	Host       string                 `json:"host"`
	Method     string                 `json:"method"`
	Path       []string               `json:"path"`
	Parameters url.Values             `json:"parameters"`
	Headers    map[string][]string    `json:"headers"`
	JWTHeader  JwtHeader              `json:"tokenHeader"`
	JWTPayload map[string]interface{} `json:"tokenPayload"`
	Body       interface{}            `json:"body,omitempty"`
	Form       url.Values             `json:"form,omitempty"`
}

// Payload for OPA requests
type Payload struct {
	Input *PayloadInput `json:"input"`
}

// Response from OPA
type Response struct {
	Result map[string]json.RawMessage `json:"result"`
}

// New creates a new plugin
func New(ctx context.Context, next http.Handler, config *Config, pluginName string) (http.Handler, error) {
	jwtPlugin := &JwtPlugin{
		httpClient:         &http.Client{},
		next:               next,
		opaUrl:             config.OpaUrl,
		opaAllowField:      config.OpaAllowField,
		opaBody:            config.OpaBody,
		opaDebugMode:       config.OpaDebugMode,
		payloadFields:      config.PayloadFields,
		required:           config.Required,
		alg:                config.Alg,
		keys:               make(map[string]interface{}),
		opaHeaders:         config.OpaHeaders,
		jwtHeaders:         config.JwtHeaders,
		jwksHeaders:        config.JwksHeaders,
		opaResponseHeaders: config.OpaResponseHeaders,
		opaHttpStatusField: config.OpaHttpStatusField,
		jwtCookieKey:       config.JwtCookieKey,
		jwtQueryKey:        config.JwtQueryKey,
		name:               pluginName,
	}
	if len(config.Keys) > 0 {
		if err := jwtPlugin.ParseKeys(config.Keys); err != nil {
			return nil, err
		}
		if len(jwtPlugin.jwkEndpoints) > 0 {
			if config.ForceRefreshKeys {
				jwtPlugin.forceRefreshCmd = make(chan chan<- struct{})
			}
			if backgroundRefreshCancel[pluginName] != nil {
				logInfo(fmt.Sprintf("Cancel BackgroundRefresh %s", pluginName)).print()
				backgroundRefreshCancel[pluginName]()
			}
			cancel, cancelFunc := context.WithCancel(ctx)
			backgroundRefreshCancel[pluginName] = cancelFunc
			jwtPlugin.cancelCtx = cancel
			go jwtPlugin.BackgroundRefresh()
		}
	}
	return jwtPlugin, nil
}

func (jwtPlugin *JwtPlugin) BackgroundRefresh() {
	jwtPlugin.FetchKeys()
	for {
		select {
		case keysFetchedChan := <-jwtPlugin.forceRefreshCmd:
			jwtPlugin.FetchKeys()
			keysFetchedChan <- struct{}{}
		case <-jwtPlugin.cancelCtx.Done():
			logInfo(fmt.Sprintf("Quit BackgroundRefresh for %s", jwtPlugin.name)).print()
			return
		case <-time.After(15 * time.Minute):
			jwtPlugin.FetchKeys()
		}
	}
}

func (jwtPlugin *JwtPlugin) forceRefreshKeys() (refreshed bool) {
	if jwtPlugin.forceRefreshCmd == nil || len(jwtPlugin.jwkEndpoints) == 0 {
		return
	}
	refreshedCh := make(chan struct{})
	jwtPlugin.forceRefreshCmd <- refreshedCh
	<-refreshedCh
	refreshed = true
	return
}

func (jwtPlugin *JwtPlugin) ParseKeys(certificates []string) error {
	jwtPlugin.keysLock.Lock()
	defer jwtPlugin.keysLock.Unlock()

	for _, certificate := range certificates {
		if block, rest := pem.Decode([]byte(certificate)); block != nil {
			if len(rest) > 0 {
				return fmt.Errorf("extra data after a PEM certificate block")
			}
			if block.Type == "CERTIFICATE" {
				cert, err := x509.ParseCertificate(block.Bytes)
				if err != nil {
					return fmt.Errorf("failed to parse a PEM certificate: %v", err)
				}
				jwtPlugin.keys[base64.RawURLEncoding.EncodeToString(cert.SubjectKeyId)] = cert.PublicKey
			} else if block.Type == "PUBLIC KEY" || block.Type == "RSA PUBLIC KEY" {
				key, err := x509.ParsePKIXPublicKey(block.Bytes)
				if err != nil {
					return fmt.Errorf("failed to parse a PEM public key: %v", err)
				}
				jwtPlugin.keys[strconv.Itoa(len(jwtPlugin.keys))] = key
			} else {
				return fmt.Errorf("failed to extract a Key from the PEM certificate")
			}
		} else if u, err := url.ParseRequestURI(certificate); err == nil {
			jwtPlugin.jwkEndpoints = append(jwtPlugin.jwkEndpoints, u)
		} else {
			return fmt.Errorf("Invalid configuration, expecting a certificate, public key or JWK URL")
		}
	}
	return nil
}

func (jwtPlugin *JwtPlugin) FetchKeys() {
	logInfo(fmt.Sprintf("FetchKeys - #%d jwkEndpoints to fetch", len(jwtPlugin.jwkEndpoints))).
		print()
	fetchedKeys := map[string]interface{}{}
	for _, u := range jwtPlugin.jwkEndpoints {
		req, err := http.NewRequest("GET", u.String(), nil)
		if err != nil {
			logWarn("FetchKeys - Failed to create request").withUrl(u.String()).print()
			continue
		}
		for headerKey, headerValue := range jwtPlugin.jwksHeaders {
			req.Header.Add(headerKey, headerValue)
		}
		response, err := jwtPlugin.httpClient.Do(req)
		if err != nil {
			logWarn("FetchKeys - Failed to fetch keys").withUrl(u.String()).print()
			continue
		}
		body, err := io.ReadAll(response.Body)
		if err != nil {
			logWarn("FetchKeys - Failed to read keys").withUrl(u.String()).print()
			continue
		}
		var jwksKeys Keys
		err = json.Unmarshal(body, &jwksKeys)
		if err != nil {
			logWarn("FetchKeys - Failed to unmarshal keys").withUrl(u.String()).print()
			continue
		}
		for _, key := range jwksKeys.Keys {
			switch key.Kty {
			case "RSA":
				{
					if key.Kid == "" {
						key.Kid, err = JWKThumbprint(fmt.Sprintf(`{"e":"%s","kty":"RSA","n":"%s"}`, key.E, key.N))
						if err != nil {
							break
						}
					}
					nBytes, err := base64.RawURLEncoding.DecodeString(key.N)
					if err != nil {
						break
					}
					eBytes, err := base64.RawURLEncoding.DecodeString(key.E)
					if err != nil {
						break
					}
					ptr := new(rsa.PublicKey)
					ptr.N = new(big.Int).SetBytes(nBytes)
					ptr.E = int(new(big.Int).SetBytes(eBytes).Uint64())
					fetchedKeys[key.Kid] = ptr
				}
			case "EC":
				{
					if key.Kid == "" {
						key.Kid, err = JWKThumbprint(fmt.Sprintf(`{"crv":"P-256","kty":"EC","x":"%s","y":"%s"}`, key.X, key.Y))
						if err != nil {
							break
						}
					}
					var crv elliptic.Curve
					switch key.Crv {
					case "P-256":
						crv = elliptic.P256()
					case "P-384":
						crv = elliptic.P384()
					case "P-521":
						crv = elliptic.P521()
					default:
						switch key.Alg {
						case "ES256":
							crv = elliptic.P256()
						case "ES384":
							crv = elliptic.P384()
						case "ES512":
							crv = elliptic.P521()
						default:
							crv = elliptic.P256()
						}
					}
					xBytes, err := base64.RawURLEncoding.DecodeString(key.X)
					if err != nil {
						break
					}
					yBytes, err := base64.RawURLEncoding.DecodeString(key.Y)
					if err != nil {
						break
					}
					ptr := new(ecdsa.PublicKey)
					ptr.Curve = crv
					ptr.X = new(big.Int).SetBytes(xBytes)
					ptr.Y = new(big.Int).SetBytes(yBytes)
					fetchedKeys[key.Kid] = ptr
				}
			case "oct":
				{
					kBytes, err := base64.RawURLEncoding.DecodeString(key.K)
					if err != nil {
						break
					}
					if key.Kid == "" {
						key.Kid, err = JWKThumbprint(key.K)
						if err != nil {
							break
						}
					}
					fetchedKeys[key.Kid] = kBytes
				}
			}
		}
	}

	jwtPlugin.keysLock.Lock()
	defer jwtPlugin.keysLock.Unlock()

	for k, v := range fetchedKeys {
		jwtPlugin.keys[k] = v
	}
}

func (jwtPlugin *JwtPlugin) ServeHTTP(rw http.ResponseWriter, request *http.Request) {
	if st, err := jwtPlugin.CheckToken(request, rw); err != nil {
		if st >= 300 && st < 600 {
			http.Error(rw, err.Error(), st)
		} else {
			http.Error(rw, err.Error(), http.StatusForbidden)
		}
		return
	}
	jwtPlugin.next.ServeHTTP(rw, request)
}

func (jwtPlugin *JwtPlugin) CheckToken(request *http.Request, rw http.ResponseWriter) (int, error) {
	jwtToken, err := jwtPlugin.ExtractToken(request)
	if jwtToken == nil {
		if jwtPlugin.required {
			return 0, err
		} else {
			logWarn(err.Error()).
				withUrl(request.URL.String()).
				withNetwork(jwtPlugin.remoteAddr(request)).
				print()
		}
	}

	sub := ""
	if jwtToken != nil {
		sub = fmt.Sprint(jwtToken.Payload["sub"])
		// only verify jwt tokens if keys are configured
		if len(jwtPlugin.getKeysSync()) > 0 || len(jwtPlugin.jwkEndpoints) > 0 {
			if err = jwtPlugin.VerifyToken(jwtToken); err != nil {
				logError(fmt.Sprintf("Token is invalid - err: %s", err.Error())).
					withSub(sub).
					withUrl(request.URL.String()).
					withNetwork(jwtPlugin.remoteAddr(request)).
					print()
				return 0, err
			}
		}
		for _, fieldName := range jwtPlugin.payloadFields {
			_, ok := jwtToken.Payload[fieldName]
			if !ok {
				logError(fmt.Sprintf("Missing JWT field %s", fieldName)).
					withSub(sub).
					withUrl(request.URL.String()).
					withNetwork(jwtPlugin.remoteAddr(request)).
					print()
				return 0, fmt.Errorf("payload missing required field %s", fieldName)
			}
			if fieldName == "exp" {
				if expInt, err := strconv.ParseInt(fmt.Sprint(jwtToken.Payload["exp"]), 10, 64); err != nil || expInt < time.Now().Unix() {
					logError("Token is expired").
						withSub(sub).
						withUrl(request.URL.String()).
						withNetwork(jwtPlugin.remoteAddr(request)).
						print()
					return 0, fmt.Errorf("token is expired")
				}
			} else if fieldName == "nbf" {
				if nbfInt, err := strconv.ParseInt(fmt.Sprint(jwtToken.Payload["nbf"]), 10, 64); err != nil || nbfInt > time.Now().Add(1*time.Minute).Unix() {
					logError("Token not valid yet").
						withSub(sub).
						withUrl(request.URL.String()).
						withNetwork(jwtPlugin.remoteAddr(request)).
						print()
					return 0, fmt.Errorf("token not valid yet")
				}
			}
		}
		for k, v := range jwtPlugin.jwtHeaders {
			_, ok := jwtToken.Payload[v]
			if ok {
				request.Header.Add(k, fmt.Sprint(jwtToken.Payload[v]))
			}
		}
	}
	if jwtPlugin.opaUrl != "" {
		if st, err := jwtPlugin.CheckOpa(request, jwtToken, rw); err != nil {
			logError(fmt.Sprintf("OPA Check failed - err: %s", err.Error())).
				withSub(sub).
				withUrl(request.URL.String()).
				withNetwork(jwtPlugin.remoteAddr(request)).
				print()
			return st, err
		}
	}
	return 0, nil
}

func (jwtPlugin *JwtPlugin) ExtractToken(request *http.Request) (*JWT, error) {
	// first check if the token is present in header and is valid
	jwtTokenStr, err := jwtPlugin.extractTokenFromHeader(request)
	if err != nil && jwtPlugin.jwtCookieKey != "" {
		jwtTokenStr, err = jwtPlugin.extractTokenFromCookie(request)
	}
	if err != nil && jwtPlugin.jwtQueryKey != "" {
		jwtTokenStr, err = jwtPlugin.extractTokenFromQuery(request)
	}
	if err != nil {
		return nil, err
	}

	parts := strings.Split(jwtTokenStr, ".")
	if len(parts) != 3 {
		logError("Invalid token format, expected 3 parts").
			withUrl(request.URL.String()).
			withNetwork(jwtPlugin.remoteAddr(request)).
			print()
		return nil, fmt.Errorf("invalid token format")
	}
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, err
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, err
	}
	jwtToken := JWT{
		Plaintext: []byte(jwtTokenStr[0 : len(parts[0])+len(parts[1])+1]),
		Signature: signature,
	}
	err = json.Unmarshal(header, &jwtToken.Header)
	if err != nil {
		return nil, err
	}
	d := json.NewDecoder(bytes.NewBuffer(payload))
	d.UseNumber()
	err = d.Decode(&jwtToken.Payload)
	if err != nil {
		return nil, err
	}
	return &jwtToken, nil
}

func (jwtPlugin *JwtPlugin) extractTokenFromHeader(request *http.Request) (string, error) {
	authHeader, ok := request.Header["Authorization"]
	if !ok {
		return "", fmt.Errorf("authorization header missing")
	}
	auth := authHeader[0]
	if !strings.HasPrefix(strings.ToLower(auth), "bearer ") {
		return "", fmt.Errorf("authorization type not Bearer")
	}
	return auth[7:], nil
}

func (jwtPlugin *JwtPlugin) extractTokenFromCookie(request *http.Request) (string, error) {
	cookie, err := request.Cookie(jwtPlugin.jwtCookieKey)
	if err != nil {
		return "", err
	}
	return cookie.Value, nil
}

func (jwtPlugin *JwtPlugin) extractTokenFromQuery(request *http.Request) (string, error) {
	query := request.URL.Query()
	if !query.Has(jwtPlugin.jwtQueryKey) {
		return "", fmt.Errorf("query parameter missing")
	}
	parameter := query.Get(jwtPlugin.jwtQueryKey)
	return parameter, nil
}

func (jwtPlugin *JwtPlugin) remoteAddr(req *http.Request) Network {
	// This will only be defined when site is accessed via non-anonymous proxy
	// and takes precedence over RemoteAddr
	// Header.Get is case-insensitive
	ipHeader := req.Header.Get("X-Forwarded-For")
	if len(ipHeader) == 0 {
		ipHeader = req.RemoteAddr
	}

	ip, port, err := net.SplitHostPort(ipHeader)
	portNumber, _ := strconv.Atoi(port)
	if err == nil {
		return Network{
			Client: Client{
				IP:   ip,
				Port: portNumber,
			},
		}
	}

	userIP := net.ParseIP(ipHeader)
	if userIP == nil {
		return Network{
			Client: Client{
				IP:   ipHeader,
				Port: portNumber,
			},
		}
	}

	return Network{
		Client: Client{
			IP:   userIP.String(),
			Port: portNumber,
		},
	}
}

func (jwtPlugin *JwtPlugin) getKeysSync() map[string]interface{} {
	jwtPlugin.keysLock.RLock()
	defer jwtPlugin.keysLock.RUnlock()
	return jwtPlugin.keys
}

func (jwtPlugin *JwtPlugin) VerifyToken(jwtToken *JWT) error {
	for _, h := range jwtToken.Header.Crit {
		if _, ok := supportedHeaderNames[h]; !ok {
			return fmt.Errorf("unsupported header: %s", h)
		}
	}
	// Look up the algorithm
	a, ok := tokenAlgorithms[jwtToken.Header.Alg]
	if !ok {
		return fmt.Errorf("unknown JWS algorithm: %s", jwtToken.Header.Alg)
	}
	if jwtPlugin.alg != "" && jwtToken.Header.Alg != jwtPlugin.alg {
		return fmt.Errorf("incorrect alg, expected %s got %s", jwtPlugin.alg, jwtToken.Header.Alg)
	}
	key, ok := jwtPlugin.getKeysSync()[jwtToken.Header.Kid]
	if !ok && jwtPlugin.forceRefreshKeys() {
		key, ok = jwtPlugin.getKeysSync()[jwtToken.Header.Kid]
	}
	if ok {
		return a.verify(key, a.hash, jwtToken.Plaintext, jwtToken.Signature)
	} else {
		for _, key := range jwtPlugin.getKeysSync() {
			err := a.verify(key, a.hash, jwtToken.Plaintext, jwtToken.Signature)
			if err == nil {
				return nil
			}
		}
		return fmt.Errorf("token validation failed")
	}
}

func (jwtPlugin *JwtPlugin) CheckOpa(request *http.Request, token *JWT, rw http.ResponseWriter) (int, error) {
	opaPayload, err := toOPAPayload(request, jwtPlugin.opaBody)
	if err != nil {
		return 0, err
	}
	if token != nil {
		opaPayload.Input.JWTHeader = token.Header
		opaPayload.Input.JWTPayload = token.Payload
	}
	authPayloadAsJSON, err := json.Marshal(opaPayload)
	if err != nil {
		return 0, err
	}
	authResponse, err := http.Post(jwtPlugin.opaUrl, "application/json", bytes.NewBuffer(authPayloadAsJSON))
	if err != nil {
		return 0, err
	}
	body, err := io.ReadAll(authResponse.Body)
	if err != nil {
		return 0, err
	}
	var result Response
	err = json.Unmarshal(body, &result)
	if err != nil {
		return 0, err
	}
	if len(result.Result) == 0 {
		return 0, fmt.Errorf("OPA result invalid")
	}
	fieldResult, ok := result.Result[jwtPlugin.opaAllowField]
	if !ok {
		return 0, fmt.Errorf("OPA result missing: %v", jwtPlugin.opaAllowField)
	}
	for k, v := range jwtPlugin.opaResponseHeaders {
		var value string
		if rawVal, rawValOk := result.Result[v]; rawValOk {
			if err = json.Unmarshal(rawVal, &value); err != nil {
				value = string(rawVal)
			}
			rw.Header().Set(k, value)
		}
	}

	var allow bool
	if err = json.Unmarshal(fieldResult, &allow); err != nil {
		return 0, err
	}

	if !allow {
		var notAllowErr error
		if jwtPlugin.opaDebugMode {
			notAllowErr = fmt.Errorf("%s", body)
		} else {
			notAllowErr = fmt.Errorf("forbidden")
		}
		if jwtPlugin.opaHttpStatusField != "" {
			if rawVal, rawValOk := result.Result[jwtPlugin.opaHttpStatusField]; rawValOk {
				if st, err := strconv.Atoi(strings.Trim(string(rawVal), `"`)); err == nil {
					return st, notAllowErr
				}
			}
		}
		return 0, notAllowErr
	}

	for k, v := range jwtPlugin.opaHeaders {
		var value string
		if rawVal, rawValOk := result.Result[v]; rawValOk {
			if err = json.Unmarshal(rawVal, &value); err != nil {
				value = string(rawVal)
			}
			request.Header.Add(k, value)
		}
	}
	return 0, nil
}

func toOPAPayload(request *http.Request, includeBody bool) (*Payload, error) {
	input := &PayloadInput{
		Host:       request.Host,
		Method:     request.Method,
		Path:       strings.Split(request.URL.Path, "/")[1:],
		Parameters: request.URL.Query(),
		Headers:    request.Header,
	}
	contentType, params, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err == nil && includeBody {
		var save []byte
		save, request.Body, err = drainBody(request.Body)
		if err == nil {
			if contentType == "application/json" && len(save) > 0 {
				err = json.Unmarshal(save, &input.Body)
				if err != nil {
					return nil, err
				}
			} else if contentType == "application/x-www-url-formencoded" {
				input.Form, err = url.ParseQuery(string(save))
				if err != nil {
					return nil, err
				}
			} else if contentType == "multipart/form-data" || contentType == "multipart/mixed" {
				boundary := params["boundary"]
				mr := multipart.NewReader(bytes.NewReader(save), boundary)
				f, err := mr.ReadForm(32 << 20)
				if err != nil {
					return nil, err
				}

				input.Form = make(url.Values)
				for k, v := range f.Value {
					input.Form[k] = append(input.Form[k], v...)
				}
			}
		}
	}
	return &Payload{Input: input}, nil
}

func drainBody(b io.ReadCloser) ([]byte, io.ReadCloser, error) {
	if b == nil || b == http.NoBody {
		// No copying needed. Preserve the magic sentinel meaning of NoBody.
		return nil, http.NoBody, nil
	}
	body, err := io.ReadAll(b)
	if err != nil {
		return nil, b, err
	}
	return body, NopCloser(bytes.NewReader(body), b), nil
}

func NopCloser(r io.Reader, c io.Closer) io.ReadCloser {
	return nopCloser{r: r, c: c}
}

type nopCloser struct {
	r io.Reader
	c io.Closer
}

func (n nopCloser) Read(b []byte) (int, error) { return n.r.Read(b) }
func (n nopCloser) Close() error               { return n.c.Close() }

type (
	tokenVerifyFunction           func(key interface{}, hash crypto.Hash, payload, signature []byte) error
	tokenVerifyAsymmetricFunction func(key interface{}, hash crypto.Hash, digest, signature []byte) error
)

// jwtAlgorithm describes a JWS 'alg' value
type tokenAlgorithm struct {
	hash   crypto.Hash
	verify tokenVerifyFunction
}

// tokenAlgorithms is the known JWT algorithms
var tokenAlgorithms = map[string]tokenAlgorithm{
	"RS256": {crypto.SHA256, verifyAsymmetric(verifyRSAPKCS)},
	"RS384": {crypto.SHA384, verifyAsymmetric(verifyRSAPKCS)},
	"RS512": {crypto.SHA512, verifyAsymmetric(verifyRSAPKCS)},
	"PS256": {crypto.SHA256, verifyAsymmetric(verifyRSAPSS)},
	"PS384": {crypto.SHA384, verifyAsymmetric(verifyRSAPSS)},
	"PS512": {crypto.SHA512, verifyAsymmetric(verifyRSAPSS)},
	"ES256": {crypto.SHA256, verifyAsymmetric(verifyECDSA)},
	"ES384": {crypto.SHA384, verifyAsymmetric(verifyECDSA)},
	"ES512": {crypto.SHA512, verifyAsymmetric(verifyECDSA)},
	"HS256": {crypto.SHA256, verifyHMAC},
	"HS384": {crypto.SHA384, verifyHMAC},
	"HS512": {crypto.SHA512, verifyHMAC},
}

// errSignatureNotVerified is returned when a signature cannot be verified.
func verifyHMAC(key interface{}, hash crypto.Hash, payload, signature []byte) error {
	macKey, ok := key.([]byte)
	if !ok {
		return fmt.Errorf("incorrect symmetric key type")
	}
	mac := hmac.New(hash.New, macKey)
	if _, err := mac.Write(payload); err != nil {
		return err
	}
	sum := mac.Sum([]byte{})
	if !hmac.Equal(signature, sum) {
		return fmt.Errorf("token verification failed (HMAC)")
	}
	return nil
}

func verifyAsymmetric(verify tokenVerifyAsymmetricFunction) tokenVerifyFunction {
	return func(key interface{}, hash crypto.Hash, payload, signature []byte) error {
		h := hash.New()
		_, err := h.Write(payload)
		if err != nil {
			return err
		}
		return verify(key, hash, h.Sum([]byte{}), signature)
	}
}

func verifyRSAPKCS(key interface{}, hash crypto.Hash, digest, signature []byte) error {
	publicKeyRsa := key.(*rsa.PublicKey)
	if err := rsa.VerifyPKCS1v15(publicKeyRsa, hash, digest, signature); err != nil {
		return fmt.Errorf("token verification failed (RSAPKCS)")
	}
	return nil
}

func verifyRSAPSS(key interface{}, hash crypto.Hash, digest, signature []byte) error {
	publicKeyRsa, ok := key.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("incorrect public key type")
	}
	if err := rsa.VerifyPSS(publicKeyRsa, hash, digest, signature, nil); err != nil {
		return fmt.Errorf("token verification failed (RSAPSS)")
	}
	return nil
}

func verifyECDSA(key interface{}, _ crypto.Hash, digest, signature []byte) error {
	publicKeyEcdsa, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("incorrect public key type")
	}
	r, s := &big.Int{}, &big.Int{}
	n := len(signature) / 2
	r.SetBytes(signature[:n])
	s.SetBytes(signature[n:])
	if ecdsa.Verify(publicKeyEcdsa, digest, r, s) {
		return nil
	}
	return fmt.Errorf("token verification failed (ECDSA)")
}

// JWKThumbprint creates a JWK thumbprint out of pub
// as specified in https://tools.ietf.org/html/rfc7638.
func JWKThumbprint(jwk string) (string, error) {
	b := sha256.Sum256([]byte(jwk))
	var slice []byte
	if len(b) > 0 {
		for _, s := range b {
			slice = append(slice, s)
		}
	}
	return base64.RawURLEncoding.EncodeToString(slice), nil
}

func logInfo(msg string) *LogEvent {
	return newLogEvent("info", msg)
}

func logWarn(msg string) *LogEvent {
	return newLogEvent("warn", msg)
}

func logError(msg string) *LogEvent {
	return newLogEvent("error", msg)
}

func newLogEvent(level, msg string) *LogEvent {
	return &LogEvent{
		Level: level,
		Msg:   msg,
	}
}

func (logEvent *LogEvent) print() {
	jsonLogEvent, _ := json.Marshal(*logEvent)
	fmt.Println(string(jsonLogEvent))
}

func (logEvent *LogEvent) withNetwork(network Network) *LogEvent {
	logEvent.Network = network
	return logEvent
}

func (logEvent *LogEvent) withUrl(url string) *LogEvent {
	logEvent.URL = url
	return logEvent
}

func (logEvent *LogEvent) withSub(sub string) *LogEvent {
	logEvent.Sub = sub
	return logEvent
}
