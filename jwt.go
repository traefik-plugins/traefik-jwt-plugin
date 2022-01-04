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
	"io/ioutil"
	"math/big"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Config the plugin configuration.
type Config struct {
	OpaUrl        string
	OpaAllowField string
	PayloadFields []string
	Required      bool
	Keys          []string
	Alg           string
	Iss           string
	Aud           string
	OpaHeaders    map[string]string
	JwtHeaders    map[string]string
}

// CreateConfig creates a new OPA Config
func CreateConfig() *Config {
	return &Config{}
}

// JwtPlugin contains the runtime config
type JwtPlugin struct {
	next          http.Handler
	opaUrl        string
	opaAllowField string
	payloadFields []string
	required      bool
	jwkEndpoints  []*url.URL
	keys          map[string]interface{}
	alg           string
	iss           string
	aud           string
	opaHeaders    map[string]string
	jwtHeaders    map[string]string
}

// LogEvent contains a single log entry
type LogEvent struct {
	Level   string    `json:"level"`
	Msg     string    `json:"msg"`
	Time    time.Time `json:"time"`
	Network `json:"network"`
	URL     string `json:"url"`
	Sub     string `json:"sub"`
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
	Body       map[string]interface{} `json:"body,omitempty"`
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
func New(_ context.Context, next http.Handler, config *Config, _ string) (http.Handler, error) {
	jwtPlugin := &JwtPlugin{
		next:          next,
		opaUrl:        config.OpaUrl,
		opaAllowField: config.OpaAllowField,
		payloadFields: config.PayloadFields,
		required:      config.Required,
		alg:           config.Alg,
		iss:           config.Iss,
		aud:           config.Aud,
		keys:          make(map[string]interface{}),
		jwtHeaders:    config.JwtHeaders,
		opaHeaders:    config.OpaHeaders,
	}
	if err := jwtPlugin.ParseKeys(config.Keys); err != nil {
		return nil, err
	}
	go jwtPlugin.BackgroundRefresh()
	return jwtPlugin, nil
}

func (jwtPlugin *JwtPlugin) BackgroundRefresh() {
	for {
		jwtPlugin.FetchKeys()
		time.Sleep(15 * time.Minute) // 15 min
	}
}

func (jwtPlugin *JwtPlugin) ParseKeys(certificates []string) error {
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
	jsonLogEvent, _ := json.Marshal(&LogEvent{
		Level: "info",
		Msg:   fmt.Sprintf("FetchKeys - #%d jwkEndpoints to fetch", len(jwtPlugin.jwkEndpoints)),
		Time:  time.Now(),
		Sub:   "",
		URL:   "",
	})
	fmt.Println(string(jsonLogEvent))

	for _, u := range jwtPlugin.jwkEndpoints {
		response, err := http.Get(u.String())
		if err != nil {
			// TODO: log warning
			jsonLogEvent, _ := json.Marshal(&LogEvent{
				Level: "warning",
				Msg:   "FetchKeys - Failed to fetch keys",
				Time:  time.Now(),
				Sub:   "",
				URL:   u.String(),
			})
			fmt.Println(string(jsonLogEvent))
			continue
		}
		body, err := ioutil.ReadAll(response.Body)
		if err != nil {
			// TODO: log warning
			jsonLogEvent, _ := json.Marshal(&LogEvent{
				Level: "warning",
				Msg:   "FetchKeys - Failed to read keys",
				Time:  time.Now(),
				Sub:   "",
				URL:   u.String(),
			})
			fmt.Println(string(jsonLogEvent))
			continue
		}
		var jwksKeys Keys
		err = json.Unmarshal(body, &jwksKeys)
		if err != nil {
			// TODO: log warning
			jsonLogEvent, _ := json.Marshal(&LogEvent{
				Level: "warning",
				Msg:   "FetchKeys - Failed to unmarshall jwksKeys",
				Time:  time.Now(),
				Sub:   "",
				URL:   u.String(),
			})
			fmt.Println(string(jsonLogEvent))
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
					// Bypass Yaegi strange behavior - avoid resuing same address at each iteration
					// -> all array element point to the same address accessing only the latest value ;-(
					// jwtPlugin.keys[key.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: int(new(big.Int).SetBytes(eBytes).Uint64())}
					// sol1
					ptr := new(rsa.PublicKey)
					ptr.N = new(big.Int).SetBytes(nBytes)
					ptr.E = int(new(big.Int).SetBytes(eBytes).Uint64())
					jwtPlugin.keys[key.Kid] = ptr
					// sol2 + adapt verify function with new type (from pointer to real object structure)
					// jwtPlugin.keys[key.Kid] = rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: int(new(big.Int).SetBytes(eBytes).Uint64())}
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
					// Bypass Yaegi strange behavior - avoid resuing same address at each iteration
					// -> all array element point to the same address accessing only the latest value ;-(
					// jwtPlugin.keys[key.Kid] = &ecdsa.PublicKey{Curve: crv, X: new(big.Int).SetBytes(xBytes), Y: new(big.Int).SetBytes(yBytes)}
					// sol1
					ptr := new(ecdsa.PublicKey)
					ptr.Curve = crv
					ptr.X = new(big.Int).SetBytes(xBytes)
					ptr.Y = new(big.Int).SetBytes(yBytes)
					jwtPlugin.keys[key.Kid] = ptr
					// sol2
					// jwtPlugin.keys[key.Kid] = ecdsa.PublicKey{Curve: crv, X: new(big.Int).SetBytes(xBytes), Y: new(big.Int).SetBytes(yBytes)}
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
					jwtPlugin.keys[key.Kid] = kBytes
				}
			}
		}
	}
}

func (jwtPlugin *JwtPlugin) ServeHTTP(rw http.ResponseWriter, request *http.Request) {
	if err := jwtPlugin.CheckToken(request); err != nil {
		http.Error(rw, err.Error(), http.StatusForbidden)
		return
	}
	jwtPlugin.next.ServeHTTP(rw, request)
}

func (jwtPlugin *JwtPlugin) CheckToken(request *http.Request) error {
	network := jwtPlugin.remoteAddr(request)
	sub := ""

	jwtToken, err := jwtPlugin.ExtractToken(request)
	if err != nil {
		return err
	}
	if jwtToken != nil {
		sub = fmt.Sprint(jwtToken.Payload["sub"])

		// only verify jwt tokens if keys are configured
		if len(jwtPlugin.keys) > 0 || len(jwtPlugin.jwkEndpoints) > 0 {
			if err = jwtPlugin.VerifyToken(jwtToken); err != nil {
				jsonLogEvent, _ := json.Marshal(&LogEvent{
					Level:   "error",
					Msg:     fmt.Sprintf("Token is invalid - err: %s", err.Error()),
					Time:    time.Now(),
					Sub:     sub,
					Network: network,
					URL:     request.URL.String(),
				})
				fmt.Println(string(jsonLogEvent))
				return err
			}
		}
		for _, fieldName := range jwtPlugin.payloadFields {
			if _, ok := jwtToken.Payload[fieldName]; !ok {
				if jwtPlugin.required {
					jsonLogEvent, _ := json.Marshal(&LogEvent{
						Level:   "error",
						Msg:     fmt.Sprintf("Missing JWT field %s", fieldName),
						Time:    time.Now(),
						Sub:     sub,
						Network: network,
						URL:     request.URL.String(),
					})
					fmt.Println(string(jsonLogEvent))
					return fmt.Errorf("payload missing required field %s", fieldName)
				} else {
					jsonLogEvent, _ := json.Marshal(&LogEvent{
						Level:   "warning",
						Msg:     fmt.Sprintf("Missing JWT field %s", fieldName),
						Time:    time.Now(),
						Sub:     sub,
						Network: network,
						URL:     request.URL.String(),
					})
					fmt.Println(string(jsonLogEvent))
				}
			}
		}
		for k, v := range jwtPlugin.jwtHeaders {
			_, ok := jwtToken.Payload[v]
			if ok {
				request.Header.Add(k, fmt.Sprintf("%v", jwtToken.Payload[v]))
			}
		}
	}
	if jwtPlugin.opaUrl != "" {
		if err := jwtPlugin.CheckOpa(request, jwtToken); err != nil {
			jsonLogEvent, _ := json.Marshal(&LogEvent{
				Level:   "error",
				Msg:     fmt.Sprintf("OPA Check failed - err: %s", err.Error()),
				Time:    time.Now(),
				Sub:     sub,
				Network: network,
				URL:     request.URL.String(),
			})
			fmt.Println(string(jsonLogEvent))
			return err
		}
	}
	return nil
}

func (jwtPlugin *JwtPlugin) ExtractToken(request *http.Request) (*JWT, error) {
	network := jwtPlugin.remoteAddr(request)

	authHeader, ok := request.Header["Authorization"]
	if !ok {
		return nil, nil
	}
	auth := authHeader[0]
	if !strings.HasPrefix(auth, "Bearer ") {
		return nil, nil
	}
	parts := strings.Split(auth[7:], ".")
	if len(parts) != 3 {
		jsonLogEvent, _ := json.Marshal(&LogEvent{
			Level:   "error",
			Msg:     "Invalid token format",
			Time:    time.Now(),
			Sub:     "",
			Network: network,
			URL:     request.URL.String(),
		})
		fmt.Println(string(jsonLogEvent))
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
		Plaintext: []byte(auth[7 : len(parts[0])+len(parts[1])+8]),
		Signature: signature,
	}
	err = json.Unmarshal(header, &jwtToken.Header)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(payload, &jwtToken.Payload)
	if err != nil {
		return nil, err
	}
	return &jwtToken, nil
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
	key, ok := jwtPlugin.keys[jwtToken.Header.Kid]
	if ok {
		return a.verify(key, a.hash, jwtToken.Plaintext, jwtToken.Signature)
	} else {
		for _, key := range jwtPlugin.keys {
			err := a.verify(key, a.hash, jwtToken.Plaintext, jwtToken.Signature)
			if err == nil {
				return nil
			}
		}
		return fmt.Errorf("token validation failed")
	}
}

func (jwtPlugin *JwtPlugin) CheckOpa(request *http.Request, token *JWT) error {
	opaPayload, err := toOPAPayload(request)
	if err != nil {
		return err
	}
	if token != nil {
		opaPayload.Input.JWTHeader = token.Header
		opaPayload.Input.JWTPayload = token.Payload
	}
	authPayloadAsJSON, err := json.Marshal(opaPayload)
	if err != nil {
		return err
	}
	authResponse, err := http.Post(jwtPlugin.opaUrl, "application/json", bytes.NewBuffer(authPayloadAsJSON))
	if err != nil {
		return err
	}
	body, err := ioutil.ReadAll(authResponse.Body)
	if err != nil {
		return err
	}
	var result Response
	err = json.Unmarshal(body, &result)
	if err != nil {
		return err
	}
	if len(result.Result) == 0 {
		return fmt.Errorf("OPA result invalid")
	}
	fieldResult, ok := result.Result[jwtPlugin.opaAllowField]
	if !ok {
		return fmt.Errorf("OPA result missing: %v", jwtPlugin.opaAllowField)
	}
	var allow bool
	if err = json.Unmarshal(fieldResult, &allow); err != nil {
		return err
	}
	if !allow {
		return fmt.Errorf("%s", body)
	}
	for k, v := range jwtPlugin.opaHeaders {
		var value string
		if err = json.Unmarshal(result.Result[v], &value); err == nil {
			request.Header.Add(k, value) // add OPA result as an HTTP header
		}
	}
	return nil
}

func toOPAPayload(request *http.Request) (*Payload, error) {
	input := &PayloadInput{
		Host:       request.Host,
		Method:     request.Method,
		Path:       strings.Split(request.URL.Path, "/")[1:],
		Parameters: request.URL.Query(),
		Headers:    request.Header,
	}
	contentType, params, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err == nil {
		var save []byte
		save, request.Body, err = drainBody(request.Body)
		if err == nil {
			if contentType == "application/json" {
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
	body, err := ioutil.ReadAll(b)
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

type tokenVerifyFunction func(key interface{}, hash crypto.Hash, payload []byte, signature []byte) error
type tokenVerifyAsymmetricFunction func(key interface{}, hash crypto.Hash, digest []byte, signature []byte) error

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
func verifyHMAC(key interface{}, hash crypto.Hash, payload []byte, signature []byte) error {
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
	return func(key interface{}, hash crypto.Hash, payload []byte, signature []byte) error {
		h := hash.New()
		_, err := h.Write(payload)
		if err != nil {
			return err
		}
		return verify(key, hash, h.Sum([]byte{}), signature)
	}
}

func verifyRSAPKCS(key interface{}, hash crypto.Hash, digest []byte, signature []byte) error {
	publicKeyRsa := key.(*rsa.PublicKey)
	if err := rsa.VerifyPKCS1v15(publicKeyRsa, hash, digest, signature); err != nil {
		return fmt.Errorf("token verification failed (RSAPKCS)")
	}
	return nil
}

func verifyRSAPSS(key interface{}, hash crypto.Hash, digest []byte, signature []byte) error {
	publicKeyRsa, ok := key.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("incorrect public key type")
	}
	if err := rsa.VerifyPSS(publicKeyRsa, hash, digest, signature, nil); err != nil {
		return fmt.Errorf("token verification failed (RSAPSS)")
	}
	return nil
}

func verifyECDSA(key interface{}, _ crypto.Hash, digest []byte, signature []byte) error {
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
