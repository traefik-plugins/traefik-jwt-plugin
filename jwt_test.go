package traefik_jwt_plugin_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	traefik_jwt_plugin "github.com/team-carepay/traefik-jwt-plugin"
)

var rsaCertPEM = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkvrllkN3t0cm6r01ngZn
2Vjqf3pwiiGf5KVoadkxuPWBLmpt+tbmNK8gIcqW0u6ER5dLkFTPcPZ9Vmnuzvgp
yQMXIsBCj+s3/geeDAd+o9V3YyDpxbn4spzJX3VquOEXxxol0aOUYLchNs5eiLEm
IEG9sWwvmRO55yxG8w+3xVBgP6PapT8fzBVUgSoMAKms0exeNQE3/vwS0/5wvbAi
iok7+Z7qB23GNl0YO8pgWCCiil9s5WNg1Tif+fcddREIki94Xac0q7uTSqNsCZcC
LbyeOPZEIhXc4g2imEZ7RD52Ka4+C8FXyRGKKtUq5EQ6MWe67L0TVpEqUUsLLmRH
gwIDAQAB
-----END PUBLIC KEY-----
`

var rsaKeyPEM = testingKey(`-----BEGIN TESTING KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCS+uWWQ3e3Rybq
vTWeBmfZWOp/enCKIZ/kpWhp2TG49YEuam361uY0ryAhypbS7oRHl0uQVM9w9n1W
ae7O+CnJAxciwEKP6zf+B54MB36j1XdjIOnFufiynMlfdWq44RfHGiXRo5RgtyE2
zl6IsSYgQb2xbC+ZE7nnLEbzD7fFUGA/o9qlPx/MFVSBKgwAqazR7F41ATf+/BLT
/nC9sCKKiTv5nuoHbcY2XRg7ymBYIKKKX2zlY2DVOJ/59x11EQiSL3hdpzSru5NK
o2wJlwItvJ449kQiFdziDaKYRntEPnYprj4LwVfJEYoq1SrkRDoxZ7rsvRNWkSpR
SwsuZEeDAgMBAAECggEAQr51gHltxUglx4YZcYPGJ+BlSHNQ5KElSz7DvgFXv36Y
5XuGKtjom/cEt+OX/vw6DIqLUWT5+HmubA3Z2Jm/29yv5mN5NoKhoBVUc3D51Kss
tlKtZdEwOufQ2CzpREBPPGZG0z6dtBelGQ64xgjv38kKu6V9rd1T18L3CwxRruND
LzzBSJwlSPF//o8cCr489oMoYi6HBIAqB9khqut/EdSk0utU2qFEpjf+AME4z4oi
Lw2d8FvLn7e1ASDwenqoJ2UC0h3g3WwDkqxCtwqBlE4W5RhTFKmAtsDcEM8eUbxu
K3WSuA+L8NSDKlmfDsByGT+nHPtHIQwDS+Swlne/iQKBgQDJN3SjiiKg5hwVWkOV
+5WqCB5YBOZOvUdbJhxehc++iinJtK1ojNH0I4Bqiu5T5NZyM40X3KQ0RumBPzIt
Rh+zpyLgsDyQT33XNlDnMXxj2DOsEBO5xsZP+UizQhIpj/ndSvv0RWarBi9BXrhp
mTzY6OyaKZFqbgTk03SHuC/uiwKBgQC6/zi/AGX84wiY9e/NSvIPsYZK/hBP0FfD
kkchtt7uxCX6taDZ3E8oOQ7aIYkJ6RcnzwPNaBOU1WbcEvQHawfl3sBO3D6CdQzl
l0+RxB2FSEuFhxaA8AabQm6A5f+LdHpGRAsOF8uzbcsUmxdhLORElc1feWIrdU9Y
RChFfdTh6QKBgET5Rnk8w6wF1QCYxWwnJmF3kPc5Dr1U8p3TDYx1MAYvlC15Sqv5
AYs/lChxYUrOuZfCBg506rCk0iwkvo14aSuLElCU+N268fcQvmDRvML4/JVxmWFo
Oth1Ki+QaWtn2A28Q2uzUoMzhoVQ88P27D2qclhSAW/LMNBDj8FqKLwLAoGAI9fb
9rCK3Ahgk4FAr+cXsu5iQWmlksbqq7AUNmApJzct2HqMFHZoLduR/znCXMXzDExf
/DVg23x0NOblI67eWq9xySvqR3NMP43bUKN4zR1obHXSWHCps4TuTYLIkuCGt4U/
YToqb4AyFwcLWjMSphrYvN41dQMNbGvUFE3kSlECgYBsiLKHY5xNp+idvY2E3AHF
JaNOk5egwFVAI83502mkzg0PcWeFM/IKDcP74+GTf7ufo6yrSx7x3MOxWNXsaGCV
Su9zwn2RfpGmyRF+a+vC9ZompKFtOIi4PL3eMw3zrKXc/Vmm0wBAdRsgi+97C5Sv
2SOQ1LMNBMiuf5kSyVDfiA==
-----END TESTING KEY-----
`)

func testingKey(s string) string { return strings.ReplaceAll(s, "TESTING KEY", "PRIVATE KEY") }

func TestServeHTTPOK(t *testing.T) {
	var tests = []struct {
		name         string
		remoteAddr   string
		forwardedFor string
	}{
		{
			name:         "x-forwarded-for, ipv4, no port",
			forwardedFor: "127.0.0.1",
		},
		{
			name:         "x-forwarded-for, ipv4, with port",
			forwardedFor: "127.0.0.1:1234",
		},
		{
			name:         "x-forwarded-for, ipv6, localhost, no port",
			forwardedFor: "::1",
		},
		{
			name:         "x-forwarded-for, ipv6, no port",
			forwardedFor: "2001:4860:0:2001::68",
		},
		{
			name:         "x-forwarded-for, ipv6, with port",
			forwardedFor: "[1fff:0:a88:85a3::ac1f]:8001",
		},
		{
			name:       "remoteAddr, ipv4, no port",
			remoteAddr: "127.0.0.1",
		},
		{
			name:       "remoteAddr, ipv4, with port",
			remoteAddr: "127.0.0.1:1234",
		},
		{
			name:       "remoteAddr, ipv6, localhost, no port",
			remoteAddr: "::1",
		},
		{
			name:       "remoteAddr, ipv6, no port",
			remoteAddr: "2001:4860:0:2001::68",
		},
		{
			name:       "remoteAddr, ipv6, with port",
			remoteAddr: "[1fff:0:a88:85a3::ac1f]:8001",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := traefik_jwt_plugin.CreateConfig()
			cfg.PayloadFields = []string{"exp"}
			cfg.JwtHeaders = map[string]string{"Name": "name"}
			cfg.Keys = []string{"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnzyis1ZjfNB0bBgKFMSv\nvkTtwlvBsaJq7S5wA+kzeVOVpVWwkWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHc\naT92whREFpLv9cj5lTeJSibyr/Mrm/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIy\ntvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0\ne+lf4s4OxQawWD79J9/5d3Ry0vbV3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWb\nV6L11BWkpzGXSW4Hv43qa+GSYOD2QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9\nMwIDAQAB\n-----END PUBLIC KEY-----"}
			ctx := context.Background()
			nextCalled := false
			next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) { nextCalled = true })

			jwt, err := traefik_jwt_plugin.New(ctx, next, cfg, "test-traefik-jwt-plugin")
			if err != nil {
				t.Fatal(err)
			}

			recorder := httptest.NewRecorder()

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Header["Authorization"] = []string{"Bearer eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.JlX3gXGyClTBFciHhknWrjo7SKqyJ5iBO0n-3S2_I7cIgfaZAeRDJ3SQEbaPxVC7X8aqGCOM-pQOjZPKUJN8DMFrlHTOdqMs0TwQ2PRBmVAxXTSOZOoEhD4ZNCHohYoyfoDhJDP4Qye_FCqu6POJzg0Jcun4d3KW04QTiGxv2PkYqmB7nHxYuJdnqE3704hIS56pc_8q6AW0WIT0W-nIvwzaSbtBU9RgaC7ZpBD2LiNE265UBIFraMDF8IAFw9itZSUCTKg1Q-q27NwwBZNGYStMdIBDor2Bsq5ge51EkWajzZ7ALisVp-bskzUsqUf77ejqX_CBAqkNdH1Zebn93A"}
			if len(tt.forwardedFor) > 0 {
				req.Header["X-Forwarded-For"] = []string{tt.forwardedFor}
			}
			if len(tt.remoteAddr) > 0 {
				req.RemoteAddr = tt.remoteAddr
			}

			jwt.ServeHTTP(recorder, req)

			if nextCalled == false {
				t.Fatal("next.ServeHTTP was not called")
			}
			if v := req.Header.Get("Name"); v != "John Doe" {
				t.Fatal("Expected header Name:John Doe")
			}
		})
	}
}

func TestServeOPAWithBody(t *testing.T) {
	var tests = []struct {
		name           string
		method         string
		contentType    string
		body           string
		expectedBody   map[string]interface{}
		expectedForm   url.Values
		expectedStatus int
	}{
		{
			name:           "get",
			method:         "GET",
			expectedStatus: http.StatusOK,
		},
		{
			name:        "json",
			method:      "POST",
			contentType: "application/json",
			body:        `{ "killroy": "washere" }`,
			expectedBody: map[string]interface{}{
				"killroy": "washere",
			},
			expectedStatus: http.StatusOK,
		},
		{
			name:        "form",
			method:      "POST",
			contentType: "application/x-www-url-formencoded",
			body:        `foo=bar&bar=foo`,
			expectedForm: map[string][]string{
				"foo": {"bar"},
				"bar": {"foo"},
			},
			expectedStatus: http.StatusOK,
		},
		{
			name:        "multipart",
			method:      "POST",
			contentType: "multipart/form-data; boundary=----boundary",
			body:        "------boundary\nContent-Disposition: form-data; name=\"field1\"\n\nblabla\n------boundary--",
			expectedForm: map[string][]string{
				"field1": {"blabla"},
			},
			expectedStatus: http.StatusOK,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var input traefik_jwt_plugin.Payload
				err := json.NewDecoder(r.Body).Decode(&input)
				if err != nil {
					t.Fatal(err)
				}
				if tt.expectedBody != nil && !reflect.DeepEqual(input.Input.Body, tt.expectedBody) {
					t.Fatalf("Expected %v, got %v", tt.expectedBody, input.Input.Body)
				}
				if tt.expectedForm != nil && !reflect.DeepEqual(input.Input.Form, tt.expectedForm) {
					t.Fatalf("Expected %v, got %v", tt.expectedForm, input.Input.Form)
				}
				w.WriteHeader(http.StatusOK)
				_, _ = fmt.Fprintln(w, `{ "result": { "allow": true, "foo": "Bar" } }`)
			}))
			defer ts.Close()
			cfg := traefik_jwt_plugin.CreateConfig()
			cfg.OpaUrl = fmt.Sprintf("%s/v1/data/testok?Param1=foo&Param1=bar", ts.URL)
			cfg.OpaAllowField = "allow"
			ctx := context.Background()
			next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
				body, err := io.ReadAll(req.Body)
				if err != nil {
					t.Fatal(err)
				}
				if tt.body != "" && string(body) != tt.body {
					t.Fatalf("Incorrect body, expected %v, received %v", tt.body, string(body))
				}
			})

			jwt, err := traefik_jwt_plugin.New(ctx, next, cfg, "test-traefik-jwt-plugin")
			if err != nil {
				t.Fatal(err)
			}

			recorder := httptest.NewRecorder()

			req, err := http.NewRequestWithContext(ctx, tt.method, "http://localhost", bytes.NewReader([]byte(tt.body)))
			if err != nil {
				t.Fatal(err)
			}
			req.Header["Authorization"] = []string{"Bearer eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.JlX3gXGyClTBFciHhknWrjo7SKqyJ5iBO0n-3S2_I7cIgfaZAeRDJ3SQEbaPxVC7X8aqGCOM-pQOjZPKUJN8DMFrlHTOdqMs0TwQ2PRBmVAxXTSOZOoEhD4ZNCHohYoyfoDhJDP4Qye_FCqu6POJzg0Jcun4d3KW04QTiGxv2PkYqmB7nHxYuJdnqE3704hIS56pc_8q6AW0WIT0W-nIvwzaSbtBU9RgaC7ZpBD2LiNE265UBIFraMDF8IAFw9itZSUCTKg1Q-q27NwwBZNGYStMdIBDor2Bsq5ge51EkWajzZ7ALisVp-bskzUsqUf77ejqX_CBAqkNdH1Zebn93A"}
			req.Header["Content-Type"] = []string{tt.contentType}

			jwt.ServeHTTP(recorder, req)
			if recorder.Result().StatusCode != tt.expectedStatus {
				t.Fatalf("Expected status %d, received %d", tt.expectedStatus, recorder.Result().StatusCode)
			}
		})
	}
}

func TestServeWithBody(t *testing.T) {
	// TODO: add more testcases with DSA, etc.
	cfg := traefik_jwt_plugin.CreateConfig()
	cfg.PayloadFields = []string{"exp"}
	cfg.JwtHeaders = map[string]string{"Name": "name"}
	cfg.Keys = []string{"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnzyis1ZjfNB0bBgKFMSv\nvkTtwlvBsaJq7S5wA+kzeVOVpVWwkWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHc\naT92whREFpLv9cj5lTeJSibyr/Mrm/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIy\ntvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0\ne+lf4s4OxQawWD79J9/5d3Ry0vbV3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWb\nV6L11BWkpzGXSW4Hv43qa+GSYOD2QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9\nMwIDAQAB\n-----END PUBLIC KEY-----"}
	ctx := context.Background()
	nextCalled := false
	type requestType struct {
		Killroy string `json:"killroy"`
	}
	var requestBody requestType
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		_ = json.NewDecoder(req.Body).Decode(&requestBody)
		nextCalled = true
	})

	jwt, err := traefik_jwt_plugin.New(ctx, next, cfg, "test-traefik-jwt-plugin")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", bytes.NewReader([]byte(`{ "killroy": "was here" }`)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header["Authorization"] = []string{"Bearer eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.JlX3gXGyClTBFciHhknWrjo7SKqyJ5iBO0n-3S2_I7cIgfaZAeRDJ3SQEbaPxVC7X8aqGCOM-pQOjZPKUJN8DMFrlHTOdqMs0TwQ2PRBmVAxXTSOZOoEhD4ZNCHohYoyfoDhJDP4Qye_FCqu6POJzg0Jcun4d3KW04QTiGxv2PkYqmB7nHxYuJdnqE3704hIS56pc_8q6AW0WIT0W-nIvwzaSbtBU9RgaC7ZpBD2LiNE265UBIFraMDF8IAFw9itZSUCTKg1Q-q27NwwBZNGYStMdIBDor2Bsq5ge51EkWajzZ7ALisVp-bskzUsqUf77ejqX_CBAqkNdH1Zebn93A"}
	req.Header["Content-Type"] = []string{"application/json"}

	jwt.ServeHTTP(recorder, req)

	if nextCalled == false {
		t.Fatal("next.ServeHTTP was not called")
	}
	if requestBody.Killroy != "was here" {
		t.Fatal("Missing request body")
	}
	if v := req.Header.Get("Name"); v != "John Doe" {
		t.Fatal("Expected header Name:John Doe")
	}
}

func TestServeHTTPInvalidSignature(t *testing.T) {
	cfg := traefik_jwt_plugin.CreateConfig()
	cfg.PayloadFields = []string{"exp"}
	cfg.Keys = []string{"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnzyis1ZjfNB0bBgKFMSv\nvkTtwlvBsaJq7S5wA+kzeVOVpVWwkWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHc\naT92whREFpLv9cj5lTeJSibyr/Mrm/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIy\ntvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0\ne+lf4s4OxQawWD79J9/5d3Ry0vbV3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWb\nV6L11BWkpzGXSW4Hv43qa+GSYOD2QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9\nMwIDAQAB\n-----END PUBLIC KEY-----"}
	ctx := context.Background()
	nextCalled := false
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) { nextCalled = true })

	jwt, err := traefik_jwt_plugin.New(ctx, next, cfg, "test-traefik-jwt-plugin")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header["Authorization"] = []string{"Bearer AAAAAA.BBBBBB.CCCCCC"}

	jwt.ServeHTTP(recorder, req)

	if nextCalled == true {
		t.Fatal("next.ServeHTTP was called")
	}
}

func TestServeHTTPMissingExp(t *testing.T) {
	cfg := traefik_jwt_plugin.CreateConfig()
	cfg.PayloadFields = []string{"exp"}
	cfg.Required = true
	cfg.Keys = []string{"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnzyis1ZjfNB0bBgKFMSv\nvkTtwlvBsaJq7S5wA+kzeVOVpVWwkWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHc\naT92whREFpLv9cj5lTeJSibyr/Mrm/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIy\ntvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0\ne+lf4s4OxQawWD79J9/5d3Ry0vbV3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWb\nV6L11BWkpzGXSW4Hv43qa+GSYOD2QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9\nMwIDAQAB\n-----END PUBLIC KEY-----"}
	ctx := context.Background()
	nextCalled := false
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) { nextCalled = true })

	jwt, err := traefik_jwt_plugin.New(ctx, next, cfg, "test-traefik-jwt-plugin")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header["Authorization"] = []string{"Bearer eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.JlX3gXGyClTBFciHhknWrjo7SKqyJ5iBO0n-3S2_I7cIgfaZAeRDJ3SQEbaPxVC7X8aqGCOM-pQOjZPKUJN8DMFrlHTOdqMs0TwQ2PRBmVAxXTSOZOoEhD4ZNCHohYoyfoDhJDP4Qye_FCqu6POJzg0Jcun4d3KW04QTiGxv2PkYqmB7nHxYuJdnqE3704hIS56pc_8q6AW0WIT0W-nIvwzaSbtBU9RgaC7ZpBD2LiNE265UBIFraMDF8IAFw9itZSUCTKg1Q-q27NwwBZNGYStMdIBDor2Bsq5ge51EkWajzZ7ALisVp-bskzUsqUf77ejqX_CBAqkNdH1Zebn93A"}

	jwt.ServeHTTP(recorder, req)

	if nextCalled == true {
		t.Fatal("next.ServeHTTP was called")
	}
}

func TestServeHTTPAllowed(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/data/testok" {
			t.Fatal(fmt.Sprintf("Path incorrect: %s", r.URL.Path))
		}
		param1 := r.URL.Query()["Param1"]
		if len(param1) != 2 || param1[0] != "foo" || param1[1] != "bar" {
			t.Fatal(fmt.Sprintf("Parameters incorrect, expected foo,bar but got %s", strings.Join(param1, ",")))
		}
		var input traefik_jwt_plugin.Payload
		_ = json.NewDecoder(r.Body).Decode(&input)
		if input.Input.Parameters.Get("frodo") != "notpass" {
			t.Fatal("Missing frodo")
		}
		bodyContent := input.Input.Body
		if bodyContent["baggins"] != "shire" {
			t.Fatal("Input body payload incorrect")
		}
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintln(w, `{ "result": { "allow": true, "foo": "Bar" } }`)
	}))
	defer ts.Close()
	cfg := traefik_jwt_plugin.CreateConfig()
	cfg.OpaUrl = fmt.Sprintf("%s/v1/data/testok?Param1=foo&Param1=bar", ts.URL)
	cfg.OpaAllowField = "allow"
	cfg.OpaHeaders = map[string]string{"Foo": "foo"}

	ctx := context.Background()
	nextCalled := false
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) { nextCalled = true })

	opa, err := traefik_jwt_plugin.New(ctx, next, cfg, "test-traefik-jwt-plugin")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost?frodo=notpass", bytes.NewReader([]byte(`{ "baggins": "shire" }`)))
	req.Header.Add("Content-Type", "application/json")
	if err != nil {
		t.Fatal(err)
	}

	opa.ServeHTTP(recorder, req)

	if recorder.Code == http.StatusForbidden {
		t.Fatal("Exptected OK")
	}
	if nextCalled == false {
		t.Fatal("next.ServeHTTP was not called")
	}
	if req.Header.Get("Foo") != "Bar" {
		t.Fatal("Expected Foo:Bar header")
	}
}

func TestServeHTTPForbidden(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintln(w, "{ \"result\": { \"allow\": false } }")
	}))
	defer ts.Close()
	cfg := traefik_jwt_plugin.CreateConfig()
	cfg.OpaUrl = ts.URL
	cfg.OpaAllowField = "allow"
	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) { t.Fatal("Should not chain HTTP call") })

	opa, err := traefik_jwt_plugin.New(ctx, next, cfg, "test-traefik-jwt-plugin")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}

	opa.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusForbidden {
		t.Fatal("Exptected Forbidden")
	}
}

func TestNewJWKEndpoint(t *testing.T) {
	var tests = []struct {
		name   string
		key    string
		token  string
		status int
		next   bool
	}{
		{
			name:   "rsa",
			key:    `{"keys":[{"alg":"RS512","e":"AQAB","n":"nzyis1ZjfNB0bBgKFMSvvkTtwlvBsaJq7S5wA-kzeVOVpVWwkWdVha4s38XM_pa_yr47av7-z3VTmvDRyAHcaT92whREFpLv9cj5lTeJSibyr_Mrm_YtjCZVWgaOYIhwrXwKLqPr_11inWsAkfIytvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0e-lf4s4OxQawWD79J9_5d3Ry0vbV3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWbV6L11BWkpzGXSW4Hv43qa-GSYOD2QU68Mb59oSk2OB-BtOLpJofmbGEGgvmwyCI9Mw","kty":"RSA"}]}`,
			token:  "Bearer eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.JlX3gXGyClTBFciHhknWrjo7SKqyJ5iBO0n-3S2_I7cIgfaZAeRDJ3SQEbaPxVC7X8aqGCOM-pQOjZPKUJN8DMFrlHTOdqMs0TwQ2PRBmVAxXTSOZOoEhD4ZNCHohYoyfoDhJDP4Qye_FCqu6POJzg0Jcun4d3KW04QTiGxv2PkYqmB7nHxYuJdnqE3704hIS56pc_8q6AW0WIT0W-nIvwzaSbtBU9RgaC7ZpBD2LiNE265UBIFraMDF8IAFw9itZSUCTKg1Q-q27NwwBZNGYStMdIBDor2Bsq5ge51EkWajzZ7ALisVp-bskzUsqUf77ejqX_CBAqkNdH1Zebn93A",
			status: http.StatusOK,
			next:   true,
		},
		{
			name:   "rsapss",
			key:    `{"keys":[{ "alg":"PS384", "kty": "RSA", "n": "nzyis1ZjfNB0bBgKFMSvvkTtwlvBsaJq7S5wA-kzeVOVpVWwkWdVha4s38XM_pa_yr47av7-z3VTmvDRyAHcaT92whREFpLv9cj5lTeJSibyr_Mrm_YtjCZVWgaOYIhwrXwKLqPr_11inWsAkfIytvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0e-lf4s4OxQawWD79J9_5d3Ry0vbV3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWbV6L11BWkpzGXSW4Hv43qa-GSYOD2QU68Mb59oSk2OB-BtOLpJofmbGEGgvmwyCI9Mw", "e": "AQAB" }]}`,
			token:  "Bearer eyJhbGciOiJQUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.MqF1AKsJkijKnfqEI3VA1OnzAL2S4eIpAuievMgD3tEFyFMU67gCbg-fxsc5dLrxNwdZEXs9h0kkicJZ70mp6p5vdv-j2ycDKBWg05Un4OhEl7lYcdIsCsB8QUPmstF-lQWnNqnq3wra1GynJrOXDL27qIaJnnQKlXuayFntBF0j-82jpuVdMaSXvk3OGaOM-7rCRsBcSPmocaAO-uWJEGPw_OWVaC5RRdWDroPi4YL4lTkDEC-KEvVkqCnFm_40C-T_siXquh5FVbpJjb3W2_YvcqfDRj44TsRrpVhk6ohsHMNeUad_cxnFnpolIKnaXq_COv35e9EgeQIPAbgIeg",
			status: http.StatusOK,
			next:   true,
		},
		{
			name:   "ec",
			key:    `{"keys":[{"alg":"ES512","x":"AYHOB2c_v3wWwu5ZhMMNADtzSvcFWTw2dFRJ7GlBSxGKU82_dJyE7SVHD1G7zrHWSGdUPH526rgGIMVy-VIBzKMs","y":"ib476MkyyYgPk0BXZq3mq4zImTRNuaU9slj9TVJ3ScT3L1bXwVuPJDzpr5GOFpaj-WwMAl8G7CqwoJOsW7Kddns","kty":"EC"}]}`,
			token:  "Bearer eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCIsImtpZCI6InhaRGZacHJ5NFA5dlpQWnlHMmZOQlJqLTdMejVvbVZkbTd0SG9DZ1NOZlkifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.AP_CIMClixc5-BFflmjyh_bRrkloEvwzn8IaWJFfMz13X76PGWF0XFuhjJUjp7EYnSAgtjJ-7iJG4IP7w3zGTBk_AUdmvRCiWp5YAe8S_Hcs8e3gkeYoOxiXFZlSSAx0GfwW1cZ0r67mwGtso1I3VXGkSjH5J0Rk6809bn25GoGRjOPu",
			status: http.StatusOK,
			next:   true,
		},
		{
			name:   "hmac",
			key:    `{"keys":[{"kty":"oct","kid":"57bd26a0-6209-4a93-a688-f8752be5d191","k":"eW91ci01MTItYml0LXNlY3JldA","alg":"HS512"}]}`,
			token:  "Bearer eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCIsImNyaXQiOlsia2lkIl0sImtpZCI6IjU3YmQyNmEwLTYyMDktNGE5My1hNjg4LWY4NzUyYmU1ZDE5MSJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.573ixRAw4I4XUFJwJGpv5dHNOGaexX5zTtF0nOQTWuU2_JyZjD-7cuMPxQUHOv8RR0kQrS0uVdo_N1lzTCPFnA",
			status: http.StatusOK,
			next:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = fmt.Fprintln(w, tt.key)
			}))
			defer ts.Close()
			cfg := traefik_jwt_plugin.CreateConfig()
			cfg.Keys = []string{ts.URL}
			ctx := context.Background()
			nextCalled := false
			next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) { nextCalled = true })

			opa, err := traefik_jwt_plugin.New(ctx, next, cfg, "test-traefik-jwt-plugin")
			if err != nil {
				t.Fatal(err)
			}
			time.Sleep(1 * time.Second)

			recorder := httptest.NewRecorder()

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Add("Authorization", tt.token)

			opa.ServeHTTP(recorder, req)

			if recorder.Result().StatusCode != tt.status {
				t.Fatal("Expected OK")
			}
			if nextCalled != tt.next {
				t.Fatalf("next.ServeHTTP was called: %t, expected: %t", nextCalled, tt.next)
			}
		})
	}
}

func TestIssue3(t *testing.T) {
	cfg := traefik_jwt_plugin.CreateConfig()
	cfg.PayloadFields = []string{"exp"}
	cfg.JwtHeaders = map[string]string{"Subject": "sub", "User": "preferred_username"}
	cfg.Keys = []string{"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnzyis1ZjfNB0bBgKFMSv\nvkTtwlvBsaJq7S5wA+kzeVOVpVWwkWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHc\naT92whREFpLv9cj5lTeJSibyr/Mrm/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIy\ntvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0\ne+lf4s4OxQawWD79J9/5d3Ry0vbV3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWb\nV6L11BWkpzGXSW4Hv43qa+GSYOD2QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9\nMwIDAQAB\n-----END PUBLIC KEY-----"}
	ctx := context.Background()
	nextCalled := false
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) { nextCalled = true })

	jwt, err := traefik_jwt_plugin.New(ctx, next, cfg, "test-traefik-jwt-plugin")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header["Authorization"] = []string{"Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2MTkyMTQ3MjIsImlhdCI6MTYxOTIxNDQyMiwianRpIjoiMDQxNDE4MTUtMjlmMy00OGVlLWI0ZGQtYTA0N2Q1NWU1MjcxIiwiaXNzIjoiaHR0cHM6Ly9rZXljbG9hay50ZXN0LnNjdy5mcmVlcGhwNS5uZXQvYXV0aC9yZWFsbXMvdGVzdCIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiJjMDNhM2Q4YS1lMGI1LTQ3Y2EtOWIwZi1iMmY5ZTY5Y2YzNDgiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJ0ZXN0LWNsaWVudCIsInNlc3Npb25fc3RhdGUiOiJjMmU1MmFhYS0yOTVkLTRhOWItOGNmMS1iYmIyYzliZmVmMmEiLCJhY3IiOiIxIiwiYWxsb3dlZC1vcmlnaW5zIjpbImh0dHBzOi8vd2hvYW1pLnRlc3Quc2N3LmZyZWVwaHA1Lm5ldCJdLCJyZWFsbV9hY2Nlc3MiOnsicm9sZXMiOlsib2ZmbGluZV9hY2Nlc3MiLCJ1bWFfYXV0aG9yaXphdGlvbiJdfSwicmVzb3VyY2VfYWNjZXNzIjp7ImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyIsInZpZXctcHJvZmlsZSJdfX0sInNjb3BlIjoiZW1haWwgcHJvZmlsZSIsImVtYWlsX3ZlcmlmaWVkIjpmYWxzZSwicHJlZmVycmVkX3VzZXJuYW1lIjoidXNlciJ9.UM_lD4nnS83CvNK6sryFTBK65_i7rzwYGNytupJB8TcXdmeIFL-a9mXcSrBA21Ch-lNO8cmVhqqRAoNzdm_DXxKn6Hq-OF3aPs-4aVUvMT1EuZx_QSWeaDf6qnxemhrUkTYmrHgmMKyUX6saeErKHTI_SXPncyctYkAaKAY8ibrM7vl9FOJC3LdKd7vAEIqwXwSN1m-aaTIVTvfhMBAlaULsiGQJW8lp0ktDtv2n3ta7zYv-Pl5bzyA7t5b1KRDUCrodZQjJfLOkwZUfNgJmHRrWBrEQg-D4CP9dr_9xTSHVFvOfWEboXOn1j2uJ0MgxikodYz2UT4qOYYhZyrB7zw"}

	jwt.ServeHTTP(recorder, req)

	if nextCalled == false {
		t.Fatal("next.ServeHTTP was not called")
	}
	if v := req.Header.Get("Subject"); v != "c03a3d8a-e0b5-47ca-9b0f-b2f9e69cf348" {
		t.Fatal("Expected header sub:c03a3d8a-e0b5-47ca-9b0f-b2f9e69cf348")
	}
	if v := req.Header.Get("User"); v != "user" {
		t.Fatal("Expected header User:user")
	}
}
