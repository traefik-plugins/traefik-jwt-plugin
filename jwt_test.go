package traefik_jwt_plugin

import (
	"bytes"
	"context"
	"encoding/base64"
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
)

func TestServeHTTPOK(t *testing.T) {
	tests := []struct {
		name         string
		remoteAddr   string
		forwardedFor string
		authPrefix   string
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
		{
			name:       "Authorization, uppercase prefix",
			authPrefix: "BEARER",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{
				JwtHeaders: map[string]string{"Name": "name"},
				Keys:       []string{"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnzyis1ZjfNB0bBgKFMSv\nvkTtwlvBsaJq7S5wA+kzeVOVpVWwkWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHc\naT92whREFpLv9cj5lTeJSibyr/Mrm/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIy\ntvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0\ne+lf4s4OxQawWD79J9/5d3Ry0vbV3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWb\nV6L11BWkpzGXSW4Hv43qa+GSYOD2QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9\nMwIDAQAB\n-----END PUBLIC KEY-----"},
			}
			ctx := context.Background()
			nextCalled := false
			next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) { nextCalled = true })

			jwt, err := New(ctx, next, &cfg, "test-traefik-jwt-plugin")
			if err != nil {
				t.Fatal(err)
			}

			recorder := httptest.NewRecorder()

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
			if err != nil {
				t.Fatal(err)
			}
			authPrefix := "Bearer"
			if len(tt.authPrefix) > 0 {
				authPrefix = tt.authPrefix
			}
			req.Header["Authorization"] = []string{fmt.Sprintf("%s eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.JlX3gXGyClTBFciHhknWrjo7SKqyJ5iBO0n-3S2_I7cIgfaZAeRDJ3SQEbaPxVC7X8aqGCOM-pQOjZPKUJN8DMFrlHTOdqMs0TwQ2PRBmVAxXTSOZOoEhD4ZNCHohYoyfoDhJDP4Qye_FCqu6POJzg0Jcun4d3KW04QTiGxv2PkYqmB7nHxYuJdnqE3704hIS56pc_8q6AW0WIT0W-nIvwzaSbtBU9RgaC7ZpBD2LiNE265UBIFraMDF8IAFw9itZSUCTKg1Q-q27NwwBZNGYStMdIBDor2Bsq5ge51EkWajzZ7ALisVp-bskzUsqUf77ejqX_CBAqkNdH1Zebn93A", authPrefix)}
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
	tests := []struct {
		name           string
		method         string
		contentType    string
		body           string
		allowed        bool
		expectedBody   interface{}
		expectedForm   url.Values
		expectedStatus int
		drainBody      bool
	}{
		{
			name:           "get",
			method:         "GET",
			allowed:        true,
			expectedStatus: http.StatusOK,
		},
		{
			name:        "json",
			method:      "POST",
			contentType: "application/json",
			body:        `{ "killroy": "washere" }`,
			allowed:     true,
			expectedBody: map[string]interface{}{
				"killroy": "washere",
			},
			expectedStatus: http.StatusOK,
			drainBody:      true,
		},
		{
			name:        "jsonArray",
			method:      "POST",
			contentType: "application/json",
			body:        `[ "killroy", "washere" ]`,
			allowed:     true,
			expectedBody: []interface{}{
				"killroy", "washere",
			},
			expectedStatus: http.StatusOK,
			drainBody:      true,
		},
		{
			name:           "jsonLiteral",
			method:         "POST",
			contentType:    "application/json",
			body:           `"killroy"`,
			allowed:        true,
			expectedBody:   "killroy",
			expectedStatus: http.StatusOK,
			drainBody:      true,
		},
		{
			name:           "nobody",
			method:         "POST",
			contentType:    "application/json",
			body:           `{ "killroy": "washere" }`,
			allowed:        true,
			expectedBody:   nil,
			expectedStatus: http.StatusOK,
			drainBody:      false,
		},
		{
			name:        "form",
			method:      "POST",
			contentType: "application/x-www-form-urlencoded",
			body:        `foo=bar&bar=foo`,
			allowed:     true,
			expectedForm: map[string][]string{
				"foo": {"bar"},
				"bar": {"foo"},
			},
			expectedStatus: http.StatusOK,
			drainBody:      true,
		},
		{
			name:        "multipart",
			method:      "POST",
			contentType: "multipart/form-data; boundary=----boundary",
			body:        "------boundary\nContent-Disposition: form-data; name=\"field1\"\n\nblabla\n------boundary--",
			allowed:     true,
			expectedForm: map[string][]string{
				"field1": {"blabla"},
			},
			expectedStatus: http.StatusOK,
			drainBody:      true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var input Payload
				err := json.NewDecoder(r.Body).Decode(&input)
				if err != nil {
					t.Fatal(err)
				}
				if tt.expectedBody != nil && !reflect.DeepEqual(input.Input.Body, tt.expectedBody) {
					t.Fatalf("Expected %v, got %v", tt.expectedBody, input.Input.Body)
				}
				if len(tt.expectedForm) == 0 && !reflect.DeepEqual(input.Input.Form, tt.expectedForm) {
					t.Fatalf("Expected %v, got %v", tt.expectedForm, input.Input.Form)
				}
				w.WriteHeader(http.StatusOK)
				_, _ = fmt.Fprintf(w, `{ "result": { "allow": %t, "foo": "Bar" } }`, tt.allowed)
			}))
			defer ts.Close()
			cfg := Config{
				OpaUrl:        fmt.Sprintf("%s/v1/data/testok?Param1=foo&Param1=bar", ts.URL),
				OpaAllowField: "allow",
				OpaBody:       tt.drainBody,
			}
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

			jwt, err := New(ctx, next, &cfg, "test-traefik-jwt-plugin")
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
			resp := recorder.Result()
			if resp.StatusCode != tt.expectedStatus {
				t.Fatalf("Expected status code %d, received %d", tt.expectedStatus, resp.StatusCode)
			}
		})
	}
}

func TestServeWithBody(t *testing.T) {
	// TODO: add more testcases with DSA, etc.
	cfg := Config{
		JwtHeaders: map[string]string{"Name": "name"},
		Keys:       []string{"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnzyis1ZjfNB0bBgKFMSv\nvkTtwlvBsaJq7S5wA+kzeVOVpVWwkWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHc\naT92whREFpLv9cj5lTeJSibyr/Mrm/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIy\ntvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0\ne+lf4s4OxQawWD79J9/5d3Ry0vbV3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWb\nV6L11BWkpzGXSW4Hv43qa+GSYOD2QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9\nMwIDAQAB\n-----END PUBLIC KEY-----"},
	}
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

	jwt, err := New(ctx, next, &cfg, "test-traefik-jwt-plugin")
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

func TestServeGETWithContentType(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintln(w, `{ "result": { "allow": true } }`)
	}))
	defer ts.Close()
	cfg := *CreateConfig()
	cfg.Required = false
	cfg.OpaUrl = ts.URL

	ctx := context.Background()
	nextCalled := false
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) { nextCalled = true })

	jwt, err := New(ctx, next, &cfg, "test-traefik-jwt-plugin")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header["Content-Type"] = []string{"application/json"}

	jwt.ServeHTTP(recorder, req)

	if nextCalled == false {
		t.Fatal("next.ServeHTTP was not called")
	}
}

func TestServeHTTPInvalidSignature(t *testing.T) {
	cfg := Config{
		Required:      true,
		PayloadFields: []string{"exp"},
		Keys:          []string{"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnzyis1ZjfNB0bBgKFMSv\nvkTtwlvBsaJq7S5wA+kzeVOVpVWwkWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHc\naT92whREFpLv9cj5lTeJSibyr/Mrm/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIy\ntvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0\ne+lf4s4OxQawWD79J9/5d3Ry0vbV3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWb\nV6L11BWkpzGXSW4Hv43qa+GSYOD2QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9\nMwIDAQAB\n-----END PUBLIC KEY-----"},
	}
	ctx := context.Background()
	nextCalled := false
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) { nextCalled = true })

	jwt, err := New(ctx, next, &cfg, "test-traefik-jwt-plugin")
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
	cfg := Config{
		PayloadFields: []string{"exp"},
		Required:      true,
		Keys:          []string{"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnzyis1ZjfNB0bBgKFMSv\nvkTtwlvBsaJq7S5wA+kzeVOVpVWwkWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHc\naT92whREFpLv9cj5lTeJSibyr/Mrm/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIy\ntvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0\ne+lf4s4OxQawWD79J9/5d3Ry0vbV3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWb\nV6L11BWkpzGXSW4Hv43qa+GSYOD2QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9\nMwIDAQAB\n-----END PUBLIC KEY-----"},
	}
	ctx := context.Background()
	nextCalled := false
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) { nextCalled = true })

	jwt, err := New(ctx, next, &cfg, "test-traefik-jwt-plugin")
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

func TestServeHTTPAllowedByOPA(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/data/testok" {
			t.Fatalf("Path incorrect: %s", r.URL.Path)
		}
		param1 := r.URL.Query()["Param1"]
		if len(param1) != 2 || param1[0] != "foo" || param1[1] != "bar" {
			t.Fatalf("Parameters incorrect, expected foo,bar but got %s", strings.Join(param1, ","))
		}
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintln(w, `{ "result": { "allow": true, "foo": "Bar" } }`)
	}))
	defer ts.Close()
	cfg := Config{
		OpaAllowField:      "allow",
		Required:           false,
		OpaUrl:             fmt.Sprintf("%s/v1/data/testok?Param1=foo&Param1=bar", ts.URL),
		OpaBody:            false,
		OpaHeaders:         map[string]string{"RequestFoo": "foo", "RequestAllow": "allow", "RequestMissing": "missing"},
		OpaResponseHeaders: map[string]string{"ResponseFoo": "foo", "ResponseAllow": "allow", "ResponseMissing": "missing"},
	}

	ctx := context.Background()
	nextCalled := false
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) { nextCalled = true })

	opa, err := New(ctx, next, &cfg, "test-traefik-jwt-plugin")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost?frodo=notpass", nil)
	req.Header.Add("Content-Type", "application/json")
	if err != nil {
		t.Fatal(err)
	}

	opa.ServeHTTP(recorder, req)

	resp := recorder.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status code %d, received %d", http.StatusOK, resp.StatusCode)
	}
	if nextCalled == false {
		t.Fatal("next.ServeHTTP was not called")
	}
	if req.Header.Get("RequestFoo") != "Bar" {
		t.Fatal("Expected RequestFoo:Bar header")
	}
	if req.Header.Get("RequestAllow") != "true" {
		t.Fatal("Expected RequestAllow:true header")
	}
	if req.Header.Get("RequestMissing") != "" {
		t.Fatal("Unexpected RequestMissing: header")
	}
	if resp.Header.Get("ResponseFoo") != "Bar" {
		t.Fatal("Expected ResponseFoo:Bar header")
	}
	if resp.Header.Get("ResponseAllow") != "true" {
		t.Fatal("Expected Responsellow:true header")
	}
	if resp.Header.Get("ResponseMissing") != "" {
		t.Fatal("Unexpected ResponseMissing: header")
	}
}

func TestServeHTTPForbiddenByOPA(t *testing.T) {
	opaResponse := "{ \"result\": { \"allow\": false, \"foo\": \"Bar\" } }"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte(opaResponse))
		if err != nil {
			t.Fatal("Failed to write opa response")
		}
	}))
	defer ts.Close()
	cfg := Config{
		OpaAllowField:      "allow",
		Required:           false,
		OpaUrl:             ts.URL,
		OpaBody:            false,
		OpaHeaders:         map[string]string{"RequestFoo": "foo", "RequestAllow": "allow", "RequestMissing": "missing"},
		OpaResponseHeaders: map[string]string{"ResponseFoo": "foo", "ResponseAllow": "allow", "ResponseMissing": "missing"},
	}
	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) { t.Fatal("Should not chain HTTP call") })

	opa, err := New(ctx, next, &cfg, "test-traefik-jwt-plugin")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}

	opa.ServeHTTP(recorder, req)

	resp := recorder.Result()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("Expected status code %d, received %d", http.StatusForbidden, resp.StatusCode)
	}
	validateOpaResponse(t, req, resp, "forbidden")

	// enable OpaDebugMode
	cfg.OpaDebugMode = true
	opa, err = New(ctx, next, &cfg, "test-traefik-jwt-plugin")
	if err != nil {
		t.Fatal(err)
	}

	recorder = httptest.NewRecorder()

	req, err = http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}

	opa.ServeHTTP(recorder, req)
	resp = recorder.Result()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("Expected status code %d, received %d", http.StatusForbidden, resp.StatusCode)
	}

	validateOpaResponse(t, req, resp, opaResponse)
}

func validateOpaResponse(t *testing.T, req *http.Request, resp *http.Response, opaResponseBody string) {
	body, _ := io.ReadAll(resp.Body)

	if strings.TrimSpace(string(body)) != opaResponseBody {
		t.Fatalf("The body response is expected to be %q, but found: %s", opaResponseBody, string(body))
	}
	if req.Header.Get("RequestFoo") == "Bar" {
		t.Fatal("Unexpected RequestFoo:Bar header")
	}
	if req.Header.Get("RequestAllow") == "false" {
		t.Fatal("Unexpected RequestAllow:true header")
	}
	if req.Header.Get("RequestMissing") != "" {
		t.Fatal("Unexpected RequestMissing: header")
	}
	if resp.Header.Get("ResponseFoo") != "Bar" {
		t.Fatal("Expected ResponseFoo:Bar header")
	}
	if resp.Header.Get("ResponseAllow") != "false" {
		t.Fatal("Expected Responsellow:false header")
	}
	if resp.Header.Get("ResponseMissing") != "" {
		t.Fatal("Unexpected ResponseMissing: header")
	}
}

func TestNewJWKEndpoint(t *testing.T) {
	tests := []struct {
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
		{
			name:   "rsa-multiplekeys",
			key:    `{"keys":[{"alg":"RS512","e":"AQAB","n":"nzyis1ZjfNB0bBgKFMSvvkTtwlvBsaJq7S5wA-kzeVOVpVWwkWdVha4s38XM_pa_yr47av7-z3VTmvDRyAHcaT92whREFpLv9cj5lTeJSibyr_Mrm_YtjCZVWgaOYIhwrXwKLqPr_11inWsAkfIytvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0e-lf4s4OxQawWD79J9_5d3Ry0vbV3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWbV6L11BWkpzGXSW4Hv43qa-GSYOD2QU68Mb59oSk2OB-BtOLpJofmbGEGgvmwyCI9Mw","kty":"RSA"},{ "alg":"PS384", "kty": "RSA", "n": "nzyis1ZjfNB0bBgKFMSvvkTtwlvBsaJq7S5wA-kzeVOVpVWwkWdVha4s38XM_pa_yr47av7-z3VTmvDRyAHcaT92whREFpLv9cj5lTeJSibyr_Mrm_YtjCZVWgaOYIhwrXwKLqPr_11inWsAkfIytvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0e-lf4s4OxQawWD79J9_5d3Ry0vbV3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWbV6L11BWkpzGXSW4Hv43qa-GSYOD2QU68Mb59oSk2OB-BtOLpJofmbGEGgvmwyCI9Mw", "e": "AQAB" }]}`,
			token:  "Bearer eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.JlX3gXGyClTBFciHhknWrjo7SKqyJ5iBO0n-3S2_I7cIgfaZAeRDJ3SQEbaPxVC7X8aqGCOM-pQOjZPKUJN8DMFrlHTOdqMs0TwQ2PRBmVAxXTSOZOoEhD4ZNCHohYoyfoDhJDP4Qye_FCqu6POJzg0Jcun4d3KW04QTiGxv2PkYqmB7nHxYuJdnqE3704hIS56pc_8q6AW0WIT0W-nIvwzaSbtBU9RgaC7ZpBD2LiNE265UBIFraMDF8IAFw9itZSUCTKg1Q-q27NwwBZNGYStMdIBDor2Bsq5ge51EkWajzZ7ALisVp-bskzUsqUf77ejqX_CBAqkNdH1Zebn93A",
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
			cfg := Config{
				Keys: []string{ts.URL},
			}
			ctx := context.Background()
			nextCalled := false
			next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) { nextCalled = true })

			opa, err := New(ctx, next, &cfg, "test-traefik-jwt-plugin")
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

			resp := recorder.Result()
			if resp.StatusCode != tt.status {
				t.Fatalf("Expected status code %d, received %d", tt.status, resp.StatusCode)
			}
			if nextCalled != tt.next {
				t.Fatalf("next.ServeHTTP was called: %t, expected: %t", nextCalled, tt.next)
			}
		})
	}
}

func TestForceRefreshKeys(t *testing.T) {
	keys := `{"keys":[{"kty":"oct","kid":"57bd26a0-6209-4a93-a688-f8752be5d191","k":"eW91ci01MTItYml0LXNlY3JldA","alg":"HS512"}]}`
	token := "Bearer eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCIsImNyaXQiOlsia2lkIl0sImtpZCI6IjU3YmQyNmEwLTYyMDktNGE5My1hNjg4LWY4NzUyYmU1ZDE5MSJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.573ixRAw4I4XUFJwJGpv5dHNOGaexX5zTtF0nOQTWuU2_JyZjD-7cuMPxQUHOv8RR0kQrS0uVdo_N1lzTCPFnA"
	jwksCalledCounter := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() { jwksCalledCounter++ }()
		w.WriteHeader(http.StatusOK)
		if jwksCalledCounter == 0 {
			fmt.Fprintln(w, `{"keys":[]}`)
			return
		}
		_, _ = fmt.Fprintln(w, keys)
	}))
	defer ts.Close()
	cfg := Config{
		Keys:             []string{ts.URL},
		ForceRefreshKeys: true,
	}
	ctx := context.Background()
	nextCalled := false
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) { nextCalled = true })
	opa, err := New(ctx, next, &cfg, "test-traefik-jwt-plugin")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("Authorization", token)

	opa.ServeHTTP(recorder, req)

	resp := recorder.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status code %d, received %d", http.StatusOK, resp.StatusCode)
	}
	if !nextCalled {
		t.Fatalf("next.ServeHTTP was called: %t, expected: %t", nextCalled, true)
	}
	if jwksCalledCounter != 2 {
		t.Fatalf("jwks was called: %d times, expected: %d", jwksCalledCounter, 2)
	}
}

func TestIssue3(t *testing.T) {
	cfg := Config{
		JwtHeaders: map[string]string{"Subject": "sub", "User": "preferred_username"},
		Keys:       []string{"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnzyis1ZjfNB0bBgKFMSv\nvkTtwlvBsaJq7S5wA+kzeVOVpVWwkWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHc\naT92whREFpLv9cj5lTeJSibyr/Mrm/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIy\ntvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0\ne+lf4s4OxQawWD79J9/5d3Ry0vbV3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWb\nV6L11BWkpzGXSW4Hv43qa+GSYOD2QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9\nMwIDAQAB\n-----END PUBLIC KEY-----"},
	}
	ctx := context.Background()
	nextCalled := false
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) { nextCalled = true })

	jwt, err := New(ctx, next, &cfg, "test-traefik-jwt-plugin")
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

func TestIssue13(t *testing.T) {
	cfg := Config{
		JwtHeaders: map[string]string{"Subject": "sub", "User": "preferred_username"},
		Keys:       []string{"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnzyis1ZjfNB0bBgKFMSv\nvkTtwlvBsaJq7S5wA+kzeVOVpVWwkWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHc\naT92whREFpLv9cj5lTeJSibyr/Mrm/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIy\ntvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0\ne+lf4s4OxQawWD79J9/5d3Ry0vbV3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWb\nV6L11BWkpzGXSW4Hv43qa+GSYOD2QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9\nMwIDAQAB\n-----END PUBLIC KEY-----", "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmDaxrT7mDmyGHZaBuwq6\nMimV2hUrOoZ86MT/dTpspnNL4DgvvUOjvkn7Oebg9kNmAxjfqDmHtqKdKvot/vZp\nJMPr/+s/haBDN3plDf3SeWOEWwFgVwkLnkOm+mCWEvhYL6bBGCcv9AwYYtyQONKg\n+2NFOVxtQVlGo1Z8xUIY4vELiUcqTjqBZPi3+CaxqWvGsh5Wg4Si84/xKx85Ah6f\nrAtPGGO8wG2Jqlw1R4ZHJmBgXtLXTeDI2zzxugI1BtcQfy5fd9PBVoEM6782km0R\nei3X8CqIMuv00O2juFh2rZxC9ENibTbdf2OueI+sbYoP1FsziruDHJRzKnm/oAVY\nDwIDAQAB\n-----END PUBLIC KEY-----"},
	}
	ctx := context.Background()
	nextCalled := false
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) { nextCalled = true })

	jwt, err := New(ctx, next, &cfg, "test-traefik-jwt-plugin")
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

func TestIssue15(t *testing.T) {
	cfg := Config{
		JwtHeaders: map[string]string{"X-Subject": "sub", "X-Exp": "exp", "X-Email-Verified": "email_verified"},
	}
	ctx := context.Background()
	nextCalled := false
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) { nextCalled = true })

	jwt, err := New(ctx, next, &cfg, "test-traefik-jwt-plugin")
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
	if v := req.Header.Get("X-Subject"); v != "c03a3d8a-e0b5-47ca-9b0f-b2f9e69cf348" {
		t.Fatal("Expected header X-Subject: c03a3d8a-e0b5-47ca-9b0f-b2f9e69cf348")
	}
	if v := req.Header.Get("X-Exp"); v != "1619214722" {
		t.Fatal("Expected header X-Exp: 1619214722")
	}
	if v := req.Header.Get("X-Email-Verified"); v != "false" {
		t.Fatal("Expected header X-Email-Verified: false")
	}
}

func TestServeHTTPExpiration(t *testing.T) {
	lastMinute := time.Now().Add(-1 * time.Minute).Unix()
	nextMinute := time.Now().Add(2 * time.Minute).Unix()
	tests := []struct {
		Name   string `json:"sub"`
		Fields []string
		Claims string
		err    string
	}{
		{
			Name:   "valid",
			Fields: []string{"exp", "nbf"},
			Claims: fmt.Sprintf(`{"exp": %d, "nbf": %d}`, nextMinute, lastMinute),
			err:    "",
		},
		{
			Name:   "no expiration",
			Claims: "{}",
			err:    "",
		},
		{
			Name:   "valid - exp only",
			Fields: []string{"exp"},
			Claims: fmt.Sprintf(`{"exp": %d}`, nextMinute),
			err:    "",
		},
		{
			Name:   "expired",
			Fields: []string{"exp"},
			Claims: fmt.Sprintf(`{"exp": %d}`, lastMinute),
			err:    "token is expired",
		},
		{
			Name:   "not yet valid",
			Fields: []string{"exp", "nbf"},
			Claims: fmt.Sprintf(`{"exp": %d, "nbf": %d}`, nextMinute, nextMinute),
			err:    "token not valid yet",
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			ctx := context.Background()
			nextCalled := false
			next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) { nextCalled = true })

			jwt, err := New(ctx, next, &Config{PayloadFields: tt.Fields}, "test-traefik-jwt-plugin")
			if err != nil {
				t.Fatal(err)
			}

			recorder := httptest.NewRecorder()

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
			if err != nil {
				t.Fatal(err)
			}

			req.Header["Authorization"] = []string{"Bearer eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9." + base64.RawURLEncoding.EncodeToString([]byte(tt.Claims)) + ".JlX3gXGyClTBFciHhknWrjo7SKqyJ5iBO0n-3S2_I7cIgfaZAeRDJ3SQEbaPxVC7X8aqGCOM-pQOjZPKUJN8DMFrlHTOdqMs0TwQ2PRBmVAxXTSOZOoEhD4ZNCHohYoyfoDhJDP4Qye_FCqu6POJzg0Jcun4d3KW04QTiGxv2PkYqmB7nHxYuJdnqE3704hIS56pc_8q6AW0WIT0W-nIvwzaSbtBU9RgaC7ZpBD2LiNE265UBIFraMDF8IAFw9itZSUCTKg1Q-q27NwwBZNGYStMdIBDor2Bsq5ge51EkWajzZ7ALisVp-bskzUsqUf77ejqX_CBAqkNdH1Zebn93A"}

			jwt.ServeHTTP(recorder, req)

			if tt.err == "" && nextCalled == false {
				t.Fatal("next.ServeHTTP was not called")
			} else if tt.err != "" {
				if nextCalled == true {
					t.Fatal("next.ServeHTTP was called")
				} else if tt.err != strings.TrimSpace(recorder.Body.String()) {
					t.Fatalf("Expected error: %s, got: %s", tt.err, recorder.Body.String())
				}
			}
		})
	}
}

func TestServeHTTPJwtRequired(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintln(w, `{ "result": { "allow": true }`)
	}))
	defer ts.Close()
	cfg := Config{
		OpaAllowField: "allow",
		Required:      true,
		OpaUrl:        ts.URL,
		OpaBody:       false,
	}

	ctx := context.Background()
	nextCalled := false
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) { nextCalled = true })

	opa, err := New(ctx, next, &cfg, "test-traefik-jwt-plugin")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	req.Header.Add("Content-Type", "application/json")
	if err != nil {
		t.Fatal(err)
	}

	opa.ServeHTTP(recorder, req)

	resp := recorder.Result()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("Expected status code %d, received %d", http.StatusForbidden, resp.StatusCode)
	}
	if nextCalled == true {
		t.Fatal("next.ServeHTTP was called")
	}
}

func TestServeHTTPStatusFromOPA(t *testing.T) {
	tests := []struct {
		name               string
		opaHttpStatusField string
		statusFieldName    string
		statusFieldValue   string
		expectedStatus     int
	}{
		{
			name:               "status field int",
			opaHttpStatusField: "allow_status_code",
			statusFieldName:    "allow_status_code",
			statusFieldValue:   "401",
			expectedStatus:     http.StatusUnauthorized,
		},
		{
			name:               "status field string",
			opaHttpStatusField: "allow_status_code",
			statusFieldName:    "allow_status_code",
			statusFieldValue:   "\"401\"",
			expectedStatus:     http.StatusUnauthorized,
		},
		{
			name:               "status field incorrect type",
			opaHttpStatusField: "allow_status_code",
			statusFieldName:    "allow_status_code",
			statusFieldValue:   "401.12",
			expectedStatus:     http.StatusForbidden,
		},
		{
			name:               "status field missing",
			opaHttpStatusField: "allow_status_code",
			statusFieldName:    "missing",
			statusFieldValue:   "401",
			expectedStatus:     http.StatusForbidden,
		},
		{
			name:               "status field out of lower range",
			opaHttpStatusField: "allow_status_code",
			statusFieldName:    "allow_status_code",
			statusFieldValue:   "200",
			expectedStatus:     http.StatusForbidden,
		},
		{
			name:               "status field out of upper range",
			opaHttpStatusField: "allow_status_code",
			statusFieldName:    "allow_status_code",
			statusFieldValue:   "600",
			expectedStatus:     http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = fmt.Fprintf(w, "{ \"result\": { \"allow\": false, \"%s\": %s }}\n", tt.statusFieldName, tt.statusFieldValue)
			}))
			defer ts.Close()
			cfg := Config{
				Required:           false,
				OpaAllowField:      "allow",
				OpaUrl:             ts.URL,
				OpaBody:            false,
				OpaHttpStatusField: tt.opaHttpStatusField,
			}

			ctx := context.Background()
			nextCalled := false
			next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) { nextCalled = true })

			opa, err := New(ctx, next, &cfg, "test-traefik-jwt-plugin")
			if err != nil {
				t.Fatal(err)
			}

			recorder := httptest.NewRecorder()

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
			req.Header.Add("Content-Type", "application/json")
			if err != nil {
				t.Fatal(err)
			}

			opa.ServeHTTP(recorder, req)

			resp := recorder.Result()
			if resp.StatusCode != tt.expectedStatus {
				t.Fatalf("Expected status code %d, received %d", tt.expectedStatus, resp.StatusCode)
			}
			if nextCalled == true {
				t.Fatal("next.ServeHTTP was called")
			}
		})
	}
}

func TestTokenFromCookieConfigured(t *testing.T) {
	cfg := *CreateConfig()
	cfg.JwtCookieKey = "jwt"
	ctx := context.Background()
	nextCalled := false
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) { nextCalled = true })

	jwt, err := New(ctx, next, &cfg, "test-traefik-jwt-plugin")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}

	req.AddCookie(&http.Cookie{Name: "jwt", Value: "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.TnHVsM5_N0SKi_HCwlz3ys1cDktu10g_sKkjqzVe5k09z-bmByflWPFWjAbwgRCKAc77kF8BjDNv0gisAPurBxgxNGxioDFehhcb0IS0YeCAWpzRfBMT6gQZ1gZeNM2Dg_yf4shPhF4rcUCGqnFFzIDSU9Rv2NNMK5DPO4512uTxAQUMHpi5PGTki-zykqTB10Ju1L4jRhmJwJDtGcfdHPlEKKUrFPfYl3RPZLOfdyAqSJ8Gi0R3ymDffmXHz08AJUAY_Kapk8laggIYcvFJhYGJBWZpcy7NWMiOIjEI3bogki4o7z0-Z1xMZdZ9rqypQ1MB44F8VZS2KkPfEmhSog"})

	jwt.ServeHTTP(recorder, req)

	if nextCalled == false {
		t.Fatal("next.ServeHTTP was not called")
	}
}

func TestTokenFromCookieConfiguredButNotSet(t *testing.T) {
	cfg := *CreateConfig()
	cfg.JwtCookieKey = "jwt"
	ctx := context.Background()
	nextCalled := false
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) { nextCalled = true })

	jwt, err := New(ctx, next, &cfg, "test-traefik-jwt-plugin")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}

	jwt.ServeHTTP(recorder, req)

	resp := recorder.Result()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("Expected status code %d, received %d", http.StatusForbidden, resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	responseBodyExpected := "http: named cookie not present"
	if strings.TrimSpace(string(body)) != responseBodyExpected {
		t.Fatalf("The body response is expected to be %q, but found: %s", responseBodyExpected, string(body))
	}

	if nextCalled == true {
		t.Fatal("next.ServeHTTP was called, but should not")
	}
}

func TestTokenFromCookieNotConfigured(t *testing.T) {
	cfg := *CreateConfig()
	ctx := context.Background()
	nextCalled := false
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) { nextCalled = true })

	jwt, err := New(ctx, next, &cfg, "test-traefik-jwt-plugin")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}

	req.AddCookie(&http.Cookie{Name: "jwt", Value: "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.TnHVsM5_N0SKi_HCwlz3ys1cDktu10g_sKkjqzVe5k09z-bmByflWPFWjAbwgRCKAc77kF8BjDNv0gisAPurBxgxNGxioDFehhcb0IS0YeCAWpzRfBMT6gQZ1gZeNM2Dg_yf4shPhF4rcUCGqnFFzIDSU9Rv2NNMK5DPO4512uTxAQUMHpi5PGTki-zykqTB10Ju1L4jRhmJwJDtGcfdHPlEKKUrFPfYl3RPZLOfdyAqSJ8Gi0R3ymDffmXHz08AJUAY_Kapk8laggIYcvFJhYGJBWZpcy7NWMiOIjEI3bogki4o7z0-Z1xMZdZ9rqypQ1MB44F8VZS2KkPfEmhSog"})

	jwt.ServeHTTP(recorder, req)

	if nextCalled == true {
		t.Fatal("next.ServeHTTP was called, but should not")
	}
}

func TestTokenFromQueryConfigured(t *testing.T) {
	cfg := *CreateConfig()
	cfg.JwtQueryKey = "jwt"
	ctx := context.Background()
	nextCalled := false
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) { nextCalled = true })

	jwt, err := New(ctx, next, &cfg, "test-traefik-jwt-plugin")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}
	query := req.URL.Query()
	query.Add("jwt", "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.TnHVsM5_N0SKi_HCwlz3ys1cDktu10g_sKkjqzVe5k09z-bmByflWPFWjAbwgRCKAc77kF8BjDNv0gisAPurBxgxNGxioDFehhcb0IS0YeCAWpzRfBMT6gQZ1gZeNM2Dg_yf4shPhF4rcUCGqnFFzIDSU9Rv2NNMK5DPO4512uTxAQUMHpi5PGTki-zykqTB10Ju1L4jRhmJwJDtGcfdHPlEKKUrFPfYl3RPZLOfdyAqSJ8Gi0R3ymDffmXHz08AJUAY_Kapk8laggIYcvFJhYGJBWZpcy7NWMiOIjEI3bogki4o7z0-Z1xMZdZ9rqypQ1MB44F8VZS2KkPfEmhSog")
	req.URL.RawQuery = query.Encode()

	jwt.ServeHTTP(recorder, req)

	if nextCalled == false {
		t.Fatal("next.ServeHTTP was not called")
	}
}

func TestTokenFromQueryNotConfigured(t *testing.T) {
	cfg := *CreateConfig()
	ctx := context.Background()
	nextCalled := false
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) { nextCalled = true })

	jwt, err := New(ctx, next, &cfg, "test-traefik-jwt-plugin")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}

	query := req.URL.Query()
	query.Add("jwt", "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.TnHVsM5_N0SKi_HCwlz3ys1cDktu10g_sKkjqzVe5k09z-bmByflWPFWjAbwgRCKAc77kF8BjDNv0gisAPurBxgxNGxioDFehhcb0IS0YeCAWpzRfBMT6gQZ1gZeNM2Dg_yf4shPhF4rcUCGqnFFzIDSU9Rv2NNMK5DPO4512uTxAQUMHpi5PGTki-zykqTB10Ju1L4jRhmJwJDtGcfdHPlEKKUrFPfYl3RPZLOfdyAqSJ8Gi0R3ymDffmXHz08AJUAY_Kapk8laggIYcvFJhYGJBWZpcy7NWMiOIjEI3bogki4o7z0-Z1xMZdZ9rqypQ1MB44F8VZS2KkPfEmhSog")
	req.URL.RawQuery = query.Encode()

	jwt.ServeHTTP(recorder, req)

	if nextCalled == true {
		t.Fatal("next.ServeHTTP was called, but should not")
	}
}

func TestTokenFromQueryConfiguredButNotInURL(t *testing.T) {
	cfg := *CreateConfig()
	cfg.JwtQueryKey = "jwt"
	ctx := context.Background()
	nextCalled := false
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) { nextCalled = true })

	jwt, err := New(ctx, next, &cfg, "test-traefik-jwt-plugin")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}

	jwt.ServeHTTP(recorder, req)

	resp := recorder.Result()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("Expected status code %d, received %d", http.StatusForbidden, resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	responseBodyExpected := "query parameter missing"
	if strings.TrimSpace(string(body)) != responseBodyExpected {
		t.Fatalf("The body response is expected to be %q, but found: %s", responseBodyExpected, string(body))
	}

	if nextCalled == true {
		t.Fatal("next.ServeHTTP was called, but should not")
	}
}

func TestTokenFromHeaderConfigured(t *testing.T) {
	cfg := *CreateConfig()
	cfg.JwtSources = []map[string]string{{"type": "header", "key": "X-JWT"}}
	ctx := context.Background()
	nextCalled := false
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) { nextCalled = true })

	jwt, err := New(ctx, next, &cfg, "test-traefik-jwt-plugin")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header["X-JWT"] = []string{"eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.TnHVsM5_N0SKi_HCwlz3ys1cDktu10g_sKkjqzVe5k09z-bmByflWPFWjAbwgRCKAc77kF8BjDNv0gisAPurBxgxNGxioDFehhcb0IS0YeCAWpzRfBMT6gQZ1gZeNM2Dg_yf4shPhF4rcUCGqnFFzIDSU9Rv2NNMK5DPO4512uTxAQUMHpi5PGTki-zykqTB10Ju1L4jRhmJwJDtGcfdHPlEKKUrFPfYl3RPZLOfdyAqSJ8Gi0R3ymDffmXHz08AJUAY_Kapk8laggIYcvFJhYGJBWZpcy7NWMiOIjEI3bogki4o7z0-Z1xMZdZ9rqypQ1MB44F8VZS2KkPfEmhSog"}

	jwt.ServeHTTP(recorder, req)

	if nextCalled == false {
		t.Fatal("next.ServeHTTP was not called")
	}
}

func TestTokenSourceOrder(t *testing.T) {
	cfg := *CreateConfig()
	cfg.JwtSources = []map[string]string{{"type": "header", "key": "X-JWT"}, {"type": "cookie", "key": "jwt"}}
	ctx := context.Background()
	nextCalled := false
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) { nextCalled = true })

	jwt, err := New(ctx, next, &cfg, "test-traefik-jwt-plugin")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(&http.Cookie{Name: "jwt", Value: "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.TnHVsM5_N0SKi_HCwlz3ys1cDktu10g_sKkjqzVe5k09z-bmByflWPFWjAbwgRCKAc77kF8BjDNv0gisAPurBxgxNGxioDFehhcb0IS0YeCAWpzRfBMT6gQZ1gZeNM2Dg_yf4shPhF4rcUCGqnFFzIDSU9Rv2NNMK5DPO4512uTxAQUMHpi5PGTki-zykqTB10Ju1L4jRhmJwJDtGcfdHPlEKKUrFPfYl3RPZLOfdyAqSJ8Gi0R3ymDffmXHz08AJUAY_Kapk8laggIYcvFJhYGJBWZpcy7NWMiOIjEI3bogki4o7z0-Z1xMZdZ9rqypQ1MB44F8VZS2KkPfEmhSog"})

	jwt.ServeHTTP(recorder, req)

	if nextCalled == false {
		t.Fatal("next.ServeHTTP was not called")
	}
}

func TestJwksHeaders(t *testing.T) {
	tests := []struct {
		name        string
		jwksHeaders map[string]string
		expected    map[string]string
	}{
		{
			name:        "No Headers",
			jwksHeaders: map[string]string{},
			expected:    map[string]string{},
		},
		{
			name:        "One Header",
			jwksHeaders: map[string]string{"Content-Type": "application/json"},
			expected:    map[string]string{"Content-Type": "application/json"},
		},
		{
			name: "Multiple Headers",
			jwksHeaders: map[string]string{
				"Authorization": "Bearer token",
				"User-Agent":    "Traefik",
			},
			expected: map[string]string{
				"Authorization": "Bearer token",
				"User-Agent":    "Traefik",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{
				JwksHeaders: tt.jwksHeaders,
			}
			ctx := context.Background()

			jwtPlugin, err := New(ctx, nil, &cfg, "test-traefik-jwt-plugin")
			if err != nil {
				t.Fatal(err)
			}

			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				for key, val := range tt.expected {
					if r.Header.Get(key) != val {
						t.Errorf("Expected header %s to be %s, got %s", key, val, r.Header.Get(key))
					}
				}
			}))
			defer ts.Close()

			jwtPlugin.(*JwtPlugin).jwkEndpoints = append(jwtPlugin.(*JwtPlugin).jwkEndpoints, mustParseUrl(ts.URL))

			jwtPlugin.(*JwtPlugin).FetchKeys()
		})
	}
}

func mustParseUrl(urlStr string) *url.URL {
	u, err := url.Parse(urlStr)
	if err != nil {
		panic(err)
	}
	return u
}
