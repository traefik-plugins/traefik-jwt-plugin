# traefik-jwt-plugin ![Build](https://github.com/team-carepay/traefik-jwt-plugin/workflows/build/badge.svg)
Traefik plugin for verifying JSON Web Tokens (JWT). Supports public keys, certificates or JWKS endpoints.
Supports RSA, ECDSA and symmetric keys. Supports Open Policy Agent (OPA) for additional authorization checks.

Features:
* RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384, ES512, HS256, HS384, HS512
* Certificates or public keys can be configured in the dynamic config 
* Supports JWK endpoints for fetching keys remotely
* Reject a request or Log warning when required field is missing from JWT payload
* Validate request with Open Policy Agent
* Adds the verified and decoded token to the OPA input

## Installation
The plugin needs to be configured in the Traefik static configuration before it can be used.
### Installation with Helm
The following snippet can be used as an example for the values.yaml file:
```values.yaml
pilot:
  enabled: true
  token: xxxxx-xxxx-xxxx

experimental:
  plugins:
    enabled: true

additionalArguments:
- --experimental.plugins.jwt.moduleName=github.com/team-carepay/traefik-jwt-plugin
- --experimental.plugins.jwt.version=v0.0.1
```

### Installation via command line
```
traefik \
  --experimental.pilot.token=xxxx-xxxx-xxx \
  --experimental.plugins.jwt.moduleName=github.com/team-carepay/traefik-jwt-plugin \
  --experimental.plugins.jwt.version=v0.0.3
```

## Configuration
The plugin currently supports the following configuration settings:

Name | Description
--- | ---
OpaUrl | URL for Open Policy Agent (e.g. http://opa:8181/v1/data/example) 
OpaAllowField | Field in the JSON result which contains a boolean, indicating whether the request is allowed or not
PayloadFields | The field-name in the JWT payload that are required (e.g. `exp`). Multiple field names may be specificied (string array)
Required | When true, in case the JWT payload is missing a field, the request will be forbidden
Keys | Used to validate JWT signature. Multiple keys are supported. Allowed values include certificates, public keys, symmetric keys. In case the value is a valid URL, the plugin will fetch keys from the JWK endpoint.
Alg | Used to verify which PKI algorithm is used in the JWT
Iss | Used to verify the issuer of the JWT
Aud | Used to verify the audience of the JWT
JwtHeaders | Map used to inject JWT payload fields as an HTTP header
OpaHeaders | Map used to inject OPA result fields as an HTTP header

## Example configuration
This example uses Kubernetes Custom Resource Descriptors (CRD) :
```
apiVersion: traefik.containo.us/v1alpha1
kind: Middleware
metadata:
  name: jwt
spec:
  plugin:
    jwt:
      OpaUrl: http://localhost:8181/v1/data/example
      OpaAllowField: allow
      PayloadFields:
        - exp
      Required: true
      Keys:
        - |
          -----BEGIN PUBLIC KEY-----
          MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnzyis1ZjfNB0bBgKFMSv
          vkTtwlvBsaJq7S5wA+kzeVOVpVWwkWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHc
          aT92whREFpLv9cj5lTeJSibyr/Mrm/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIy
          tvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0
          e+lf4s4OxQawWD79J9/5d3Ry0vbV3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWb
          V6L11BWkpzGXSW4Hv43qa+GSYOD2QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9
          MwIDAQAB
        -----END PUBLIC KEY-----
      OpaHeaders:
        Allowed: allow
      JwtHeaders:
        Subject: sub
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: test-server
  labels:
    app: test-server
  annotations:
    kubernetes.io/ingress.class: traefik
    traefik.ingress.kubernetes.io/router.middlewares: default-jwt@kubernetescrd

```

# Open Policy Agent
The following section describes how to use this plugin with Open Policy Agent (OPA)

## OPA input payload
The plugin will translate the HTTP request (including headers and parameters) and forwards the payload as JSON to OPA. For example, the following URL: `http://localhost/api/path?param1=foo&param2=bar` will result in the following payload (headers are reduced for readability):

```
{
    "headers": {
      "Accept-Encoding": [
        "gzip, deflate, br"
      ],
      "X-Forwarded-Host": [
        "localhost"
      ],
      "X-Forwarded-Port": [
        "80"
      ],
      "X-Forwarded-Proto": [
        "http"
      ],
      "X-Forwarded-Server": [
        "traefik-84c77c5547-sm2cb"
      ],
      "X-Real-Ip": [
        "172.18.0.1"
      ]
    },
    "host": "localhost",
    "method": "GET",
    "parameters": {
      "param1": [
        "foo"
      ],
      "param2": [
        "bar"
      ]
    },
    "path": [
      "api",
      "path"
    ]
  }
```

## Example OPA policy in Rego
The policies you enforce can be as complex or simple as you prefer. For example, the policy could decode the JWT token and verify the token is valid and has not expired, and that the user has the required claims in the token.

The policy below shows an simplified example:
```
package example

default allow = false

allow {
	input.method = "GET"
	input.path[0] = "public"
}

allow {
	input.method = "GET"
	input.path = [ "secure", i ]
  has_token([ "123", "456"])
}

has_token(tokens) {
    input.path[1] = tokens[i]
}
```
In the above example, requesting `/public/anything` or `/secure/123` is allowed, however requesting `/secure/xxx` would be rejected and results in a 403 Forbidden.

## License
This software is released under the Apache 2.0 License
