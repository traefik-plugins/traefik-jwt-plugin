# traefik-jwt-plugin ![Build](https://github.com/team-carepay/traefik-jwt-plugin/workflows/build/badge.svg)
Traefik plugin for verifying JSON Web Tokens (JWT). Supports public keys, certificates or JWKS endpoints.
Supports RSA, ECDSA and symmetric keys. Supports Open Policy Agent (OPA) for additional authorization checks.

Features:
* RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384, ES512, HS256, HS384, HS512
* Certificates, Public Key or JWKS endpoint
* Reject a request or Log warning when required field is missing from JWT payload
* Open Policy Agent
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
Keys | Used to validate JWT signature. Multiple keys are supported
Alg | Used to verify which PKI algorithm is used in the JWT
Iss | Used to verify the issuer of the JWT
Aud | Used to verify the audience of the JWT

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


## License
This software is released under the Apache 2.0 License
