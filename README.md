# traefik-jwt-plugin ![Build](https://github.com/team-carepay/traefik-jwt-plugin/workflows/build/badge.svg)
Traefik plugin which logs a warning when an invalid JWT token is encountered


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
RequiredField | The field-name in the JWT payload that is required (e.g. `exp`)

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
      RequiredField: exp
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
