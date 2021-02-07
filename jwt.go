package traefik_jwt_plugin

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/traefik/traefik/v2/pkg/log"
)

// Config the plugin configuration.
type Config struct {
	RequiredField string `json:"required-field,omitempty"`
}

// CreateConfig creates a new OPA Config
func CreateConfig() *Config {
	return &Config{}
}

// Jwt contains the runtime config
type Jwt struct {
	next          http.Handler
	requiredField string
	log           *log.Logger
}

// LogEvent contains a single log entry
type LogEvent struct {
	Level string    `json:"level"`
	Msg   string    `json:"msg"`
	Time  time.Time `json:"time"`
}

// New creates a new plugin
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	return &Jwt{
		next:          next,
		requiredField: config.RequiredField,
	}, nil
}

func (jwtConfig *Jwt) ServeHTTP(rw http.ResponseWriter, request *http.Request) {
	authHeader := request.Header["Authorization"]
	if authHeader != nil {
		auth := authHeader[0]
		if strings.HasPrefix(auth, "Bearer ") {
			parts := strings.Split(auth[7:], ".")
			if len(parts) == 3 {
				body, err := base64.StdEncoding.DecodeString(parts[1])
				if err == nil {
					var payload map[string]json.RawMessage
					err := json.Unmarshal(body, &payload)
					if err == nil {
						if payload[jwtConfig.requiredField] == nil {
							logEvent := &LogEvent{
								Level: "warning",
								Msg:   fmt.Sprintf("JWT missing %s: sub=%s, IP=%s, URL=%s", jwtConfig.requiredField, payload["sub"], request.RemoteAddr, request.URL),
								Time:  time.Now(),
							}
							jsonLogEvent, _ := json.Marshal(&logEvent)
							fmt.Println(string(jsonLogEvent))
						}
					}
				}
			}
		}
	}
	jwtConfig.next.ServeHTTP(rw, request)
}
