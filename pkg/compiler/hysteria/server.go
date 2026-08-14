package hysteria

import (
	"encoding/json"
	"fmt"
	"github.com/blackalex1/sentinel-core/pkg/ast"
)

// ServerCompiler compiles ServerInboundSpec into official Hysteria 2 server configuration.
type ServerCompiler struct{}

// NewServerCompiler creates a new Hysteria 2 server compiler.
func NewServerCompiler() *ServerCompiler {
	return &ServerCompiler{}
}

// CompileServer builds official Hysteria 2 server config (with Webhook Auth and local Xray routing forward)
func (sc *ServerCompiler) CompileServer(inbound ast.ServerInboundSpec, forwardToXraySocksPort int) (string, error) {
	listenAddr := fmt.Sprintf(":%d", inbound.Port)
	if inbound.ListenAddress != "" && inbound.ListenAddress != "0.0.0.0" && inbound.ListenAddress != "::" {
		listenAddr = fmt.Sprintf("%s:%d", inbound.ListenAddress, inbound.Port)
	}

	configObj := map[string]interface{}{
		"listen": listenAddr,
	}

	// TLS Settings
	tlsMap := map[string]interface{}{}
	if inbound.CertPath != "" && inbound.KeyPath != "" {
		tlsMap["cert"] = inbound.CertPath
		tlsMap["key"] = inbound.KeyPath
	}
	if inbound.SNI != "" {
		tlsMap["sni"] = inbound.SNI
	}
	if len(tlsMap) > 0 {
		configObj["tls"] = tlsMap
	}

	// Authentication (HTTP Webhook Auth or Userpass)
	// If SNI or AuthURL specified in Extra or if Client password starts with http
	authSet := false
	for _, c := range inbound.Clients {
		if c.Email == "http_webhook" || c.ID == "webhook" {
			configObj["auth"] = map[string]interface{}{
				"type": "http",
				"http": map[string]interface{}{
					"url": c.Password,
				},
			}
			authSet = true
			break
		}
	}

	if !authSet {
		if len(inbound.Clients) > 0 {
			userPassMap := make(map[string]string)
			for _, c := range inbound.Clients {
				user := c.Email
				if user == "" {
					user = c.UUID
				}
				if user == "" {
					user = "user"
				}
				userPassMap[user] = c.Password
			}
			configObj["auth"] = map[string]interface{}{
				"type":     "userpass",
				"userpass": userPassMap,
			}
		} else {
			configObj["auth"] = map[string]interface{}{
				"type": "password",
				"password": map[string]interface{}{
					"value": "default-secret",
				},
			}
		}
	}

	// Obfuscation (Salamander)
	if inbound.ObfsPassword != "" {
		obfsType := "salamander"
		if inbound.ObfsType != "" {
			obfsType = inbound.ObfsType
		}
		configObj["obfs"] = map[string]interface{}{
			"type": obfsType,
			"salamander": map[string]interface{}{
				"password": inbound.ObfsPassword,
			},
		}
	}

	// Bandwidth
	bandwidthMap := make(map[string]interface{})
	if inbound.BandwidthUp != "" {
		bandwidthMap["up"] = inbound.BandwidthUp
	}
	if inbound.BandwidthDown != "" {
		bandwidthMap["down"] = inbound.BandwidthDown
	}
	if len(bandwidthMap) > 0 {
		configObj["bandwidth"] = bandwidthMap
	}

	// Outbound: Forward decrypted traffic into local Xray for full routing!
	if forwardToXraySocksPort > 0 {
		configObj["outbounds"] = []map[string]interface{}{
			{
				"name": "to-xray-routing",
				"type": "socks5",
				"socks5": map[string]interface{}{
					"addr": fmt.Sprintf("127.0.0.1:%d", forwardToXraySocksPort),
				},
			},
		}
	}

	jsonBytes, err := json.MarshalIndent(configObj, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal hysteria2 server config: %w", err)
	}

	return string(jsonBytes), nil
}
