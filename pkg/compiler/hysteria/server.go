package hysteria

import (
	"encoding/json"
	"fmt"
	"strings"
	"github.com/blackalex1/sentinel-core/pkg/ast"
)

// ServerCompiler compiles ServerInboundSpec into official Hysteria 2 server configuration.
type ServerCompiler struct{}

// NewServerCompiler creates a new Hysteria 2 server compiler.
func NewServerCompiler() *ServerCompiler {
	return &ServerCompiler{}
}

// CompileServer builds official Hysteria 2 server config (with Webhook Auth and local Xray routing forward)
func (sc *ServerCompiler) CompileServer(inbound ast.ServerInboundSpec, forwardToXraySocksPort int, logLevel ...string) (string, error) {
	listenAddr := fmt.Sprintf(":%d", inbound.Port)
	if inbound.PortHop != "" {
		parts := strings.Split(inbound.PortHop, "-")
		if len(parts) == 2 {
			var startP int
			fmt.Sscanf(parts[0], "%d", &startP)
			if startP == inbound.Port {
				listenAddr = fmt.Sprintf(":%s", inbound.PortHop)
			}
		}
	} else if inbound.ListenAddress != "" && inbound.ListenAddress != "0.0.0.0" && inbound.ListenAddress != "::" {
		listenAddr = fmt.Sprintf("%s:%d", inbound.ListenAddress, inbound.Port)
	}

	adminPort := inbound.AdminPort
	if adminPort <= 0 {
		adminPort = 10100 + (inbound.Port % 1000)
	}

	lvl := "info"
	if len(logLevel) > 0 && logLevel[0] != "" {
		lvl = logLevel[0]
	}

	configObj := map[string]interface{}{
		"listen": listenAddr,
		"trafficStats": map[string]interface{}{
			"listen": fmt.Sprintf("127.0.0.1:%d", adminPort),
		},
		"quic": map[string]interface{}{
			"initStreamReceiveWindow": 8388608,
			"maxStreamReceiveWindow":  8388608,
		},
		"log": map[string]interface{}{
			"level": lvl,
		},
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
	if inbound.AuthURL != "" {
		configObj["auth"] = map[string]interface{}{
			"type": "http",
			"http": map[string]interface{}{
				"url": inbound.AuthURL,
			},
		}
	} else {
		authSet := false
		for _, c := range inbound.Clients {
			if c.Email == "http_webhook" || c.ID == "webhook" || strings.HasPrefix(c.Password, "http://") || strings.HasPrefix(c.Password, "https://") {
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

	// Masquerade
	masqMap := map[string]interface{}{}
	switch inbound.MasqType {
	case "file":
		masqMap["type"] = "file"
		masqMap["file"] = map[string]interface{}{"dir": inbound.MasqValue}
	case "proxy":
		masqMap["type"] = "proxy"
		masqMap["proxy"] = map[string]interface{}{"url": inbound.MasqValue, "rewriteHost": true}
	case "string", "status", "drop":
		statusCode := 404
		if inbound.MasqStatusCode > 0 {
			statusCode = inbound.MasqStatusCode
		}
		content := "Not Found"
		if statusCode == 403 {
			content = "Forbidden"
		} else if statusCode == 444 {
			content = "Connection dropped"
		}
		masqMap["type"] = "string"
		masqMap["string"] = map[string]interface{}{
			"statusCode": statusCode,
			"content":    content,
		}
	default:
		if inbound.MasqValue != "" {
			masqMap["type"] = "proxy"
			masqMap["proxy"] = map[string]interface{}{"url": inbound.MasqValue, "rewriteHost": true}
		} else {
			masqMap["type"] = "string"
			masqMap["string"] = map[string]interface{}{
				"statusCode": 404,
				"content":    "Not Found",
			}
		}
	}
	configObj["masquerade"] = masqMap

	// Outbound: Forward decrypted traffic into local Xray for full routing!
	socksPort := forwardToXraySocksPort
	if inbound.SocksPort > 0 {
		socksPort = inbound.SocksPort
	}
	if socksPort > 0 {
		socksMap := map[string]interface{}{
			"addr": fmt.Sprintf("127.0.0.1:%d", socksPort),
		}
		if inbound.SocksUsername != "" {
			socksMap["username"] = inbound.SocksUsername
		}
		if inbound.SocksPassword != "" {
			socksMap["password"] = inbound.SocksPassword
		}
		configObj["outbounds"] = []map[string]interface{}{
			{
				"name":   "xray-routing",
				"type":   "socks5",
				"socks5": socksMap,
			},
		}
	}

	jsonBytes, err := json.MarshalIndent(configObj, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal hysteria2 server config: %w", err)
	}

	return string(jsonBytes), nil
}
