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
	return sc.CompileServerWithDNS(inbound, forwardToXraySocksPort, nil, logLevel...)
}

// CompileServerWithDNS builds official Hysteria 2 server config with custom DNS resolver
func (sc *ServerCompiler) CompileServerWithDNS(inbound ast.ServerInboundSpec, forwardToXraySocksPort int, dns *ast.DNSSpec, logLevel ...string) (string, error) {
	listenAddr := fmt.Sprintf(":%d", inbound.Port)
	if inbound.PortHop != "" && strings.Contains(inbound.PortHop, "-") {
		listenAddr = fmt.Sprintf(":%s", strings.TrimPrefix(inbound.PortHop, ":"))
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
		"resolver": BuildHysteriaResolver(dns),
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
		httpAuth := map[string]interface{}{
			"url": inbound.AuthURL,
		}
		if inbound.Insecure || strings.Contains(inbound.AuthURL, "127.0.0.1") || strings.Contains(inbound.AuthURL, "localhost") {
			httpAuth["insecure"] = true
		}
		configObj["auth"] = map[string]interface{}{
			"type": "http",
			"http": httpAuth,
		}
	} else {
		authSet := false
		for _, c := range inbound.Clients {
			if c.Email == "http_webhook" || c.ID == "webhook" || strings.HasPrefix(c.Password, "http://") || strings.HasPrefix(c.Password, "https://") {
				httpAuth := map[string]interface{}{
					"url": c.Password,
				}
				if inbound.Insecure || strings.Contains(c.Password, "127.0.0.1") || strings.Contains(c.Password, "localhost") {
					httpAuth["insecure"] = true
				}
				configObj["auth"] = map[string]interface{}{
					"type": "http",
					"http": httpAuth,
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
					"type":     "password",
					"password": "default-secret",
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

	// Masquerade - ONLY included if explicitly configured by the user
	if inbound.MasqType != "" && inbound.MasqType != "none" {
		masqMap := map[string]interface{}{}
		switch inbound.MasqType {
		case "file":
			if inbound.MasqValue != "" {
				masqMap["type"] = "file"
				masqMap["file"] = map[string]interface{}{"dir": inbound.MasqValue}
			}
		case "proxy":
			if inbound.MasqValue != "" {
				masqMap["type"] = "proxy"
				masqMap["proxy"] = map[string]interface{}{"url": normalizeMasqURL(inbound.MasqValue), "rewriteHost": true}
			}
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
			} else if inbound.MasqValue != "" {
				content = inbound.MasqValue
			}
			masqMap["type"] = "string"
			masqMap["string"] = map[string]interface{}{
				"statusCode": statusCode,
				"content":    content,
			}
		}
		if len(masqMap) > 0 {
			configObj["masquerade"] = masqMap
		}
	}

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

func normalizeMasqURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
		return "https://" + raw
	}
	return raw
}



// BuildHysteriaResolver creates a native Hysteria 2 resolver block for encrypted DoH
func BuildHysteriaResolver(dns *ast.DNSSpec) map[string]interface{} {
	targetURL := "https://8.8.8.8/dns-query"
	if dns != nil {
		if dns.DirectServer != "" {
			targetURL = dns.DirectServer
		} else if dns.RemoteServer != "" {
			targetURL = dns.RemoteServer
		} else if len(dns.Servers) > 0 {
			targetURL = dns.Servers[0]
		}
	}

	if strings.HasPrefix(targetURL, "https://") {
		trimmed := strings.TrimPrefix(targetURL, "https://")
		parts := strings.SplitN(trimmed, "/", 2)
		hostPart := parts[0]
		addr := hostPart
		sni := ""

		knownIPs := map[string]string{
			"dns.google":                "8.8.8.8",
			"cloudflare-dns.com":        "1.1.1.1",
			"one.one.one.one":           "1.1.1.1",
			"dns.adguard-dns.com":       "94.140.14.14",
			"dns.yandex.ru":             "77.88.8.8",
			"common.dot.dns.yandex.net":  "77.88.8.8",
		}

		if ip, ok := knownIPs[hostPart]; ok {
			addr = ip + ":443"
			sni = hostPart
		} else if hostPart == "8.8.8.8" || hostPart == "8.8.4.4" {
			addr = hostPart + ":443"
			sni = "dns.google"
		} else if hostPart == "1.1.1.1" || hostPart == "1.0.0.1" {
			addr = hostPart + ":443"
			sni = "cloudflare-dns.com"
		} else if hostPart == "94.140.14.14" || hostPart == "94.140.15.15" {
			addr = hostPart + ":443"
			sni = "dns.adguard-dns.com"
		} else if hostPart == "77.88.8.8" || hostPart == "77.88.8.1" {
			addr = hostPart + ":443"
			sni = "dns.yandex.ru"
		} else if !strings.Contains(hostPart, ":") {
			addr = hostPart + ":443"
		}

		httpsObj := map[string]interface{}{
			"addr":    addr,
			"timeout": "4s",
		}
		if sni != "" {
			httpsObj["sni"] = sni
		}
		return map[string]interface{}{
			"type":  "https",
			"https": httpsObj,
		}
	} else if strings.HasPrefix(targetURL, "tcp://") {
		addr := strings.TrimPrefix(targetURL, "tcp://")
		if !strings.Contains(addr, ":") {
			addr += ":53"
		}
		return map[string]interface{}{
			"type": "tcp",
			"tcp": map[string]interface{}{
				"addr":    addr,
				"timeout": "4s",
			},
		}
	} else {
		addr := strings.TrimPrefix(targetURL, "udp://")
		if !strings.Contains(addr, ":") {
			addr += ":53"
		}
		return map[string]interface{}{
			"type": "udp",
			"udp": map[string]interface{}{
				"addr":    addr,
				"timeout": "4s",
			},
		}
	}
}
