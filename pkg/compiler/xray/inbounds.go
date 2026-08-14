package xray

import (
	"strings"
	"github.com/blackalex1/sentinel-core/pkg/ast"
)

// BuildXrayInbounds creates inbounds for Xray-core
func BuildXrayInbounds(spec *ast.ConfigSpec) []map[string]interface{} {
	inbounds := make([]map[string]interface{}, 0)

	// 1. Client Inbounds
	if spec.ClientInbound != nil {
		cb := spec.ClientInbound
		listenAddr := cb.ListenAddress
		if listenAddr == "" {
			listenAddr = "127.0.0.1"
		}

		// SOCKS Inbound
		if cb.SocksPort > 0 {
			socksIn := map[string]interface{}{
				"tag":      "socks-in",
				"port":     cb.SocksPort,
				"listen":   listenAddr,
				"protocol": "socks",
				"settings": map[string]interface{}{
					"udp":  true,
					"auth": "noauth",
				},
				"sniffing": map[string]interface{}{
					"enabled":      true,
					"destOverride": []string{"http", "tls", "quic", "fakedns"},
					"routeOnly":    false,
				},
			}

			if cb.AuthEnabled && cb.AuthUsername != "" {
				socksIn["settings"] = map[string]interface{}{
					"udp":  true,
					"auth": "password",
					"accounts": []map[string]interface{}{
						{
							"user": cb.AuthUsername,
							"pass": cb.AuthPassword,
						},
					},
				}
			}

			inbounds = append(inbounds, socksIn)
		}

		// HTTP Inbound
		if cb.HTTPPort > 0 {
			inbounds = append(inbounds, map[string]interface{}{
				"tag":      "http-in",
				"port":     cb.HTTPPort,
				"listen":   listenAddr,
				"protocol": "http",
				"settings": map[string]interface{}{
					"allowTransparent": false,
				},
				"sniffing": map[string]interface{}{
					"enabled":      true,
					"destOverride": []string{"http", "tls", "quic", "fakedns"},
				},
			})
		}
	}

	// 2. Server Inbounds (for Sentinel-Panel)
	for _, sb := range spec.ServerInbounds {
		proto := strings.ToLower(sb.Protocol)
		if proto == "" {
			proto = "vless"
		}

		listenAddr := sb.ListenAddress
		if listenAddr == "" {
			listenAddr = "0.0.0.0"
		}

		settings := map[string]interface{}{}

		switch proto {
		case "vless":
			clients := make([]map[string]interface{}, 0, len(sb.Clients))
			for _, c := range sb.Clients {
				cl := map[string]interface{}{
					"id":    c.UUID,
					"email": c.Email,
				}
				if c.Flow != "" {
					cl["flow"] = c.Flow
				}
				clients = append(clients, cl)
			}
			settings["clients"] = clients
			settings["decryption"] = "none"

		case "trojan":
			clients := make([]map[string]interface{}, 0, len(sb.Clients))
			for _, c := range sb.Clients {
				clients = append(clients, map[string]interface{}{
					"password": c.Password,
					"email":    c.Email,
				})
			}
			settings["clients"] = clients

		case "vmess":
			clients := make([]map[string]interface{}, 0, len(sb.Clients))
			for _, c := range sb.Clients {
				clients = append(clients, map[string]interface{}{
					"id":    c.UUID,
					"email": c.Email,
				})
			}
			settings["clients"] = clients

		case "shadowsocks":
			if len(sb.Clients) > 0 {
				settings["password"] = sb.Clients[0].Password
			}
			settings["method"] = "2022-blake3-aes-128-gcm"

		case "socks":
			settings["udp"] = true
			settings["auth"] = "noauth"
		}

		serverIn := map[string]interface{}{
			"tag":      sb.Tag,
			"port":     sb.Port,
			"listen":   listenAddr,
			"protocol": proto,
			"settings": settings,
			"sniffing": map[string]interface{}{
				"enabled":      true,
				"destOverride": []string{"http", "tls", "quic", "fakedns"},
				"routeOnly":    false,
			},
		}

		// StreamSettings for TLS / Reality
		streamSettings := map[string]interface{}{
			"network": "tcp",
		}

		if sb.Security == ast.SecurityReality {
			streamSettings["security"] = "reality"
			streamSettings["realitySettings"] = map[string]interface{}{
				"show":        false,
				"dest":        sb.SNI + ":443",
				"xver":        0,
				"serverNames": []string{sb.SNI},
				"privateKey":  sb.PrivateKey,
				"shortIds":    sb.ShortIDs,
			}
		} else if sb.Security == ast.SecurityTLS {
			streamSettings["security"] = "tls"
			streamSettings["tlsSettings"] = map[string]interface{}{
				"serverName": sb.SNI,
				"certificates": []map[string]interface{}{
					{
						"certificateFile": sb.CertPath,
						"keyFile":         sb.KeyPath,
					},
				},
			}
		}

		serverIn["streamSettings"] = streamSettings
		inbounds = append(inbounds, serverIn)
	}

	if len(inbounds) == 0 {
		inbounds = append(inbounds, map[string]interface{}{
			"tag":      "socks-in",
			"port":     10808,
			"listen":   "127.0.0.1",
			"protocol": "socks",
			"settings": map[string]interface{}{
				"udp":  true,
				"auth": "noauth",
			},
			"sniffing": map[string]interface{}{
				"enabled":      true,
				"destOverride": []string{"http", "tls", "quic", "fakedns"},
			},
		})
	}

	return inbounds
}
