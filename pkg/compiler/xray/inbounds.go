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
		if sb.RawSettings != nil {
			for k, v := range sb.RawSettings {
				settings[k] = v
			}
		}

		switch proto {
		case "vless":
			if len(sb.Clients) > 0 {
				clients := make([]map[string]interface{}, 0, len(sb.Clients))
				for _, c := range sb.Clients {
					uid := c.UUID
					if uid == "" {
						uid = c.ID
					}
					cl := map[string]interface{}{
						"id":    uid,
						"email": c.Email,
					}
					flow := c.Flow
					if flow == "" && sb.RawSettings != nil {
						if f, ok := sb.RawSettings["flow"].(string); ok && f != "" {
							flow = f
						}
					}
					// Flow is only supported for TCP + (Reality or TLS)
					if sb.Transport != "" && sb.Transport != "tcp" {
						flow = ""
					}
					secVal := sb.Security
					if secVal == "" && sb.StreamSettings != nil {
						if s, ok := sb.StreamSettings["security"].(string); ok {
							secVal = s
						}
					}
					if secVal != "reality" && secVal != "tls" {
						flow = ""
					}
					if flow != "" && flow != "xtls-rprx-vision" && flow != "xtls-rprx-vision-udp443" {
						flow = ""
					}
					if flow != "" {
						cl["flow"] = flow
					}
					clients = append(clients, cl)
				}
				settings["clients"] = clients
			} else if _, ok := settings["clients"]; !ok {
				settings["clients"] = []map[string]interface{}{}
			}
			// VLESS Encryption (vlessenc) vs standard VLESS
			if dec, ok := settings["decryption"].(string); ok && strings.HasPrefix(dec, "mlkem768x25519plus.") {
				settings["decryption"] = dec
			} else {
				settings["decryption"] = "none"
			}
			delete(settings, "encryption")

			sec := sb.Security
			if sec == "" && sb.StreamSettings != nil {
				if s, ok := sb.StreamSettings["security"].(string); ok {
					sec = s
				}
			}

			if sec != "reality" {
				if len(sb.Fallbacks) > 0 {
					settings["fallbacks"] = sb.Fallbacks
				} else if fb, ok := sb.RawSettings["fallbacks"]; ok {
					settings["fallbacks"] = fb
				}
			} else {
				delete(settings, "fallbacks")
			}

		case "trojan":
			if len(sb.Clients) > 0 {
				clients := make([]map[string]interface{}, 0, len(sb.Clients))
				for _, c := range sb.Clients {
					clients = append(clients, map[string]interface{}{
						"password": c.Password,
						"email":    c.Email,
					})
				}
				settings["clients"] = clients
			}

		case "vmess":
			if len(sb.Clients) > 0 {
				clients := make([]map[string]interface{}, 0, len(sb.Clients))
				for _, c := range sb.Clients {
					clients = append(clients, map[string]interface{}{
						"id":    c.UUID,
						"email": c.Email,
					})
				}
				settings["clients"] = clients
			}

		case "shadowsocks":
			if len(sb.Clients) > 0 {
				settings["password"] = sb.Clients[0].Password
			}
			if _, ok := settings["method"]; !ok {
				settings["method"] = "2022-blake3-aes-128-gcm"
			}
			if net, ok := settings["network"].(string); !ok || net == "" {
				settings["network"] = "tcp,udp"
			}

		case "socks":
			if _, ok := settings["udp"]; !ok {
				settings["udp"] = true
			}
			if _, ok := settings["auth"]; !ok {
				settings["auth"] = "noauth"
			}
		}

		sniffing := map[string]interface{}{
			"enabled":      true,
			"destOverride": []string{"http", "tls", "quic", "fakedns"},
			"routeOnly":    false,
		}
		if sb.Sniffing != nil && len(sb.Sniffing) > 0 {
			sniffing = sb.Sniffing
		}

		serverIn := map[string]interface{}{
			"tag":      sb.Tag,
			"port":     sb.Port,
			"listen":   listenAddr,
			"protocol": proto,
			"settings": settings,
			"sniffing": sniffing,
		}

		// StreamSettings for TLS / Reality
		streamSettings := map[string]interface{}{
			"network": "tcp",
		}
		if sb.StreamSettings != nil && len(sb.StreamSettings) > 0 {
			for k, v := range sb.StreamSettings {
				streamSettings[k] = v
			}
		}

		if sb.Security == ast.SecurityReality || streamSettings["security"] == "reality" {
			streamSettings["security"] = "reality"
			if _, ok := streamSettings["realitySettings"]; !ok {
				streamSettings["realitySettings"] = map[string]interface{}{
					"show":        false,
					"dest":        sb.SNI + ":443",
					"xver":        0,
					"serverNames": []string{sb.SNI},
					"privateKey":  sb.PrivateKey,
					"shortIds":    sb.ShortIDs,
				}
			}
		} else if sb.Security == ast.SecurityTLS || streamSettings["security"] == "tls" {
			streamSettings["security"] = "tls"
			if _, ok := streamSettings["tlsSettings"]; !ok {
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
