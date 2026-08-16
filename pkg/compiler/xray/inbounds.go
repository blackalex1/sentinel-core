package xray

import (
	"strings"

	"github.com/blackalex1/sentinel-core/pkg/ast"
)

// BuildXrayInbounds creates inbounds for Xray-core via modular per-protocol builders.
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

	// 2. Server Inbounds (Modular per-protocol builders)
	for _, sb := range spec.ServerInbounds {
		proto := strings.ToLower(sb.Protocol)
		var serverIn map[string]interface{}

		switch proto {
		case "vless", "":
			serverIn = buildXrayVLESSInbound(&sb)
		case "shadowsocks":
			serverIn = buildXrayShadowsocksInbound(&sb)
		case "trojan":
			serverIn = buildXrayTrojanInbound(&sb)
		case "vmess":
			serverIn = buildXrayVMessInbound(&sb)
		case "socks":
			serverIn = buildXraySOCKSInbound(&sb)
		case "http":
			serverIn = buildXrayHTTPInbound(&sb)
		case "hysteria2", "hysteria":
			serverIn = buildXrayHysteria2Inbound(&sb)
		default:
			serverIn = buildXrayVLESSInbound(&sb)
		}

		if serverIn != nil {
			inbounds = append(inbounds, serverIn)
		}
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
