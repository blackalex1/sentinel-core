package singbox

import (
	"strings"

	"github.com/blackalex1/sentinel-core/pkg/ast"
	"github.com/blackalex1/sentinel-core/pkg/platform/android"
	"github.com/blackalex1/sentinel-core/pkg/platform/desktop"
)

// BuildSingBoxInbounds generates inbounds based on the spec
func BuildSingBoxInbounds(spec *ast.ConfigSpec) []map[string]interface{} {
	inbounds := make([]map[string]interface{}, 0)

	// 1. Client Inbounds (TUN / SOCKS / HTTP)
	if spec.ClientInbound != nil {
		cb := spec.ClientInbound
		listenAddr := cb.ListenAddress
		if listenAddr == "" {
			listenAddr = "127.0.0.1"
		}

		// SOCKS5 Inbound
		if cb.SocksPort > 0 {
			socksIn := map[string]interface{}{
				"type":        "socks",
				"tag":         "socks-in",
				"listen":      listenAddr,
				"listen_port": cb.SocksPort,
			}
			if cb.AuthEnabled && cb.AuthUsername != "" {
				socksIn["users"] = []map[string]interface{}{
					{
						"username": cb.AuthUsername,
						"password": cb.AuthPassword,
					},
				}
			}
			inbounds = append(inbounds, socksIn)
		}

		// HTTP Inbound
		if cb.HTTPPort > 0 {
			inbounds = append(inbounds, map[string]interface{}{
				"type":        "http",
				"tag":         "http-in",
				"listen":      listenAddr,
				"listen_port": cb.HTTPPort,
			})
		}

		// TUN Inbound (Strictly delegated to corresponding platform package)
		if cb.Mode == ast.InboundModeMobileVpn {
			inbounds = append(inbounds, android.BuildSingBoxAndroidTunInbound(cb))
		} else if cb.Mode == ast.InboundModeDesktopTun {
			inbounds = append(inbounds, desktop.BuildSingBoxDesktopTunInbound(cb))
		}

		// LAN / Hotspot Sharing Inbounds (HTTP & SOCKS)
		if cb.LanSharingEnabled {
			lanAddr := cb.LanListenAddress
			if lanAddr == "" {
				lanAddr = "0.0.0.0"
			}

			if cb.LanHTTPPort > 0 {
				httpIn := map[string]interface{}{
					"type":        "http",
					"tag":         "lan-http-in",
					"listen":      lanAddr,
					"listen_port": cb.LanHTTPPort,
				}
				if cb.LanAuthEnabled && cb.LanUsername != "" {
					httpIn["users"] = []map[string]interface{}{
						{
							"username": cb.LanUsername,
							"password": cb.LanPassword,
						},
					}
				}
				inbounds = append(inbounds, httpIn)
			}

			if cb.LanSocksPort > 0 {
				socksIn := map[string]interface{}{
					"type":        "socks",
					"tag":         "lan-socks-in",
					"listen":      lanAddr,
					"listen_port": cb.LanSocksPort,
				}
				if cb.LanAuthEnabled && cb.LanUsername != "" {
					socksIn["users"] = []map[string]interface{}{
						{
							"username": cb.LanUsername,
							"password": cb.LanPassword,
						},
					}
				}
				inbounds = append(inbounds, socksIn)
			}
		}
	}

	// 2. Server Inbounds (Modular per-protocol builders)
	for _, sb := range spec.ServerInbounds {
		protoLower := strings.ToLower(sb.Protocol)
		var serverIn map[string]interface{}

		switch protoLower {
		case "shadowsocks":
			serverIn = buildShadowsocksInbound(&sb)
		case "vless":
			serverIn = buildVLESSInbound(&sb)
		case "vmess":
			serverIn = buildVMessInbound(&sb)
		case "hysteria2", "hysteria":
			serverIn = buildHysteria2Inbound(&sb)
		case "trojan":
			serverIn = buildTrojanInbound(&sb)
		case "tuic":
			serverIn = buildTUICInbound(&sb)
		case "http":
			serverIn = buildHTTPInbound(&sb)
		case "socks":
			serverIn = buildSocksInbound(&sb)
		default:
			// Generic fallback
			listenAddr := sb.ListenAddress
			if listenAddr == "" {
				listenAddr = "::"
			}
			serverIn = map[string]interface{}{
				"type":        sb.Protocol,
				"tag":         sb.Tag,
				"listen":      listenAddr,
				"listen_port": sb.Port,
			}
			if tlsMap := buildInboundTLS(&sb); tlsMap != nil {
				serverIn["tls"] = tlsMap
			}
			applyCommonInboundOptions(serverIn, &sb)
		}

		if serverIn != nil {
			inbounds = append(inbounds, serverIn)
		}
	}

	if len(inbounds) == 0 {
		// Fallback default inbound
		inbounds = append(inbounds, map[string]interface{}{
			"type":        "socks",
			"tag":         "socks-in",
			"listen":      "127.0.0.1",
			"listen_port": 10808,
		})
	}

	return inbounds
}
