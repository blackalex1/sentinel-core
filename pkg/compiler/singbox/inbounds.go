package singbox

import (
	"strings"

	"github.com/blackalex1/sentinel-core/pkg/ast"
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

		// TUN Inbound (Wintun for Windows or VpnService for Android)
		if cb.Mode == ast.InboundModeDesktopTun || cb.Mode == ast.InboundModeMobileVpn {
			ifname := cb.TunInterfaceName
			if ifname == "" {
				ifname = "sentinel-tun"
			}
			stack := cb.TunStack
			if stack == "" {
				stack = "mixed"
			}
			mtu := cb.MTU
			if mtu <= 0 {
				mtu = 9000
			}

			endpoint := cb.EndpointIP
			if endpoint == "" {
				endpoint = "172.19.0.1/30"
			}

			tunIn := map[string]interface{}{
				"type":                     "tun",
				"tag":                      "tun-in",
				"interface_name":           ifname,
				"inet4_address":            endpoint,
				"auto_route":               true,
				"strict_route":             cb.StrictRoute,
				"stack":                    stack,
				"mtu":                      mtu,
				"sniff":                    true,
				"sniff_override_destination": false,
			}

			if len(cb.IncludePackages) > 0 {
				tunIn["include_package"] = cb.IncludePackages
			}
			if len(cb.ExcludePackages) > 0 {
				tunIn["exclude_package"] = cb.ExcludePackages
			}

			inbounds = append(inbounds, tunIn)
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
