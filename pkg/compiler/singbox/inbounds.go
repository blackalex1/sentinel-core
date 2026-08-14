package singbox

import (
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

	// 2. Server Inbounds (for Sentinel-Panel)
	for _, sb := range spec.ServerInbounds {
		serverIn := map[string]interface{}{
			"type":                       sb.Protocol,
			"tag":                        sb.Tag,
			"listen":                     sb.ListenAddress,
			"listen_port":                sb.Port,
			"sniff":                      true,
			"sniff_override_destination": true,
		}

		// Add server users / clients
		if len(sb.Clients) > 0 {
			users := make([]map[string]interface{}, 0, len(sb.Clients))
			for _, c := range sb.Clients {
				userMap := map[string]interface{}{
					"name": c.Email,
				}
				if c.UUID != "" {
					userMap["uuid"] = c.UUID
				}
				if c.Password != "" {
					userMap["password"] = c.Password
				}
				if c.Flow != "" {
					userMap["flow"] = c.Flow
				}
				users = append(users, userMap)
			}
			serverIn["users"] = users
		}

		// Server TLS / Reality
		if sb.Security == ast.SecurityReality {
			serverIn["tls"] = map[string]interface{}{
				"enabled":     true,
				"server_name": sb.SNI,
				"reality": map[string]interface{}{
					"enabled":     true,
					"private_key": sb.PrivateKey,
					"short_id":    sb.ShortIDs,
					"handshake": map[string]interface{}{
						"server":      sb.SNI,
						"server_port": 443,
					},
				},
			}
		} else if sb.Security == ast.SecurityTLS {
			serverIn["tls"] = map[string]interface{}{
				"enabled":          true,
				"server_name":      sb.SNI,
				"certificate_path": sb.CertPath,
				"key_path":         sb.KeyPath,
			}
		}

		// Hysteria 2 server parameters
		if sb.Protocol == ast.ProtoHysteria2 {
			if sb.ObfsPassword != "" {
				obfsType := "salamander"
				if sb.ObfsType != "" {
					obfsType = sb.ObfsType
				}
				serverIn["obfs"] = map[string]interface{}{
					"type":     obfsType,
					"password": sb.ObfsPassword,
				}
			}
			if sb.BandwidthUp != "" {
				serverIn["up_mbps"] = parseBandwidth(sb.BandwidthUp)
			}
			if sb.BandwidthDown != "" {
				serverIn["down_mbps"] = parseBandwidth(sb.BandwidthDown)
			}
		}

		inbounds = append(inbounds, serverIn)
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
