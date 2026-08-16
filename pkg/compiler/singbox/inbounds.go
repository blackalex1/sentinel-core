package singbox

import (
	"fmt"
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

	// 2. Server Inbounds (for Sentinel-Panel)
	for _, sb := range spec.ServerInbounds {
		listenAddr := sb.ListenAddress
		if listenAddr == "" {
			listenAddr = "::"
		}

		serverIn := map[string]interface{}{
			"type":        sb.Protocol,
			"tag":         sb.Tag,
			"listen":      listenAddr,
			"listen_port": sb.Port,
		}

		// Add server users / clients
		if len(sb.Clients) > 0 {
			users := make([]map[string]interface{}, 0, len(sb.Clients))
			for _, c := range sb.Clients {
				userMap := map[string]interface{}{
					"name": c.Email,
				}
				protoLower := strings.ToLower(sb.Protocol)
				if protoLower == "vless" || protoLower == "vmess" {
					uid := c.UUID
					if uid == "" {
						uid = c.ID
					}
					if uid == "" {
						uid = c.Password
					}
					userMap["uuid"] = uid
					if c.Flow != "" && protoLower == "vless" {
						userMap["flow"] = c.Flow
					}
				} else {
					pwd := c.Password
					if pwd == "" {
						pwd = c.UUID
					}
					if pwd == "" {
						pwd = c.ID
					}
					userMap["password"] = pwd
				}
				users = append(users, userMap)
			}
			serverIn["users"] = users
		}

		// Server TLS / Reality
		sec := sb.Security
		if sec == "" && sb.StreamSettings != nil {
			if s, ok := sb.StreamSettings["security"].(string); ok {
				sec = s
			}
		}

		if sec == ast.SecurityReality || sec == "reality" {
			privateKey := sb.PrivateKey
			serverName := sb.SNI
			dest := "example.com:443"
			shortIDs := sb.ShortIDs
			if sb.StreamSettings != nil {
				if rs, ok := sb.StreamSettings["realitySettings"].(map[string]interface{}); ok {
					if pk, ok := rs["privateKey"].(string); ok && pk != "" {
						privateKey = pk
					}
					if d, ok := rs["dest"].(string); ok && d != "" {
						dest = d
					}
					if sns, ok := rs["serverNames"].([]interface{}); ok && len(sns) > 0 {
						if sn, ok := sns[0].(string); ok && sn != "" {
							serverName = sn
						}
					}
					if sids, ok := rs["shortIds"].([]interface{}); ok {
						for _, sid := range sids {
							if s, ok := sid.(string); ok {
								shortIDs = append(shortIDs, s)
							}
						}
					}
				}
			}
			destHost := serverName
			destPort := 443
			if strings.Contains(dest, ":") {
				parts := strings.Split(dest, ":")
				destHost = parts[0]
				fmt.Sscanf(parts[1], "%d", &destPort)
			}
			serverIn["tls"] = map[string]interface{}{
				"enabled":     true,
				"server_name": serverName,
				"reality": map[string]interface{}{
					"enabled":     true,
					"private_key": privateKey,
					"short_id":    shortIDs,
					"handshake": map[string]interface{}{
						"server":      destHost,
						"server_port": destPort,
					},
				},
			}
		} else if sec == ast.SecurityTLS || sec == "tls" {
			certPath := sb.CertPath
			keyPath := sb.KeyPath
			serverName := sb.SNI
			if sb.StreamSettings != nil {
				if ts, ok := sb.StreamSettings["tlsSettings"].(map[string]interface{}); ok {
					if sn, ok := ts["serverName"].(string); ok && sn != "" {
						serverName = sn
					}
					if cp, ok := ts["certificateFile"].(string); ok && cp != "" {
						certPath = cp
					}
					if kp, ok := ts["keyFile"].(string); ok && kp != "" {
						keyPath = kp
					}
				}
			}
			serverIn["tls"] = map[string]interface{}{
				"enabled":          true,
				"server_name":      serverName,
				"certificate_path": certPath,
				"key_path":         keyPath,
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
