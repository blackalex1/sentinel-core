package singbox

import (
	"strings"

	"github.com/blackalex1/sentinel-core/pkg/ast"
)

// buildHysteria2Outbound compiles an ast.ServerProfile into a Sing-box Hysteria 2 outbound object.
func buildHysteria2Outbound(tag string, node *ast.ServerProfile) (map[string]interface{}, error) {
	authPass := node.Password
	if node.Username != "" && node.Password != "" {
		authPass = node.Username + ":" + node.Password
	} else if node.Password == "" && node.Username != "" {
		authPass = node.Username
	}

	out := map[string]interface{}{
		"type":     "hysteria2",
		"tag":      tag,
		"server":   node.Address,
		"password": authPass,
	}

	if node.PortHopping != "" {
		if strings.Contains(node.PortHopping, "-") || strings.Contains(node.PortHopping, ",") || strings.Contains(node.PortHopping, ":") {
			parts := strings.Split(node.PortHopping, ",")
			var ports []string
			for _, p := range parts {
				trimmed := strings.TrimSpace(p)
				if trimmed != "" {
					// Normalize 40000-50000 into 40000:50000
					normalized := strings.ReplaceAll(trimmed, "-", ":")
					ports = append(ports, normalized)
				}
			}
			if len(ports) > 0 {
				out["server_ports"] = ports
				hopInterval := "30s"
				if node.Extra != nil {
					if val, ok := node.Extra["hop_interval"].(string); ok && val != "" {
						hopInterval = val
					}
				}
				out["hop_interval"] = hopInterval
			}
		} else {
			var pInt int
			for _, c := range strings.TrimSpace(node.PortHopping) {
				if c >= '0' && c <= '9' {
					pInt = pInt*10 + int(c-'0')
				}
			}
			if pInt > 0 {
				out["server_port"] = pInt
			} else {
				out["server_port"] = node.Port
			}
		}
	} else {
		out["server_port"] = node.Port
	}

	if node.BandwidthUp != "" {
		out["up_mbps"] = parseBandwidth(node.BandwidthUp)
	}
	if node.BandwidthDown != "" {
		out["down_mbps"] = parseBandwidth(node.BandwidthDown)
	}

	if node.ObfsType != "" {
		out["obfs"] = map[string]interface{}{
			"type":     node.ObfsType,
			"password": node.ObfsPassword,
		}
	}

	// TLS Settings
	tlsMap := buildSingBoxTLS(node)
	if tlsMap != nil {
		out["tls"] = tlsMap
	} else {
		// Hysteria 2 always requires TLS enabled in sing-box
		tlsMap = map[string]interface{}{
			"enabled": true,
		}
		if node.SNI != "" {
			tlsMap["server_name"] = node.SNI
		}
		if node.Insecure {
			tlsMap["insecure"] = true
		}
		if node.PinnedPeerCertSha256 != "" {
			tlsMap["pinned_peer_certificate_sha256"] = node.PinnedPeerCertSha256
		}
		out["tls"] = tlsMap
	}

	return out, nil
}

// compileRawHysteria2Outbound compiles a raw settings/streamSettings dictionary into a Sing-box Hysteria 2 outbound object.
func compileRawHysteria2Outbound(tag string, sMap, tsMap map[string]interface{}) map[string]interface{} {
	hyOb := map[string]interface{}{
		"type": "hysteria2",
		"tag":  tag,
	}

	var server string
	var portRaw interface{}
	var password string

	if sMap != nil {
		if s, ok := sMap["server"].(string); ok && s != "" {
			server = s
		} else if a, ok := sMap["address"].(string); ok && a != "" {
			server = a
		} else if h, ok := sMap["host"].(string); ok && h != "" {
			server = h
		}

		if p, ok := sMap["port"]; ok {
			portRaw = p
		} else if p, ok := sMap["server_port"]; ok {
			portRaw = p
		} else if p, ok := sMap["port_hopping"]; ok {
			portRaw = p
		} else if p, ok := sMap["hop"]; ok {
			portRaw = p
		}

		if pwd, ok := sMap["password"].(string); ok && pwd != "" {
			password = pwd
		} else if auth, ok := sMap["auth"].(string); ok && auth != "" {
			password = auth
		} else if auth, ok := sMap["auth_str"].(string); ok && auth != "" {
			password = auth
		} else if u, ok := sMap["uuid"].(string); ok && u != "" {
			password = u
		}

		if vnextRaw, ok := sMap["vnext"].([]interface{}); ok && len(vnextRaw) > 0 {
			if firstVnext, ok := vnextRaw[0].(map[string]interface{}); ok {
				if server == "" {
					if addr, ok := firstVnext["address"].(string); ok {
						server = addr
					}
				}
				if portRaw == nil {
					if p, ok := firstVnext["port"]; ok {
						portRaw = p
					}
				}
				if password == "" {
					if usersRaw, ok := firstVnext["users"].([]interface{}); ok && len(usersRaw) > 0 {
						if firstUser, ok := usersRaw[0].(map[string]interface{}); ok {
							if pwd, ok := firstUser["password"].(string); ok {
								password = pwd
							} else if pwd, ok := firstUser["id"].(string); ok {
								password = pwd
							}
						}
					}
				}
			}
		}

		if serversRaw, ok := sMap["servers"].([]interface{}); ok && len(serversRaw) > 0 {
			if firstSrv, ok := serversRaw[0].(map[string]interface{}); ok {
				if server == "" {
					if addr, ok := firstSrv["address"].(string); ok {
						server = addr
					} else if srv, ok := firstSrv["server"].(string); ok {
						server = srv
					}
				}
				if portRaw == nil {
					if p, ok := firstSrv["port"]; ok {
						portRaw = p
					} else if p, ok := firstSrv["server_port"]; ok {
						portRaw = p
					}
				}
				if password == "" {
					if pwd, ok := firstSrv["password"].(string); ok {
						password = pwd
					} else if pwd, ok := firstSrv["auth"].(string); ok {
						password = pwd
					}
				}
			}
		}

		// Strict flat obfs format for Sing-box schema: {"type": "...", "password": "..."}
		var obfsType string
		var obfsPassword string
		if ot, ok := sMap["obfs_type"].(string); ok && ot != "" {
			obfsType = ot
		}
		if op, ok := sMap["obfs_password"].(string); ok && op != "" {
			obfsPassword = op
		}
		if obfsMapRaw, ok := sMap["obfs"].(map[string]interface{}); ok {
			if ot, ok := obfsMapRaw["type"].(string); ok && ot != "" {
				obfsType = ot
			}
			if op, ok := obfsMapRaw["password"].(string); ok && op != "" {
				obfsPassword = op
			}
			if sal, ok := obfsMapRaw["salamander"].(map[string]interface{}); ok {
				if op, ok := sal["password"].(string); ok && op != "" {
					obfsPassword = op
				}
			}
		}
		if obfsType != "" {
			obfsEntry := map[string]interface{}{
				"type": obfsType,
			}
			if obfsPassword != "" {
				obfsEntry["password"] = obfsPassword
			}
			hyOb["obfs"] = obfsEntry
		}

		if up, ok := sMap["up_mbps"]; ok {
			hyOb["up_mbps"] = up
		}
		if down, ok := sMap["down_mbps"]; ok {
			hyOb["down_mbps"] = down
		}
	}

	if tsMap != nil {
		if hySettings, ok := tsMap["hysteriaSettings"].(map[string]interface{}); ok {
			if portRaw == nil {
				if hop, ok := hySettings["hop"]; ok {
					portRaw = hop
				}
			}
			if password == "" {
				if pwd, ok := hySettings["auth"].(string); ok {
					password = pwd
				} else if pwd, ok := hySettings["password"].(string); ok {
					password = pwd
				}
			}
		}
	}

	hyOb["server"] = server
	if password != "" {
		hyOb["password"] = password
	}

	// Port or Port Hopping / Server Ports
	if portRaw != nil {
		switch v := portRaw.(type) {
		case float64:
			hyOb["server_port"] = int(v)
		case int:
			hyOb["server_port"] = v
		case string:
			vTrim := strings.TrimSpace(v)
			if strings.Contains(vTrim, "-") || strings.Contains(vTrim, ",") || strings.Contains(vTrim, ":") {
				parts := strings.Split(vTrim, ",")
				var ports []string
				for _, p := range parts {
					pClean := strings.TrimSpace(p)
					if pClean != "" {
						ports = append(ports, strings.ReplaceAll(pClean, "-", ":"))
					}
				}
				if len(ports) > 0 {
					hyOb["server_ports"] = ports
					hyOb["hop_interval"] = "30s"
				}
			} else {
				var pInt int
				for _, c := range vTrim {
					if c >= '0' && c <= '9' {
						pInt = pInt*10 + int(c-'0')
					}
				}
				if pInt > 0 {
					hyOb["server_port"] = pInt
				}
			}
		}
	}

	// TLS Settings
	tlsMap := map[string]interface{}{
		"enabled": true,
	}

	if tsMap != nil {
		if tlsSettings, ok := tsMap["tlsSettings"].(map[string]interface{}); ok {
			if sn, ok := tlsSettings["serverName"].(string); ok && sn != "" {
				tlsMap["server_name"] = sn
			}
			if allowInsecure, ok := tlsSettings["allowInsecure"].(bool); ok && allowInsecure {
				tlsMap["insecure"] = true
			}
			if pin, ok := tlsSettings["pinnedPeerCertSha256"].(string); ok && pin != "" {
				tlsMap["pinned_peer_certificate_sha256"] = pin
			} else if pin, ok := tlsSettings["pinned_peer_certificate_sha256"].(string); ok && pin != "" {
				tlsMap["pinned_peer_certificate_sha256"] = pin
			} else if pin, ok := tlsSettings["pinSHA256"].(string); ok && pin != "" {
				tlsMap["pinned_peer_certificate_sha256"] = pin
			}
			if alpnRaw, ok := tlsSettings["alpn"]; ok {
				if alpnList, ok := alpnRaw.([]interface{}); ok {
					var alpnStr []string
					for _, item := range alpnList {
						if s, ok := item.(string); ok {
							alpnStr = append(alpnStr, s)
						}
					}
					if len(alpnStr) > 0 {
						tlsMap["alpn"] = alpnStr
					}
				} else if alpnSlice, ok := alpnRaw.([]string); ok {
					tlsMap["alpn"] = alpnSlice
				}
			}
		}
		if sName, ok := tsMap["serverName"].(string); ok && sName != "" {
			tlsMap["server_name"] = sName
		}
	}

	if sMap != nil {
		if sn, ok := sMap["sni"].(string); ok && sn != "" {
			tlsMap["server_name"] = sn
		} else if sn, ok := sMap["server_name"].(string); ok && sn != "" {
			tlsMap["server_name"] = sn
		}
		if insecure, ok := sMap["insecure"].(bool); ok && insecure {
			tlsMap["insecure"] = true
		} else if allowInsecure, ok := sMap["allowInsecure"].(bool); ok && allowInsecure {
			tlsMap["insecure"] = true
		}
		if pin, ok := sMap["pinnedPeerCertSha256"].(string); ok && pin != "" {
			tlsMap["pinned_peer_certificate_sha256"] = pin
		} else if pin, ok := sMap["pinned_peer_certificate_sha256"].(string); ok && pin != "" {
			tlsMap["pinned_peer_certificate_sha256"] = pin
		} else if pin, ok := sMap["pinSHA256"].(string); ok && pin != "" {
			tlsMap["pinned_peer_certificate_sha256"] = pin
		}
	}

	if _, ok := tlsMap["server_name"]; !ok && server != "" {
		tlsMap["server_name"] = server
	}

	hyOb["tls"] = tlsMap
	return hyOb
}
