package singbox

import (
	"strings"

	"github.com/blackalex1/sentinel-core/pkg/ast"
)

// buildShadowsocksInbound compiles a complete Shadowsocks inbound for Sing-box
func buildShadowsocksInbound(sb *ast.ServerInboundSpec) map[string]interface{} {
	listenAddr := sb.ListenAddress
	if listenAddr == "" {
		listenAddr = "::"
	}

	inbound := map[string]interface{}{
		"type":        "shadowsocks",
		"tag":         sb.Tag,
		"listen":      listenAddr,
		"listen_port": sb.Port,
	}

	// 1. Method / Cipher
	method := ""
	if sb.RawSettings != nil {
		if m, ok := sb.RawSettings["method"].(string); ok && m != "" {
			method = m
		} else if c, ok := sb.RawSettings["cipher"].(string); ok && c != "" {
			method = c
		}
	}
	if method == "" && sb.Security != "" && sb.Security != "none" {
		method = sb.Security
	}
	if method == "" {
		method = "2022-blake3-aes-128-gcm"
	}
	inbound["method"] = method

	// 2. Network (tcp, udp, or omitted for both)
	if sb.RawSettings != nil {
		if net, ok := sb.RawSettings["network"].(string); ok && net != "" {
			if parsedNet := parseInboundNetwork(net); parsedNet != "" {
				inbound["network"] = parsedNet
			}
		}
	}

	// 3. Password / Users
	serverPassword := ""
	if sb.RawSettings != nil {
		if pwd, ok := sb.RawSettings["password"].(string); ok && pwd != "" {
			serverPassword = pwd
		}
	}

	is2022 := strings.HasPrefix(method, "2022-")

	if is2022 {
		// Shadowsocks 2022 multi-user mode
		if serverPassword != "" {
			inbound["password"] = serverPassword
		}
		if len(sb.Clients) > 0 {
			users := make([]map[string]interface{}, 0, len(sb.Clients))
			for _, c := range sb.Clients {
				pwd := c.Password
				if pwd == "" {
					pwd = c.UUID
				}
				if pwd == "" {
					pwd = c.ID
				}
				users = append(users, map[string]interface{}{
					"name":     c.Email,
					"password": pwd,
				})
			}
			inbound["users"] = users
		} else if sb.RawSettings != nil {
			if rawClients, ok := sb.RawSettings["clients"].([]interface{}); ok && len(rawClients) > 0 {
				users := make([]map[string]interface{}, 0, len(rawClients))
				for _, rc := range rawClients {
					if rcMap, ok := rc.(map[string]interface{}); ok {
						pwd, _ := rcMap["password"].(string)
						if pwd == "" {
							pwd, _ = rcMap["id"].(string)
						}
						if pwd == "" {
							pwd, _ = rcMap["uuid"].(string)
						}
						email, _ := rcMap["email"].(string)
						users = append(users, map[string]interface{}{
							"name":     email,
							"password": pwd,
						})
					}
				}
				inbound["users"] = users
			}
		}
	} else {
		// Legacy AEAD (single password per port)
		if serverPassword == "" && len(sb.Clients) > 0 {
			serverPassword = sb.Clients[0].Password
			if serverPassword == "" {
				serverPassword = sb.Clients[0].UUID
			}
			if serverPassword == "" {
				serverPassword = sb.Clients[0].ID
			}
		}
		if serverPassword == "" && sb.RawSettings != nil {
			if rawClients, ok := sb.RawSettings["clients"].([]interface{}); ok && len(rawClients) > 0 {
				if rcMap, ok := rawClients[0].(map[string]interface{}); ok {
					pwd, _ := rcMap["password"].(string)
					if pwd == "" {
						pwd, _ = rcMap["id"].(string)
					}
					if pwd == "" {
						pwd, _ = rcMap["uuid"].(string)
					}
					serverPassword = pwd
				}
			}
		}
		if serverPassword != "" {
			inbound["password"] = serverPassword
		}
	}

	// 5. Common options (multiplex, sniffing, timeouts)
	applyCommonInboundOptions(inbound, sb)

	return inbound
}
