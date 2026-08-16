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

	// 2. Network (tcp, udp, or tcp,udp)
	if sb.RawSettings != nil {
		if net, ok := sb.RawSettings["network"].(string); ok && net != "" {
			inbound["network"] = net
		}
	}

	// 3. Password (Server Key)
	serverPassword := ""
	if sb.RawSettings != nil {
		if pwd, ok := sb.RawSettings["password"].(string); ok && pwd != "" {
			serverPassword = pwd
		}
	}

	// 4. Users / Multi-user credentials
	if len(sb.Clients) > 0 {
		users := make([]map[string]interface{}, 0, len(sb.Clients))
		for _, c := range sb.Clients {
			userMap := map[string]interface{}{
				"name": c.Email,
			}
			pwd := c.Password
			if pwd == "" {
				pwd = c.UUID
			}
			if pwd == "" {
				pwd = c.ID
			}
			userMap["password"] = pwd
			users = append(users, userMap)
		}
		inbound["users"] = users

		if serverPassword == "" && !strings.HasPrefix(method, "2022-") {
			inbound["password"] = sb.Clients[0].Password
		}
	}

	if serverPassword != "" {
		inbound["password"] = serverPassword
	}

	// 5. Common options (multiplex, sniffing, timeouts)
	applyCommonInboundOptions(inbound, sb)

	return inbound
}
