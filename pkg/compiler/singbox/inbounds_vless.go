package singbox

import (
	"github.com/blackalex1/sentinel-core/pkg/ast"
)

// buildVLESSInbound compiles a complete VLESS inbound for Sing-box
func buildVLESSInbound(sb *ast.ServerInboundSpec) map[string]interface{} {
	listenAddr := sb.ListenAddress
	if listenAddr == "" {
		listenAddr = "::"
	}

	inbound := map[string]interface{}{
		"type":        "vless",
		"tag":         sb.Tag,
		"listen":      listenAddr,
		"listen_port": sb.Port,
	}

	// 1. Users
	if len(sb.Clients) > 0 {
		users := make([]map[string]interface{}, 0, len(sb.Clients))
		for _, c := range sb.Clients {
			uid := c.UUID
			if uid == "" {
				uid = c.ID
			}
			if uid == "" {
				uid = c.Password
			}
			userMap := map[string]interface{}{
				"name": c.Email,
				"uuid": uid,
			}
			if c.Flow != "" {
				userMap["flow"] = c.Flow
			}
			users = append(users, userMap)
		}
		inbound["users"] = users
	}

	// 2. TLS / Reality
	if tlsMap := buildInboundTLS(sb); tlsMap != nil {
		inbound["tls"] = tlsMap
	}

	// 3. Transport (ws, grpc, httpupgrade)
	if trMap := buildInboundTransport(sb); trMap != nil {
		inbound["transport"] = trMap
	}

	// 4. Common options
	applyCommonInboundOptions(inbound, sb)

	return inbound
}
