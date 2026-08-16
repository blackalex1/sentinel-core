package singbox

import (
	"github.com/blackalex1/sentinel-core/pkg/ast"
)

// buildTrojanInbound compiles a Trojan inbound for Sing-box
func buildTrojanInbound(sb *ast.ServerInboundSpec) map[string]interface{} {
	listenAddr := sb.ListenAddress
	if listenAddr == "" {
		listenAddr = "::"
	}

	inbound := map[string]interface{}{
		"type":        "trojan",
		"tag":         sb.Tag,
		"listen":      listenAddr,
		"listen_port": sb.Port,
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
	}

	if tlsMap := buildInboundTLS(sb); tlsMap != nil {
		inbound["tls"] = tlsMap
	}
	if trMap := buildInboundTransport(sb); trMap != nil {
		inbound["transport"] = trMap
	}
	applyCommonInboundOptions(inbound, sb)
	return inbound
}

// buildVMessInbound compiles a VMess inbound for Sing-box
func buildVMessInbound(sb *ast.ServerInboundSpec) map[string]interface{} {
	listenAddr := sb.ListenAddress
	if listenAddr == "" {
		listenAddr = "::"
	}

	inbound := map[string]interface{}{
		"type":        "vmess",
		"tag":         sb.Tag,
		"listen":      listenAddr,
		"listen_port": sb.Port,
	}

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
			users = append(users, map[string]interface{}{
				"name": c.Email,
				"uuid": uid,
			})
		}
		inbound["users"] = users
	}

	if tlsMap := buildInboundTLS(sb); tlsMap != nil {
		inbound["tls"] = tlsMap
	}
	if trMap := buildInboundTransport(sb); trMap != nil {
		inbound["transport"] = trMap
	}
	applyCommonInboundOptions(inbound, sb)
	return inbound
}
