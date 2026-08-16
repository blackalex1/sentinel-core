package singbox

import (
	"github.com/blackalex1/sentinel-core/pkg/ast"
)

// buildHTTPInbound compiles an HTTP inbound for Sing-box
func buildHTTPInbound(sb *ast.ServerInboundSpec) map[string]interface{} {
	listenAddr := sb.ListenAddress
	if listenAddr == "" {
		listenAddr = "::"
	}

	inbound := map[string]interface{}{
		"type":        "http",
		"tag":         sb.Tag,
		"listen":      listenAddr,
		"listen_port": sb.Port,
	}

	if len(sb.Clients) > 0 {
		users := make([]map[string]interface{}, 0, len(sb.Clients))
		for _, c := range sb.Clients {
			uname := c.Email
			if uname == "" {
				uname = c.ID
			}
			if uname == "" {
				uname = c.UUID
			}
			users = append(users, map[string]interface{}{
				"username": uname,
				"password": c.Password,
			})
		}
		inbound["users"] = users
	}

	if tlsMap := buildInboundTLS(sb); tlsMap != nil {
		inbound["tls"] = tlsMap
	}
	applyCommonInboundOptions(inbound, sb)
	return inbound
}

// buildSocksInbound compiles a SOCKS inbound for Sing-box
func buildSocksInbound(sb *ast.ServerInboundSpec) map[string]interface{} {
	listenAddr := sb.ListenAddress
	if listenAddr == "" {
		listenAddr = "::"
	}

	inbound := map[string]interface{}{
		"type":        "socks",
		"tag":         sb.Tag,
		"listen":      listenAddr,
		"listen_port": sb.Port,
	}

	if len(sb.Clients) > 0 {
		users := make([]map[string]interface{}, 0, len(sb.Clients))
		for _, c := range sb.Clients {
			uname := c.Email
			if uname == "" {
				uname = c.ID
			}
			if uname == "" {
				uname = c.UUID
			}
			users = append(users, map[string]interface{}{
				"username": uname,
				"password": c.Password,
			})
		}
		inbound["users"] = users
	}

	applyCommonInboundOptions(inbound, sb)
	return inbound
}

// buildTUICInbound compiles a TUIC inbound for Sing-box
func buildTUICInbound(sb *ast.ServerInboundSpec) map[string]interface{} {
	listenAddr := sb.ListenAddress
	if listenAddr == "" {
		listenAddr = "::"
	}

	inbound := map[string]interface{}{
		"type":        "tuic",
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
			users = append(users, map[string]interface{}{
				"name":     c.Email,
				"uuid":     uid,
				"password": c.Password,
			})
		}
		inbound["users"] = users
	}

	if sb.RawSettings != nil {
		if cc, ok := sb.RawSettings["congestion_controller"].(string); ok && cc != "" {
			inbound["congestion_controller"] = cc
		}
		if zrtt, ok := sb.RawSettings["zero_rtt_handshake"].(bool); ok {
			inbound["zero_rtt_handshake"] = zrtt
		}
		if hb, ok := sb.RawSettings["heartbeat"].(string); ok && hb != "" {
			inbound["heartbeat"] = hb
		}
	}

	if tlsMap := buildInboundTLS(sb); tlsMap != nil {
		inbound["tls"] = tlsMap
	}
	applyCommonInboundOptions(inbound, sb)
	return inbound
}
