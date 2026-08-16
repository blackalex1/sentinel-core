package xray

import (
	"github.com/blackalex1/sentinel-core/pkg/ast"
)

// buildXrayVMessInbound compiles an ast.ServerInboundSpec into an Xray VMess inbound configuration.
func buildXrayVMessInbound(sb *ast.ServerInboundSpec) map[string]interface{} {
	listenAddr := sb.ListenAddress
	if listenAddr == "" {
		listenAddr = "0.0.0.0"
	}

	settings := map[string]interface{}{}
	if sb.RawSettings != nil {
		for k, v := range sb.RawSettings {
			settings[k] = v
		}
	}

	if len(sb.Clients) > 0 {
		clients := make([]map[string]interface{}, 0, len(sb.Clients))
		for _, c := range sb.Clients {
			uid := c.UUID
			if uid == "" {
				uid = c.ID
			}
			if uid == "" {
				uid = c.Password
			}
			cl := map[string]interface{}{
				"id":    uid,
				"email": c.Email,
			}
			if alt, ok := sb.RawSettings["alterId"].(int); ok && alt > 0 {
				cl["alterId"] = alt
			}
			clients = append(clients, cl)
		}
		settings["clients"] = clients
	} else if rawClients, ok := settings["clients"].([]interface{}); ok && len(rawClients) > 0 {
		clients := make([]map[string]interface{}, 0, len(rawClients))
		for _, rc := range rawClients {
			if rcMap, ok := rc.(map[string]interface{}); ok {
				uid, _ := rcMap["id"].(string)
				if uid == "" {
					uid, _ = rcMap["uuid"].(string)
				}
				if uid == "" {
					uid, _ = rcMap["password"].(string)
				}
				email, _ := rcMap["email"].(string)
				cl := map[string]interface{}{
					"id":    uid,
					"email": email,
				}
				if alt, ok := rcMap["alterId"].(float64); ok && alt > 0 {
					cl["alterId"] = int(alt)
				}
				clients = append(clients, cl)
			}
		}
		settings["clients"] = clients
	}

	return map[string]interface{}{
		"tag":            sb.Tag,
		"port":           sb.Port,
		"listen":         listenAddr,
		"protocol":       "vmess",
		"settings":       settings,
		"streamSettings": buildInboundStreamSettings(sb),
		"sniffing":       buildInboundSniffing(sb),
	}
}
