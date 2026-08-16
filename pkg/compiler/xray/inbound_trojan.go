package xray

import (
	"github.com/blackalex1/sentinel-core/pkg/ast"
)

// buildXrayTrojanInbound compiles an ast.ServerInboundSpec into an Xray Trojan inbound configuration.
func buildXrayTrojanInbound(sb *ast.ServerInboundSpec) map[string]interface{} {
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
			pwd := c.Password
			if pwd == "" {
				pwd = c.UUID
			}
			if pwd == "" {
				pwd = c.ID
			}
			clients = append(clients, map[string]interface{}{
				"password": pwd,
				"email":    c.Email,
			})
		}
		settings["clients"] = clients
	} else if rawClients, ok := settings["clients"].([]interface{}); ok && len(rawClients) > 0 {
		clients := make([]map[string]interface{}, 0, len(rawClients))
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
				clients = append(clients, map[string]interface{}{
					"password": pwd,
					"email":    email,
				})
			}
		}
		settings["clients"] = clients
	}
	if clientsList, ok := settings["clients"].([]map[string]interface{}); !ok || len(clientsList) == 0 {
		if rawList, ok := settings["clients"].([]interface{}); !ok || len(rawList) == 0 {
			settings["clients"] = []map[string]interface{}{
				{
					"password": "default-trojan-password",
					"email":    "default",
				},
			}
		}
	}

	return map[string]interface{}{
		"tag":            sb.Tag,
		"port":           sb.Port,
		"listen":         listenAddr,
		"protocol":       "trojan",
		"settings":       settings,
		"streamSettings": buildInboundStreamSettings(sb),
		"sniffing":       buildInboundSniffing(sb),
	}
}
