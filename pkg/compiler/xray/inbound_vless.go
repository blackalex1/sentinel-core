package xray

import (
	"strings"

	"github.com/blackalex1/sentinel-core/pkg/ast"
)

// buildXrayVLESSInbound compiles an ast.ServerInboundSpec into an Xray VLESS inbound configuration.
func buildXrayVLESSInbound(sb *ast.ServerInboundSpec) map[string]interface{} {
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
			flow := c.Flow
			if flow == "" && sb.RawSettings != nil {
				if f, ok := sb.RawSettings["flow"].(string); ok && f != "" {
					flow = f
				}
			}
			// Flow is only supported for TCP + (Reality or TLS)
			if sb.Transport != "" && sb.Transport != "tcp" {
				flow = ""
			}
			secVal := sb.Security
			if secVal == "" && sb.StreamSettings != nil {
				if s, ok := sb.StreamSettings["security"].(string); ok {
					secVal = s
				}
			}
			if secVal != "reality" && secVal != "tls" {
				flow = ""
			}
			if flow != "" && flow != "xtls-rprx-vision" && flow != "xtls-rprx-vision-udp443" {
				flow = ""
			}
			if flow != "" {
				cl["flow"] = flow
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
				if fl, ok := rcMap["flow"].(string); ok && fl != "" {
					cl["flow"] = fl
				}
				clients = append(clients, cl)
			}
		}
		settings["clients"] = clients
	}
	if clientsList, ok := settings["clients"].([]map[string]interface{}); !ok || len(clientsList) == 0 {
		if rawList, ok := settings["clients"].([]interface{}); !ok || len(rawList) == 0 {
			settings["clients"] = []map[string]interface{}{
				{
					"id":    "00000000-0000-0000-0000-000000000000",
					"email": "default",
				},
			}
		}
	}

	// VLESS Encryption (vlessenc) vs standard VLESS
	if dec, ok := settings["decryption"].(string); ok && strings.HasPrefix(dec, "mlkem768x25519plus.") {
		settings["decryption"] = dec
	} else {
		settings["decryption"] = "none"
	}
	delete(settings, "encryption")

	sec := sb.Security
	if sec == "" && sb.StreamSettings != nil {
		if s, ok := sb.StreamSettings["security"].(string); ok {
			sec = s
		}
	}

	if sec != "reality" {
		if len(sb.Fallbacks) > 0 {
			settings["fallbacks"] = sb.Fallbacks
		} else if fb, ok := sb.RawSettings["fallbacks"]; ok {
			settings["fallbacks"] = fb
		}
	} else {
		delete(settings, "fallbacks")
	}

	return map[string]interface{}{
		"tag":            sb.Tag,
		"port":           sb.Port,
		"listen":         listenAddr,
		"protocol":       "vless",
		"settings":       settings,
		"streamSettings": buildInboundStreamSettings(sb),
		"sniffing":       buildInboundSniffing(sb),
	}
}
