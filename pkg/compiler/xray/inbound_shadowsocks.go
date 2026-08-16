package xray

import (
	"strings"

	"github.com/blackalex1/sentinel-core/pkg/ast"
	"github.com/blackalex1/sentinel-core/pkg/crypto"
)

// buildXrayShadowsocksInbound compiles an ast.ServerInboundSpec into an Xray Shadowsocks inbound configuration.
func buildXrayShadowsocksInbound(sb *ast.ServerInboundSpec) map[string]interface{} {
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

	// 1. Resolve method
	method := ""
	if m, ok := settings["method"].(string); ok && m != "" {
		method = m
	} else if c, ok := settings["cipher"].(string); ok && c != "" {
		method = c
	}
	if method == "" && sb.Security != "" && sb.Security != "none" {
		method = sb.Security
	}
	if method == "" {
		method = "2022-blake3-aes-128-gcm"
	}
	settings["method"] = method

	// 2. Extract password
	pwd := ""
	if len(sb.Clients) > 0 {
		pwd = sb.Clients[0].Password
		if pwd == "" {
			pwd = sb.Clients[0].ID
		}
		if pwd == "" {
			pwd = sb.Clients[0].UUID
		}
	}
	if pwd == "" {
		if p, ok := settings["password"].(string); ok && p != "" {
			pwd = p
		}
	}
	if pwd == "" {
		if rawClients, ok := settings["clients"].([]interface{}); ok && len(rawClients) > 0 {
			if rcMap, ok := rawClients[0].(map[string]interface{}); ok {
				if p, ok := rcMap["password"].(string); ok && p != "" {
					pwd = p
				} else if p, ok := rcMap["id"].(string); ok && p != "" {
					pwd = p
				} else if p, ok := rcMap["uuid"].(string); ok && p != "" {
					pwd = p
				}
			}
		}
	}
	if pwd == "" {
		pwd = crypto.GenerateShadowsocksKey(method)
	}
	settings["password"] = pwd

	// 3. For classic AEAD methods (non-2022), Xray expects password in root and no clients array
	if !strings.HasPrefix(method, "2022-") {
		delete(settings, "clients")
	} else {
		// For 2022 multi-user, build clients array with password field
		if len(sb.Clients) > 0 {
			clients := make([]map[string]interface{}, 0, len(sb.Clients))
			for _, c := range sb.Clients {
				cpwd := c.Password
				if cpwd == "" {
					cpwd = c.ID
				}
				if cpwd == "" {
					cpwd = c.UUID
				}
				clients = append(clients, map[string]interface{}{
					"password": cpwd,
					"email":    c.Email,
				})
			}
			settings["clients"] = clients
		}
	}

	if net, ok := settings["network"].(string); !ok || net == "" {
		settings["network"] = "tcp,udp"
	}

	return map[string]interface{}{
		"tag":            sb.Tag,
		"port":           sb.Port,
		"listen":         listenAddr,
		"protocol":       "shadowsocks",
		"settings":       settings,
		"streamSettings": buildInboundStreamSettings(sb),
		"sniffing":       buildInboundSniffing(sb),
	}
}
