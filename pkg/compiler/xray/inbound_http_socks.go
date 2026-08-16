package xray

import (
	"github.com/blackalex1/sentinel-core/pkg/ast"
)

// buildXraySOCKSInbound compiles an ast.ServerInboundSpec into an Xray SOCKS inbound configuration.
func buildXraySOCKSInbound(sb *ast.ServerInboundSpec) map[string]interface{} {
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

	if _, ok := settings["udp"]; !ok {
		settings["udp"] = true
	}

	if len(sb.Clients) > 0 {
		accounts := make([]map[string]interface{}, 0, len(sb.Clients))
		for _, c := range sb.Clients {
			user := c.Email
			if user == "" {
				user = c.ID
			}
			pass := c.Password
			if pass == "" {
				pass = c.UUID
			}
			if pass == "" {
				pass = c.ID
			}
			if user != "" && pass != "" {
				accounts = append(accounts, map[string]interface{}{
					"user": user,
					"pass": pass,
				})
			}
		}
		if len(accounts) > 0 {
			settings["auth"] = "password"
			settings["accounts"] = accounts
		} else {
			settings["auth"] = "noauth"
		}
	} else if _, ok := settings["auth"]; !ok {
		settings["auth"] = "noauth"
	}

	return map[string]interface{}{
		"tag":            sb.Tag,
		"port":           sb.Port,
		"listen":         listenAddr,
		"protocol":       "socks",
		"settings":       settings,
		"streamSettings": buildInboundStreamSettings(sb),
		"sniffing":       buildInboundSniffing(sb),
	}
}

// buildXrayHTTPInbound compiles an ast.ServerInboundSpec into an Xray HTTP inbound configuration.
func buildXrayHTTPInbound(sb *ast.ServerInboundSpec) map[string]interface{} {
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
		accounts := make([]map[string]interface{}, 0, len(sb.Clients))
		for _, c := range sb.Clients {
			user := c.Email
			if user == "" {
				user = c.ID
			}
			pass := c.Password
			if pass == "" {
				pass = c.UUID
			}
			if pass == "" {
				pass = c.ID
			}
			if user != "" && pass != "" {
				accounts = append(accounts, map[string]interface{}{
					"user": user,
					"pass": pass,
				})
			}
		}
		if len(accounts) > 0 {
			settings["accounts"] = accounts
		}
	}

	if _, ok := settings["allowTransparent"]; !ok {
		settings["allowTransparent"] = false
	}

	return map[string]interface{}{
		"tag":            sb.Tag,
		"port":           sb.Port,
		"listen":         listenAddr,
		"protocol":       "http",
		"settings":       settings,
		"streamSettings": buildInboundStreamSettings(sb),
		"sniffing":       buildInboundSniffing(sb),
	}
}
