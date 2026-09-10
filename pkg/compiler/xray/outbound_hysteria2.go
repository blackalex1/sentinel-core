package xray

import (
	"github.com/blackalex1/sentinel-core/pkg/ast"
)

// buildXrayHysteria2Outbound compiles an ast.ServerProfile into an Xray Hysteria 2 outbound.
func buildXrayHysteria2Outbound(tag string, node *ast.ServerProfile) (map[string]interface{}, error) {
	if node.Address == "127.0.0.1" || node.Address == "localhost" {
		localPort := 10808
		if node.Port > 0 {
			localPort = node.Port
		}
		return map[string]interface{}{
			"protocol": "socks",
			"tag":      tag,
			"settings": map[string]interface{}{
				"servers": []map[string]interface{}{
					{
						"address": node.Address,
						"port":    localPort,
					},
				},
			},
		}, nil
	}

	auth := node.Password
	if auth == "" {
		auth = node.UUID
	}
	if auth == "" {
		auth = node.Username
	}

	tlsSettings := map[string]interface{}{}
	sni := node.SNI
	if sni == "" {
		sni = node.Address
	}
	if sni != "" {
		tlsSettings["serverName"] = sni
	}
	if node.PinnedPeerCertSha256 != "" {
		tlsSettings["pinnedPeerCertSha256"] = node.PinnedPeerCertSha256
	}
	if len(node.ALPN) > 0 {
		tlsSettings["alpn"] = node.ALPN
	}

	hysteriaSettings := map[string]interface{}{
		"version": 2,
		"auth":    auth,
	}

	streamSettings := map[string]interface{}{
		"network":          "hysteria",
		"security":         "tls",
		"tlsSettings":      tlsSettings,
		"hysteriaSettings": hysteriaSettings,
	}

	outbound := map[string]interface{}{
		"tag":      tag,
		"protocol": "hysteria",
		"settings": map[string]interface{}{
			"version": 2,
			"address": node.Address,
			"port":    node.Port,
			"auth":    auth,
		},
		"streamSettings": streamSettings,
	}

	return outbound, nil
}
