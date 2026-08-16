package xray

import (
	"github.com/blackalex1/sentinel-core/pkg/ast"
)

// buildXrayHysteria2Outbound compiles an ast.ServerProfile into an Xray local SOCKS loopback outbound for Hysteria 2.
func buildXrayHysteria2Outbound(tag string, node *ast.ServerProfile) (map[string]interface{}, error) {
	// Xray connects to local Hysteria 2 client instance via SOCKS5 loopback
	localPort := 10808
	localHost := "127.0.0.1"
	if node.Address == "127.0.0.1" && node.Port > 0 {
		localPort = node.Port
	}
	return map[string]interface{}{
		"protocol": "socks",
		"tag":      tag,
		"settings": map[string]interface{}{
			"servers": []map[string]interface{}{
				{
					"address": localHost,
					"port":    localPort,
				},
			},
		},
	}, nil
}
