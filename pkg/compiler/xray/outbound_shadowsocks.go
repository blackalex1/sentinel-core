package xray

import (
	"github.com/blackalex1/sentinel-core/pkg/ast"
)

// buildXrayShadowsocksOutbound compiles an ast.ServerProfile into an Xray Shadowsocks outbound object.
func buildXrayShadowsocksOutbound(tag string, node *ast.ServerProfile) (map[string]interface{}, error) {
	cipher := node.Cipher
	if cipher == "" {
		cipher = "2022-blake3-aes-128-gcm"
	}
	servers := []map[string]interface{}{
		{
			"address":  node.Address,
			"port":     node.Port,
			"method":   cipher,
			"password": node.Password,
		},
	}

	return map[string]interface{}{
		"protocol": "shadowsocks",
		"tag":      tag,
		"settings": map[string]interface{}{
			"servers": servers,
		},
	}, nil
}
