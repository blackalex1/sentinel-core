package xray

import (
	"github.com/blackalex1/sentinel-core/pkg/ast"
)

// buildXraySocksOutbound compiles an ast.ServerProfile into an Xray SOCKS outbound object.
func buildXraySocksOutbound(tag string, node *ast.ServerProfile) (map[string]interface{}, error) {
	server := map[string]interface{}{
		"address": node.Address,
		"port":    node.Port,
	}

	if node.Username != "" || node.Password != "" {
		server["users"] = []map[string]interface{}{
			{
				"user":  node.Username,
				"pass":  node.Password,
				"level": 0,
			},
		}
	}

	return map[string]interface{}{
		"protocol": "socks",
		"tag":      tag,
		"settings": map[string]interface{}{
			"servers": []map[string]interface{}{server},
		},
	}, nil
}
