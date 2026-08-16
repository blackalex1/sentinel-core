package xray

import (
	"github.com/blackalex1/sentinel-core/pkg/ast"
)

// buildXrayVMessOutbound compiles an ast.ServerProfile into an Xray VMess outbound object.
func buildXrayVMessOutbound(tag string, node *ast.ServerProfile) (map[string]interface{}, error) {
	vnext := []map[string]interface{}{
		{
			"address": node.Address,
			"port":    node.Port,
			"users": []map[string]interface{}{
				{
					"id":       node.UUID,
					"alterId":  0,
					"security": "auto",
				},
			},
		},
	}

	streamSettings := buildXrayStreamSettings(node)

	return map[string]interface{}{
		"protocol": "vmess",
		"tag":      tag,
		"settings": map[string]interface{}{
			"vnext": vnext,
		},
		"streamSettings": streamSettings,
	}, nil
}
