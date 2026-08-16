package xray

import (
	"github.com/blackalex1/sentinel-core/pkg/ast"
)

// buildXrayVLESSOutbound compiles an ast.ServerProfile into an Xray VLESS outbound object.
func buildXrayVLESSOutbound(tag string, node *ast.ServerProfile) (map[string]interface{}, error) {
	enc := "none"
	if node.Encryption != "" {
		enc = node.Encryption
	}

	vnext := []map[string]interface{}{
		{
			"address": node.Address,
			"port":    node.Port,
			"users": []map[string]interface{}{
				{
					"id":         node.UUID,
					"encryption": enc,
					"flow":       node.Flow,
				},
			},
		},
	}

	streamSettings := buildXrayStreamSettings(node)

	return map[string]interface{}{
		"protocol": "vless",
		"tag":      tag,
		"settings": map[string]interface{}{
			"vnext": vnext,
		},
		"streamSettings": streamSettings,
	}, nil
}
