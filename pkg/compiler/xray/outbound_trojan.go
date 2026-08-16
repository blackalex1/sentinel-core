package xray

import (
	"github.com/blackalex1/sentinel-core/pkg/ast"
)

// buildXrayTrojanOutbound compiles an ast.ServerProfile into an Xray Trojan outbound object.
func buildXrayTrojanOutbound(tag string, node *ast.ServerProfile) (map[string]interface{}, error) {
	servers := []map[string]interface{}{
		{
			"address":  node.Address,
			"port":     node.Port,
			"password": node.Password,
		},
	}

	streamSettings := buildXrayStreamSettings(node)

	return map[string]interface{}{
		"protocol": "trojan",
		"tag":      tag,
		"settings": map[string]interface{}{
			"servers": servers,
		},
		"streamSettings": streamSettings,
	}, nil
}
