package xray

import (
	"github.com/blackalex1/sentinel-core/pkg/ast"
)

// buildXrayHttpOutbound compiles an ast.ServerProfile into an Xray HTTP outbound object.
func buildXrayHttpOutbound(tag string, node *ast.ServerProfile) (map[string]interface{}, error) {
	server := map[string]interface{}{
		"address": node.Address,
		"port":    node.Port,
	}

	if node.Username != "" || node.Password != "" {
		server["users"] = []map[string]interface{}{
			{
				"user": node.Username,
				"pass": node.Password,
			},
		}
	}

	return map[string]interface{}{
		"protocol": "http",
		"tag":      tag,
		"settings": map[string]interface{}{
			"servers": []map[string]interface{}{server},
		},
	}, nil
}
