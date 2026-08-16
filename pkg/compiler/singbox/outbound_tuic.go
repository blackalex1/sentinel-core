package singbox

import (
	"github.com/blackalex1/sentinel-core/pkg/ast"
)

// buildTUICOutbound compiles an ast.ServerProfile into a Sing-box TUIC outbound object.
func buildTUICOutbound(tag string, node *ast.ServerProfile) (map[string]interface{}, error) {
	out := map[string]interface{}{
		"type":        "tuic",
		"tag":         tag,
		"server":      node.Address,
		"server_port": node.Port,
		"uuid":        node.UUID,
		"password":    node.Password,
	}

	// TLS Settings
	tlsMap := buildSingBoxTLS(node)
	if tlsMap != nil {
		out["tls"] = tlsMap
	} else {
		tlsMap = map[string]interface{}{
			"enabled": true,
		}
		if node.SNI != "" {
			tlsMap["server_name"] = node.SNI
		}
		out["tls"] = tlsMap
	}

	return out, nil
}
