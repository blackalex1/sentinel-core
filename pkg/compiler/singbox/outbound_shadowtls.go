package singbox

import (
	"github.com/blackalex1/sentinel-core/pkg/ast"
)

// buildShadowTLSOutbound compiles an ast.ServerProfile into a Sing-box ShadowTLS outbound object.
func buildShadowTLSOutbound(tag string, node *ast.ServerProfile) (map[string]interface{}, error) {
	version := 3
	if node.ShadowTLSVersion > 0 {
		version = node.ShadowTLSVersion
	}

	out := map[string]interface{}{
		"type":        "shadowtls",
		"tag":         tag,
		"server":      node.Address,
		"server_port": node.Port,
		"version":     version,
		"password":    node.ShadowTLSPassword,
	}

	tlsMap := map[string]interface{}{
		"enabled":     true,
		"server_name": node.ShadowTLSSNI,
	}
	if node.Fingerprint != "" {
		tlsMap["utls"] = map[string]interface{}{
			"enabled":     true,
			"fingerprint": node.Fingerprint,
		}
	}
	out["tls"] = tlsMap

	return out, nil
}
