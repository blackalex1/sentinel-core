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

	if node.CongestionControl != "" {
		out["congestion_control"] = node.CongestionControl
	}
	if node.UDPRelayMode != "" {
		out["udp_relay_mode"] = node.UDPRelayMode
	}
	if node.ZeroRTTHandshake {
		out["zero_rtt_handshake"] = true
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
