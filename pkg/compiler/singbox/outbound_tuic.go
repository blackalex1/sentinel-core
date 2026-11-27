package singbox

import (
	"github.com/blackalex1/sentinel-core/pkg/ast"
)

// buildTUICOutbound compiles an ast.ServerProfile into a Sing-box TUIC outbound object.
func buildTUICOutbound(tag string, node *ast.ServerProfile) (map[string]interface{}, error) {
	return buildTUICOutboundMap(tag, node), nil
}

func buildTUICOutboundMap(tag string, node *ast.ServerProfile) map[string]interface{} {
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

	// TLS Settings (QUIC/UDP protocols like TUIC do NOT support uTLS in sing-box)
	tlsMap := buildSingBoxTLS(node)
	if tlsMap != nil {
		delete(tlsMap, "utls")
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

	return out
}

func compileRawTUICOutbound(tag string, sMap, tsMap map[string]interface{}) map[string]interface{} {
	node := &ast.ServerProfile{
		Protocol: ast.ProtoTUIC,
		Port:     8443,
	}
	if sMap != nil {
		if s, ok := sMap["host"].(string); ok && s != "" {
			node.Address = s
		} else if s, ok := sMap["address"].(string); ok && s != "" {
			node.Address = s
		} else if s, ok := sMap["server"].(string); ok && s != "" {
			node.Address = s
		}
		if p, ok := sMap["port"].(float64); ok && p > 0 {
			node.Port = int(p)
		} else if p, ok := sMap["server_port"].(float64); ok && p > 0 {
			node.Port = int(p)
		}
		if u, ok := sMap["uuid"].(string); ok {
			node.UUID = u
		}
		if pwd, ok := sMap["password"].(string); ok {
			node.Password = pwd
		}
		if cc, ok := sMap["congestionControl"].(string); ok && cc != "" {
			node.CongestionControl = cc
		} else if cc, ok := sMap["congestion_control"].(string); ok && cc != "" {
			node.CongestionControl = cc
		}
		if urm, ok := sMap["udpRelayMode"].(string); ok && urm != "" {
			node.UDPRelayMode = urm
		} else if urm, ok := sMap["udp_relay_mode"].(string); ok && urm != "" {
			node.UDPRelayMode = urm
		}
		if zr, ok := sMap["zeroRttHandshake"].(bool); ok {
			node.ZeroRTTHandshake = zr
		} else if zr, ok := sMap["zero_rtt_handshake"].(bool); ok {
			node.ZeroRTTHandshake = zr
		}
		if sni, ok := sMap["sni"].(string); ok && sni != "" {
			node.SNI = sni
		}
		if ins, ok := sMap["allowInsecure"].(bool); ok {
			node.Insecure = ins
		}
	}
	if tsMap != nil {
		if tlsSet, ok := tsMap["tlsSettings"].(map[string]interface{}); ok {
			if sn, ok := tlsSet["serverName"].(string); ok && sn != "" {
				node.SNI = sn
			}
			if ins, ok := tlsSet["allowInsecure"].(bool); ok {
				node.Insecure = ins
			}
			if alpnRaw, ok := tlsSet["alpn"].([]interface{}); ok {
				for _, item := range alpnRaw {
					if a, ok := item.(string); ok && a != "" {
						node.ALPN = append(node.ALPN, a)
					}
				}
			}
		}
	}
	return buildTUICOutboundMap(tag, node)
}
