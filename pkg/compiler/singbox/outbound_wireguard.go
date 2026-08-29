package singbox

import (
	"strings"

	"github.com/blackalex1/sentinel-core/pkg/ast"
)

// buildWireGuardOutbound compiles an ast.ServerProfile into a Sing-box WireGuard outbound/endpoint object.
func buildWireGuardOutbound(tag string, node *ast.ServerProfile) (map[string]interface{}, error) {
	pubKey := node.PeerPublicKey
	if pubKey == "" {
		pubKey = node.PublicKey
	}

	peer := map[string]interface{}{
		"address":     node.Address,
		"port":        node.Port,
		"public_key":  pubKey,
		"allowed_ips": []string{"0.0.0.0/0", "::/0"},
	}

	if node.PreSharedKey != "" {
		peer["pre_shared_key"] = node.PreSharedKey
	}

	if len(node.ReservedBytes) > 0 {
		peer["reserved"] = node.ReservedBytes
	}

	out := map[string]interface{}{
		"type":        "wireguard",
		"tag":         tag,
		"private_key": node.PrivateKey,
		"peers":       []map[string]interface{}{peer},
	}

	if len(node.LocalAddress) > 0 {
		out["address"] = node.LocalAddress
	}

	if node.MTU > 0 {
		out["mtu"] = node.MTU
	}

	return out, nil
}

// compileRawWireguardOutbound compiles raw dictionaries into a Sing-box WireGuard outbound object.
func compileRawWireguardOutbound(tag string, sMap, tsMap map[string]interface{}) map[string]interface{} {
	wgOb := map[string]interface{}{
		"type": "wireguard",
		"tag":  tag,
	}

	var server string
	var portRaw interface{}

	if sMap != nil {
		if s, ok := sMap["server"].(string); ok && s != "" {
			server = s
		} else if a, ok := sMap["address"].(string); ok && a != "" {
			server = a
		} else if h, ok := sMap["host"].(string); ok && h != "" {
			server = h
		}

		if p, ok := sMap["port"]; ok {
			portRaw = p
		} else if p, ok := sMap["server_port"]; ok {
			portRaw = p
		}

		if pk, ok := sMap["secret_key"].(string); ok && pk != "" {
			wgOb["private_key"] = pk
		} else if pk, ok := sMap["private_key"].(string); ok && pk != "" {
			wgOb["private_key"] = pk
		}

		if pub, ok := sMap["public_key"].(string); ok && pub != "" {
			wgOb["peer_public_key"] = pub
		} else if pub, ok := sMap["peer_public_key"].(string); ok && pub != "" {
			wgOb["peer_public_key"] = pub
		}

		if psk, ok := sMap["pre_shared_key"].(string); ok && psk != "" {
			wgOb["pre_shared_key"] = psk
		} else if psk, ok := sMap["preshared_key"].(string); ok && psk != "" {
			wgOb["pre_shared_key"] = psk
		}

		if la, ok := sMap["address"].([]interface{}); ok {
			wgOb["local_address"] = la
		} else if la, ok := sMap["local_address"]; ok {
			wgOb["local_address"] = la
		}

		if res, ok := sMap["reserved"]; ok {
			wgOb["reserved"] = res
		}

		if mtu, ok := sMap["mtu"]; ok {
			wgOb["mtu"] = mtu
		}
	}

	wgOb["server"] = server

	if portRaw != nil {
		switch v := portRaw.(type) {
		case float64:
			wgOb["server_port"] = int(v)
		case int:
			wgOb["server_port"] = v
		case string:
			vTrim := strings.TrimSpace(v)
			var pInt int
			for _, c := range vTrim {
				if c >= '0' && c <= '9' {
					pInt = pInt*10 + int(c-'0')
				}
			}
			if pInt > 0 {
				wgOb["server_port"] = pInt
			}
		}
	}

	return wgOb
}
