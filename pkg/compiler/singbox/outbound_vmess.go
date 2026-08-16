package singbox

import (
	"strings"

	"github.com/blackalex1/sentinel-core/pkg/ast"
)

// buildVMessOutbound compiles an ast.ServerProfile into a Sing-box VMess outbound object.
func buildVMessOutbound(tag string, node *ast.ServerProfile) (map[string]interface{}, error) {
	out := map[string]interface{}{
		"type":        "vmess",
		"tag":         tag,
		"server":      node.Address,
		"server_port": node.Port,
		"uuid":        node.UUID,
		"security":    "auto",
	}

	if node.Cipher != "" {
		out["security"] = node.Cipher
	}

	// TLS Settings
	tlsMap := buildSingBoxTLS(node)
	if tlsMap != nil {
		out["tls"] = tlsMap
	}

	// Transport Layer
	transportMap := buildSingBoxTransport(node)
	if transportMap != nil {
		out["transport"] = transportMap
	}

	return out, nil
}

// compileRawVMessOutbound compiles raw dictionaries into a Sing-box VMess outbound object.
func compileRawVMessOutbound(tag string, sMap, tsMap map[string]interface{}) map[string]interface{} {
	vmOb := map[string]interface{}{
		"type":     "vmess",
		"tag":      tag,
		"security": "auto",
	}

	var server string
	var portRaw interface{}
	var uuid string

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

		if u, ok := sMap["uuid"].(string); ok && u != "" {
			uuid = u
		} else if id, ok := sMap["id"].(string); ok && id != "" {
			uuid = id
		}

		if vnextRaw, ok := sMap["vnext"].([]interface{}); ok && len(vnextRaw) > 0 {
			if firstVnext, ok := vnextRaw[0].(map[string]interface{}); ok {
				if server == "" {
					if addr, ok := firstVnext["address"].(string); ok {
						server = addr
					}
				}
				if portRaw == nil {
					if p, ok := firstVnext["port"]; ok {
						portRaw = p
					}
				}
				if usersRaw, ok := firstVnext["users"].([]interface{}); ok && len(usersRaw) > 0 {
					if firstUser, ok := usersRaw[0].(map[string]interface{}); ok {
						if uuid == "" {
							if id, ok := firstUser["id"].(string); ok {
								uuid = id
							}
						}
						if sec, ok := firstUser["security"].(string); ok && sec != "" {
							vmOb["security"] = sec
						}
					}
				}
			}
		}
	}

	vmOb["server"] = server
	vmOb["uuid"] = uuid

	if portRaw != nil {
		switch v := portRaw.(type) {
		case float64:
			vmOb["server_port"] = int(v)
		case int:
			vmOb["server_port"] = v
		case string:
			vTrim := strings.TrimSpace(v)
			var pInt int
			for _, c := range vTrim {
				if c >= '0' && c <= '9' {
					pInt = pInt*10 + int(c-'0')
				}
			}
			if pInt > 0 {
				vmOb["server_port"] = pInt
			}
		}
	}

	applyRawTLSAndTransport(vmOb, sMap, tsMap, server)
	return vmOb
}
