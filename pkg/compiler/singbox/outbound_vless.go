package singbox

import (
	"strings"

	"github.com/blackalex1/sentinel-core/pkg/ast"
)

// buildVLESSOutbound compiles an ast.ServerProfile into a Sing-box VLESS outbound object.
func buildVLESSOutbound(tag string, node *ast.ServerProfile) (map[string]interface{}, error) {
	out := map[string]interface{}{
		"type":        "vless",
		"tag":         tag,
		"server":      node.Address,
		"server_port": node.Port,
		"uuid":        node.UUID,
	}

	if node.Flow != "" {
		out["flow"] = node.Flow
	}

	// TLS / Reality Settings
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

// compileRawVLESSOutbound compiles a raw settings/streamSettings dictionary into a Sing-box VLESS outbound object.
func compileRawVLESSOutbound(tag string, sMap, tsMap map[string]interface{}) map[string]interface{} {
	vlOb := map[string]interface{}{
		"type": "vless",
		"tag":  tag,
	}

	var server string
	var portRaw interface{}
	var uuid string
	var flow string

	if addr, ok := sMap["address"].(string); ok && addr != "" {
		server = addr
	} else if srv, ok := sMap["server"].(string); ok && srv != "" {
		server = srv
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

	if f, ok := sMap["flow"].(string); ok && f != "" {
		flow = f
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
					if flow == "" {
						if fl, ok := firstUser["flow"].(string); ok {
							flow = fl
						}
					}
				}
			}
		}
	}

	vlOb["server"] = server
	vlOb["uuid"] = uuid
	if flow != "" {
		vlOb["flow"] = flow
	}

	if portRaw != nil {
		switch v := portRaw.(type) {
		case float64:
			vlOb["server_port"] = int(v)
		case int:
			vlOb["server_port"] = v
		case string:
			vTrim := strings.TrimSpace(v)
			if strings.Contains(vTrim, "-") || strings.Contains(vTrim, ",") || strings.Contains(vTrim, ":") {
				parts := strings.Split(vTrim, ",")
				var ports []string
				for _, p := range parts {
					pClean := strings.TrimSpace(p)
					if pClean != "" {
						ports = append(ports, strings.ReplaceAll(pClean, "-", ":"))
					}
				}
				if len(ports) > 0 {
					vlOb["server_ports"] = ports
					vlOb["hop_interval"] = "30s"
				}
			} else {
				var pInt int
				for _, c := range vTrim {
					if c >= '0' && c <= '9' {
						pInt = pInt*10 + int(c-'0')
					}
				}
				if pInt > 0 {
					vlOb["server_port"] = pInt
				}
			}
		}
	}

	applyRawTLSAndTransport(vlOb, sMap, tsMap, server)
	return vlOb
}
