package singbox

import (
	"strings"

	"github.com/blackalex1/sentinel-core/pkg/ast"
)

// buildTrojanOutbound compiles an ast.ServerProfile into a Sing-box Trojan outbound object.
func buildTrojanOutbound(tag string, node *ast.ServerProfile) (map[string]interface{}, error) {
	out := map[string]interface{}{
		"type":        "trojan",
		"tag":         tag,
		"server":      node.Address,
		"server_port": node.Port,
		"password":    node.Password,
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

// compileRawTrojanOutbound compiles raw dictionaries into a Sing-box Trojan outbound object.
func compileRawTrojanOutbound(tag string, sMap, tsMap map[string]interface{}) map[string]interface{} {
	trOb := map[string]interface{}{
		"type": "trojan",
		"tag":  tag,
	}

	var server string
	var portRaw interface{}
	var password string

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

		if pwd, ok := sMap["password"].(string); ok && pwd != "" {
			password = pwd
		}

		if serversRaw, ok := sMap["servers"].([]interface{}); ok && len(serversRaw) > 0 {
			if firstSrv, ok := serversRaw[0].(map[string]interface{}); ok {
				if server == "" {
					if addr, ok := firstSrv["address"].(string); ok {
						server = addr
					}
				}
				if portRaw == nil {
					if p, ok := firstSrv["port"]; ok {
						portRaw = p
					}
				}
				if password == "" {
					if pwd, ok := firstSrv["password"].(string); ok {
						password = pwd
					}
				}
			}
		} else if serversRaw, ok := sMap["servers"].([]map[string]interface{}); ok && len(serversRaw) > 0 {
			firstSrv := serversRaw[0]
			if server == "" {
				if addr, ok := firstSrv["address"].(string); ok {
					server = addr
				}
			}
			if portRaw == nil {
				if p, ok := firstSrv["port"]; ok {
					portRaw = p
				}
			}
			if password == "" {
				if pwd, ok := firstSrv["password"].(string); ok {
					password = pwd
				}
			}
		}
	}

	trOb["server"] = server
	trOb["password"] = password

	if portRaw != nil {
		switch v := portRaw.(type) {
		case float64:
			trOb["server_port"] = int(v)
		case int:
			trOb["server_port"] = v
		case string:
			vTrim := strings.TrimSpace(v)
			var pInt int
			for _, c := range vTrim {
				if c >= '0' && c <= '9' {
					pInt = pInt*10 + int(c-'0')
				}
			}
			if pInt > 0 {
				trOb["server_port"] = pInt
			}
		}
	}

	applyRawTLSAndTransport(trOb, sMap, tsMap, server)
	return trOb
}
