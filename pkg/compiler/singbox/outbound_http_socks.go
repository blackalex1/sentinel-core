package singbox

import (
	"strings"

	"github.com/blackalex1/sentinel-core/pkg/ast"
)

// buildSocksOutbound compiles an ast.ServerProfile into a Sing-box SOCKS outbound object.
func buildSocksOutbound(tag string, node *ast.ServerProfile) (map[string]interface{}, error) {
	out := map[string]interface{}{
		"type":        "socks",
		"tag":         tag,
		"server":      node.Address,
		"server_port": node.Port,
	}
	if node.Username != "" {
		out["username"] = node.Username
	}
	if node.Password != "" {
		out["password"] = node.Password
	}
	return out, nil
}

// buildHTTPOutbound compiles an ast.ServerProfile into a Sing-box HTTP outbound object.
func buildHTTPOutbound(tag string, node *ast.ServerProfile) (map[string]interface{}, error) {
	out := map[string]interface{}{
		"type":        "http",
		"tag":         tag,
		"server":      node.Address,
		"server_port": node.Port,
	}
	if node.Username != "" {
		out["username"] = node.Username
	}
	if node.Password != "" {
		out["password"] = node.Password
	}
	if tlsMap := buildSingBoxTLS(node); tlsMap != nil {
		out["tls"] = tlsMap
	}
	return out, nil
}

// compileRawSocksHttpOutbound compiles raw dictionaries into a Sing-box SOCKS or HTTP outbound object.
func compileRawSocksHttpOutbound(tag, proto string, sMap, tsMap map[string]interface{}) map[string]interface{} {
	shOb := map[string]interface{}{
		"type": proto,
		"tag":  tag,
	}

	var server string
	var portRaw interface{}
	var user string
	var pass string

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

		if u, ok := sMap["user"].(string); ok && u != "" {
			user = u
		} else if u, ok := sMap["username"].(string); ok && u != "" {
			user = u
		}

		if p, ok := sMap["pass"].(string); ok && p != "" {
			pass = p
		} else if p, ok := sMap["password"].(string); ok && p != "" {
			pass = p
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
				if user == "" {
					if u, ok := firstSrv["user"].(string); ok {
						user = u
					} else if u, ok := firstSrv["username"].(string); ok {
						user = u
					}
				}
				if pass == "" {
					if p, ok := firstSrv["pass"].(string); ok {
						pass = p
					} else if p, ok := firstSrv["password"].(string); ok {
						pass = p
					}
				}
			}
		}
	}

	shOb["server"] = server
	if user != "" {
		shOb["username"] = user
	}
	if pass != "" {
		shOb["password"] = pass
	}

	if portRaw != nil {
		switch v := portRaw.(type) {
		case float64:
			shOb["server_port"] = int(v)
		case int:
			shOb["server_port"] = v
		case string:
			vTrim := strings.TrimSpace(v)
			var pInt int
			for _, c := range vTrim {
				if c >= '0' && c <= '9' {
					pInt = pInt*10 + int(c-'0')
				}
			}
			if pInt > 0 {
				shOb["server_port"] = pInt
			}
		}
	}

	applyRawTLSAndTransport(shOb, sMap, tsMap, server)
	return shOb
}
