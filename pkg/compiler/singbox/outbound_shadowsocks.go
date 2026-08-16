package singbox

import (
	"strings"

	"github.com/blackalex1/sentinel-core/pkg/ast"
)

// buildShadowsocksOutbound compiles an ast.ServerProfile into a Sing-box Shadowsocks outbound object.
func buildShadowsocksOutbound(tag string, node *ast.ServerProfile) (map[string]interface{}, error) {
	method := "2022-blake3-aes-128-gcm"
	if node.Cipher != "" {
		method = node.Cipher
	}

	return map[string]interface{}{
		"type":        "shadowsocks",
		"tag":         tag,
		"server":      node.Address,
		"server_port": node.Port,
		"method":      method,
		"password":    node.Password,
		"network":     "tcp",
	}, nil
}

// compileRawShadowsocksOutbound compiles raw dictionaries into a Sing-box Shadowsocks outbound object.
func compileRawShadowsocksOutbound(tag string, sMap, tsMap map[string]interface{}) map[string]interface{} {
	ssOb := map[string]interface{}{
		"type":    "shadowsocks",
		"tag":     tag,
		"network": "tcp",
	}

	var server string
	var portRaw interface{}
	var password string
	var method string = "2022-blake3-aes-128-gcm"

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

		if m, ok := sMap["method"].(string); ok && m != "" {
			method = m
		} else if m, ok := sMap["cipher"].(string); ok && m != "" {
			method = m
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
				if method == "2022-blake3-aes-128-gcm" {
					if m, ok := firstSrv["method"].(string); ok && m != "" {
						method = m
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
			if method == "2022-blake3-aes-128-gcm" {
				if m, ok := firstSrv["method"].(string); ok && m != "" {
					method = m
				}
			}
		}
	}

	ssOb["server"] = server
	ssOb["password"] = password
	ssOb["method"] = method

	if portRaw != nil {
		switch v := portRaw.(type) {
		case float64:
			ssOb["server_port"] = int(v)
		case int:
			ssOb["server_port"] = v
		case string:
			vTrim := strings.TrimSpace(v)
			var pInt int
			for _, c := range vTrim {
				if c >= '0' && c <= '9' {
					pInt = pInt*10 + int(c-'0')
				}
			}
			if pInt > 0 {
				ssOb["server_port"] = pInt
			}
		}
	}

	return ssOb
}
