package singbox

import (
	"strings"

	"github.com/blackalex1/sentinel-core/pkg/ast"
)

// buildHysteria2Outbound compiles an ast.ServerProfile into a Sing-box Hysteria 2 outbound object.
func buildHysteria2Outbound(tag string, node *ast.ServerProfile) (map[string]interface{}, error) {
	authPass := node.Password
	if node.Username != "" && node.Password != "" {
		authPass = node.Username + ":" + node.Password
	} else if node.Password == "" && node.Username != "" {
		authPass = node.Username
	}

	out := map[string]interface{}{
		"type":     "hysteria2",
		"tag":      tag,
		"server":   node.Address,
		"password": authPass,
	}

	if node.PortHopping != "" {
		if strings.Contains(node.PortHopping, "-") || strings.Contains(node.PortHopping, ",") || strings.Contains(node.PortHopping, ":") {
			parts := strings.Split(node.PortHopping, ",")
			var ports []string
			for _, p := range parts {
				trimmed := strings.TrimSpace(p)
				if trimmed != "" {
					// Normalize 40000-50000 into 40000:50000
					normalized := strings.ReplaceAll(trimmed, "-", ":")
					ports = append(ports, normalized)
				}
			}
			if len(ports) > 0 {
				out["server_ports"] = ports
				hopInterval := "300s"
				if node.Extra != nil {
					if val, ok := node.Extra["hop_interval"].(string); ok && val != "" {
						hopInterval = val
					}
				}
				out["hop_interval"] = hopInterval
			}
		} else {
			var pInt int
			for _, c := range strings.TrimSpace(node.PortHopping) {
				if c >= '0' && c <= '9' {
					pInt = pInt*10 + int(c-'0')
				}
			}
			if pInt > 0 {
				out["server_port"] = pInt
			} else {
				out["server_port"] = node.Port
			}
		}
	} else {
		out["server_port"] = node.Port
	}

	if node.BandwidthUp != "" {
		out["up_mbps"] = parseBandwidth(node.BandwidthUp)
	}
	if node.BandwidthDown != "" {
		out["down_mbps"] = parseBandwidth(node.BandwidthDown)
	}

	if node.ObfsType != "" {
		out["obfs"] = map[string]interface{}{
			"type":     node.ObfsType,
			"password": node.ObfsPassword,
		}
	}

	// TLS Settings (QUIC/UDP protocols like Hysteria 2 do NOT support uTLS in sing-box)
	tlsMap := buildSingBoxTLS(node)
	if tlsMap != nil {
		delete(tlsMap, "utls")
		out["tls"] = tlsMap
	} else {
		// Hysteria 2 always requires TLS enabled in sing-box
		tlsMap = map[string]interface{}{
			"enabled": true,
		}
		if node.SNI != "" {
			tlsMap["server_name"] = node.SNI
		}
		if node.Insecure {
			tlsMap["insecure"] = true
		}
		out["tls"] = tlsMap
	}

	return out, nil
}

// compileRawHysteria2Outbound compiles a raw settings/streamSettings dictionary into a Sing-box Hysteria 2 outbound object.
func compileRawHysteria2Outbound(tag string, sMap, tsMap map[string]interface{}) map[string]interface{} {
	hyOb := map[string]interface{}{
		"type": "hysteria2",
		"tag":  tag,
	}

	server, portRaw, password := extractRawHysteria2Base(hyOb, sMap, tsMap)
	hyOb["server"] = server
	if password != "" {
		hyOb["password"] = password
	}
	applyRawHysteria2Ports(hyOb, portRaw)
	hyOb["tls"] = buildRawHysteria2TLS(server, sMap, tsMap)
	return hyOb
}

func extractRawHysteria2Base(hyOb, sMap, tsMap map[string]interface{}) (server string, portRaw interface{}, password string) {
	if sMap != nil {
		server = firstMapStr(sMap, "server", "address", "host")
		portRaw = firstMapVal(sMap, "port", "server_port", "port_hopping", "hop")
		password = firstMapStr(sMap, "password", "auth", "auth_str", "uuid")

		extractFromVnextOrServers(sMap, &server, &portRaw, &password)
		applyRawHysteria2Obfs(hyOb, sMap)

		if up, ok := sMap["up_mbps"]; ok {
			hyOb["up_mbps"] = up
		}
		if down, ok := sMap["down_mbps"]; ok {
			hyOb["down_mbps"] = down
		}
	}

	if tsMap != nil {
		if hySettings, ok := tsMap["hysteriaSettings"].(map[string]interface{}); ok {
			if portRaw == nil {
				if hop, ok := hySettings["hop"]; ok {
					portRaw = hop
				}
			}
			if password == "" {
				password = firstMapStr(hySettings, "auth", "password")
			}
		}
	}
	return server, portRaw, password
}

func firstMapStr(m map[string]interface{}, keys ...string) string {
	for _, k := range keys {
		if s, ok := m[k].(string); ok && s != "" {
			return s
		}
	}
	return ""
}

func firstMapVal(m map[string]interface{}, keys ...string) interface{} {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			return v
		}
	}
	return nil
}

func extractFromVnextOrServers(sMap map[string]interface{}, server *string, portRaw *interface{}, password *string) {
	if vnextRaw, ok := sMap["vnext"].([]interface{}); ok && len(vnextRaw) > 0 {
		if firstVnext, ok := vnextRaw[0].(map[string]interface{}); ok {
			if *server == "" {
				*server, _ = firstVnext["address"].(string)
			}
			if *portRaw == nil {
				*portRaw = firstVnext["port"]
			}
			if *password == "" {
				if usersRaw, ok := firstVnext["users"].([]interface{}); ok && len(usersRaw) > 0 {
					if firstUser, ok := usersRaw[0].(map[string]interface{}); ok {
						*password = firstMapStr(firstUser, "password", "id")
					}
				}
			}
		}
	}
	if serversRaw, ok := sMap["servers"].([]interface{}); ok && len(serversRaw) > 0 {
		if firstSrv, ok := serversRaw[0].(map[string]interface{}); ok {
			if *server == "" {
				*server = firstMapStr(firstSrv, "address", "server")
			}
			if *portRaw == nil {
				*portRaw = firstMapVal(firstSrv, "port", "server_port")
			}
			if *password == "" {
				*password = firstMapStr(firstSrv, "password", "auth")
			}
		}
	}
}

func applyRawHysteria2Obfs(hyOb, sMap map[string]interface{}) {
	obfsType, _ := sMap["obfs_type"].(string)
	obfsPassword, _ := sMap["obfs_password"].(string)
	if obfsMapRaw, ok := sMap["obfs"].(map[string]interface{}); ok {
		if ot, ok := obfsMapRaw["type"].(string); ok && ot != "" {
			obfsType = ot
		}
		if op, ok := obfsMapRaw["password"].(string); ok && op != "" {
			obfsPassword = op
		}
		if sal, ok := obfsMapRaw["salamander"].(map[string]interface{}); ok {
			if op, ok := sal["password"].(string); ok && op != "" {
				obfsPassword = op
			}
		}
	}
	if obfsType != "" {
		obfsEntry := map[string]interface{}{"type": obfsType}
		if obfsPassword != "" {
			obfsEntry["password"] = obfsPassword
		}
		hyOb["obfs"] = obfsEntry
	}
}

func applyRawHysteria2Ports(hyOb map[string]interface{}, portRaw interface{}) {
	if portRaw == nil {
		return
	}
	switch v := portRaw.(type) {
	case float64:
		hyOb["server_port"] = int(v)
	case int:
		hyOb["server_port"] = v
	case string:
		vTrim := strings.TrimSpace(v)
		if strings.Contains(vTrim, "-") || strings.Contains(vTrim, ",") || strings.Contains(vTrim, ":") {
			var ports []string
			for _, p := range strings.Split(vTrim, ",") {
				if pClean := strings.TrimSpace(p); pClean != "" {
					ports = append(ports, strings.ReplaceAll(pClean, "-", ":"))
				}
			}
			if len(ports) > 0 {
				hyOb["server_ports"] = ports
				hyOb["hop_interval"] = "300s"
			}
			return
		}
		var pInt int
		for _, c := range vTrim {
			if c >= '0' && c <= '9' {
				pInt = pInt*10 + int(c-'0')
			}
		}
		if pInt > 0 {
			hyOb["server_port"] = pInt
		}
	}
}

func buildRawHysteria2TLS(server string, sMap, tsMap map[string]interface{}) map[string]interface{} {
	tlsMap := map[string]interface{}{"enabled": true}
	if tsMap != nil {
		if tlsSettings, ok := tsMap["tlsSettings"].(map[string]interface{}); ok {
			if sn, ok := tlsSettings["serverName"].(string); ok && sn != "" {
				tlsMap["server_name"] = sn
			}
			if allowInsecure, ok := tlsSettings["allowInsecure"].(bool); ok && allowInsecure {
				tlsMap["insecure"] = true
			}
			if alpn := extractStringList(tlsSettings["alpn"]); len(alpn) > 0 {
				tlsMap["alpn"] = alpn
			}
		}
		if sName, ok := tsMap["serverName"].(string); ok && sName != "" {
			tlsMap["server_name"] = sName
		}
	}
	if sMap != nil {
		if sn := firstMapStr(sMap, "sni", "server_name"); sn != "" {
			tlsMap["server_name"] = sn
		}
		if insecure, ok := sMap["insecure"].(bool); ok && insecure {
			tlsMap["insecure"] = true
		} else if allowInsecure, ok := sMap["allowInsecure"].(bool); ok && allowInsecure {
			tlsMap["insecure"] = true
		}
	}
	if _, ok := tlsMap["server_name"]; !ok && server != "" {
		tlsMap["server_name"] = server
	}
	return tlsMap
}
