package singbox

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/blackalex1/sentinel-core/pkg/ast"
)

// BuildSingBoxOutbound converts an ast.ServerProfile into a Sing-box JSON outbound object.
func BuildSingBoxOutbound(node *ast.ServerProfile) (map[string]interface{}, error) {
	if node == nil {
		return nil, fmt.Errorf("node profile cannot be nil")
	}

	proto := strings.ToLower(node.Protocol)
	tag := "proxy"
	if node.Name != "" {
		tag = node.Name
	}

	switch proto {
	case ast.ProtoVLESS:
		return buildVLESSOutbound(tag, node)
	case ast.ProtoHysteria2:
		return buildHysteria2Outbound(tag, node)
	case ast.ProtoTrojan:
		return buildTrojanOutbound(tag, node)
	case ast.ProtoShadowsocks:
		return buildShadowsocksOutbound(tag, node)
	case ast.ProtoShadowTLS:
		return buildShadowTLSOutbound(tag, node)
	case ast.ProtoTUIC:
		return buildTUICOutbound(tag, node)
	case ast.ProtoVMess:
		return buildVMessOutbound(tag, node)
	case ast.ProtoWireGuard:
		return buildWireGuardOutbound(tag, node)
	case ast.ProtoDirect:
		return map[string]interface{}{"type": "direct", "tag": tag}, nil
	case ast.ProtoBlock:
		return map[string]interface{}{"type": "block", "tag": tag}, nil
	default:
		return nil, fmt.Errorf("unsupported protocol for sing-box outbound: %s", proto)
	}
}

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

func buildHysteria2Outbound(tag string, node *ast.ServerProfile) (map[string]interface{}, error) {
	out := map[string]interface{}{
		"type":     "hysteria2",
		"tag":      tag,
		"server":   node.Address,
		"password": node.Password,
	}

	if node.PortHopping != "" {
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
			hopInterval := "30s"
			if node.Extra != nil {
				if val, ok := node.Extra["hop_interval"].(string); ok && val != "" {
					hopInterval = val
				}
			}
			out["hop_interval"] = hopInterval
		} else {
			out["server_port"] = node.Port
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

	if node.ObfsPassword != "" {
		obfsType := "salamander"
		if node.ObfsType != "" {
			obfsType = node.ObfsType
		}
		out["obfs"] = map[string]interface{}{
			"type":     obfsType,
			"password": node.ObfsPassword,
		}
	}

	tlsMap := buildSingBoxTLS(node)
	if tlsMap != nil {
		out["tls"] = tlsMap
	}

	return out, nil
}

func buildTrojanOutbound(tag string, node *ast.ServerProfile) (map[string]interface{}, error) {
	out := map[string]interface{}{
		"type":        "trojan",
		"tag":         tag,
		"server":      node.Address,
		"server_port": node.Port,
		"password":    node.Password,
	}

	tlsMap := buildSingBoxTLS(node)
	if tlsMap != nil {
		out["tls"] = tlsMap
	}

	transportMap := buildSingBoxTransport(node)
	if transportMap != nil {
		out["transport"] = transportMap
	}

	return out, nil
}

func buildShadowsocksOutbound(tag string, node *ast.ServerProfile) (map[string]interface{}, error) {
	cipher := node.Cipher
	if cipher == "" {
		cipher = "2022-blake3-aes-128-gcm"
	}
	return map[string]interface{}{
		"type":        "shadowsocks",
		"tag":         tag,
		"server":      node.Address,
		"server_port": node.Port,
		"method":      cipher,
		"password":    node.Password,
	}, nil
}

func buildShadowTLSOutbound(tag string, node *ast.ServerProfile) (map[string]interface{}, error) {
	version := 3
	if node.ShadowTLSVersion > 0 {
		version = node.ShadowTLSVersion
	}
	return map[string]interface{}{
		"type":        "shadowtls",
		"tag":         tag,
		"server":      node.Address,
		"server_port": node.Port,
		"version":     version,
		"password":    node.ShadowTLSPassword,
		"tls": map[string]interface{}{
			"enabled":     true,
			"server_name": node.ShadowTLSSNI,
		},
	}, nil
}

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
		out["congestion_controller"] = node.CongestionControl
	}
	if node.UDPRelayMode != "" {
		out["udp_relay_mode"] = node.UDPRelayMode
	}
	if node.ZeroRTTHandshake {
		out["zero_rtt_handshake"] = true
	}

	tlsMap := buildSingBoxTLS(node)
	if tlsMap != nil {
		out["tls"] = tlsMap
	}

	return out, nil
}

func buildVMessOutbound(tag string, node *ast.ServerProfile) (map[string]interface{}, error) {
	out := map[string]interface{}{
		"type":        "vmess",
		"tag":         tag,
		"server":      node.Address,
		"server_port": node.Port,
		"uuid":        node.UUID,
		"security":    "auto",
	}

	tlsMap := buildSingBoxTLS(node)
	if tlsMap != nil {
		out["tls"] = tlsMap
	}

	transportMap := buildSingBoxTransport(node)
	if transportMap != nil {
		out["transport"] = transportMap
	}

	return out, nil
}

func buildWireGuardOutbound(tag string, node *ast.ServerProfile) (map[string]interface{}, error) {
	out := map[string]interface{}{
		"type":        "wireguard",
		"tag":         tag,
		"server":      node.Address,
		"server_port": node.Port,
		"private_key": node.PrivateKey,
		"peer_public_key": node.PeerPublicKey,
	}
	if node.PreSharedKey != "" {
		out["pre_shared_key"] = node.PreSharedKey
	}
	if len(node.LocalAddress) > 0 {
		out["local_address"] = node.LocalAddress
	}
	if node.MTU > 0 {
		out["mtu"] = node.MTU
	}
	if len(node.ReservedBytes) > 0 {
		out["reserved"] = node.ReservedBytes
	}
	return out, nil
}

func buildSingBoxTLS(node *ast.ServerProfile) map[string]interface{} {
	if node.Security == ast.SecurityNone && node.PublicKey == "" && node.SNI == "" {
		return nil
	}

	tlsMap := map[string]interface{}{
		"enabled": true,
	}

	if node.SNI != "" {
		tlsMap["server_name"] = node.SNI
	}
	if node.Insecure {
		tlsMap["insecure"] = true
	}
	if len(node.ALPN) > 0 {
		tlsMap["alpn"] = node.ALPN
	}

	// Reality settings
	if node.PublicKey != "" || node.Security == ast.SecurityReality {
		realityMap := map[string]interface{}{
			"enabled":    true,
			"public_key": node.PublicKey,
		}
		if node.ShortID != "" {
			realityMap["short_id"] = node.ShortID
		}
		tlsMap["reality"] = realityMap
	}

	// UTLS Fingerprint
	fp := node.Fingerprint
	if fp == "" {
		fp = "chrome"
	}
	tlsMap["utls"] = map[string]interface{}{
		"enabled":     true,
		"fingerprint": fp,
	}

	return tlsMap
}

func buildSingBoxTransport(node *ast.ServerProfile) map[string]interface{} {
	t := strings.ToLower(node.Transport)
	switch t {
	case ast.TransportGRPC:
		serviceName := node.ServiceName
		if serviceName == "" {
			serviceName = node.Path
		}
		return map[string]interface{}{
			"type":         "grpc",
			"service_name": serviceName,
		}
	case ast.TransportWS:
		wsMap := map[string]interface{}{
			"type": "ws",
		}
		if node.Path != "" {
			wsMap["path"] = node.Path
		}
		if node.Host != "" {
			wsMap["headers"] = map[string]interface{}{
				"Host": node.Host,
			}
		}
		return wsMap
	case ast.TransportHTTPUpgrade:
		return map[string]interface{}{
			"type": "httpupgrade",
			"path": node.Path,
			"host": node.Host,
		}
	default:
		return nil
	}
}

func parseBandwidth(s string) int {
	clean := strings.TrimSpace(strings.ToLower(s))
	clean = strings.TrimSuffix(clean, "mbps")
	clean = strings.TrimSuffix(clean, "mb")
	clean = strings.TrimSpace(clean)
	var val int
	_, _ = fmt.Sscanf(clean, "%d", &val)
	if val <= 0 {
		return 100
	}
	return val
}

// CompileRawOutboundToSingbox converts a generic/DB outbound map into a Sing-box outbound configuration.
func CompileRawOutboundToSingbox(ob map[string]interface{}) map[string]interface{} {
	tag, _ := ob["tag"].(string)
	if tag == "" {
		tag = "proxy"
	}
	proto, _ := ob["protocol"].(string)
	proto = strings.ToLower(strings.TrimSpace(proto))

	var sMap map[string]interface{}
	if sm, ok := ob["settings"].(map[string]interface{}); ok {
		sMap = sm
	} else if smStr, ok := ob["settings"].(string); ok && smStr != "" {
		_ = json.Unmarshal([]byte(smStr), &sMap)
	}

	var tsMap map[string]interface{}
	if tsm, ok := ob["stream_settings"].(map[string]interface{}); ok {
		tsMap = tsm
	} else if tsm, ok := ob["streamSettings"].(map[string]interface{}); ok {
		tsMap = tsm
	} else if tsmStr, ok := ob["stream_settings"].(string); ok && tsmStr != "" {
		_ = json.Unmarshal([]byte(tsmStr), &tsMap)
	} else if tsmStr, ok := ob["streamSettings"].(string); ok && tsmStr != "" {
		_ = json.Unmarshal([]byte(tsmStr), &tsMap)
	}

	switch proto {
	case "freedom", "direct":
		return map[string]interface{}{"type": "direct", "tag": tag}
	case "blackhole", "block":
		return map[string]interface{}{"type": "block", "tag": tag}
	case "hysteria2", "hysteria":
		return compileRawHysteria2Outbound(tag, sMap, tsMap)
	case "vless":
		return compileRawVLESSOutbound(tag, sMap, tsMap)
	case "vmess":
		return compileRawVMessOutbound(tag, sMap, tsMap)
	case "trojan":
		return compileRawTrojanOutbound(tag, sMap, tsMap)
	case "shadowsocks":
		return compileRawShadowsocksOutbound(tag, sMap, tsMap)
	case "wireguard":
		return compileRawWireguardOutbound(tag, sMap, tsMap)
	case "socks", "http":
		return compileRawSocksHttpOutbound(tag, proto, sMap, tsMap)
	default:
		return map[string]interface{}{"type": "direct", "tag": tag}
	}
}

func compileRawHysteria2Outbound(tag string, sMap, tsMap map[string]interface{}) map[string]interface{} {
	hyOb := map[string]interface{}{
		"type": "hysteria2",
		"tag":  tag,
	}

	server := ""
	var portRaw interface{}
	password := ""

	if sMap != nil {
		if srv, ok := sMap["address"].(string); ok && srv != "" {
			server = srv
		} else if srv, ok := sMap["server"].(string); ok && srv != "" {
			server = srv
		}

		if p, ok := sMap["port"]; ok && p != nil {
			portRaw = p
		} else if p, ok := sMap["server_port"]; ok && p != nil {
			portRaw = p
		} else if p, ok := sMap["port_hopping"]; ok && p != nil {
			portRaw = p
		}

		if pwd, ok := sMap["password"].(string); ok && pwd != "" {
			password = pwd
		} else if pwd, ok := sMap["auth"].(string); ok && pwd != "" {
			password = pwd
		} else if pwd, ok := sMap["auth_str"].(string); ok && pwd != "" {
			password = pwd
		} else if pwd, ok := sMap["auth_password"].(string); ok && pwd != "" {
			password = pwd
		}

		if servers, ok := sMap["servers"].([]interface{}); ok && len(servers) > 0 {
			if firstSrv, ok := servers[0].(map[string]interface{}); ok {
				if server == "" {
					if srv, ok := firstSrv["address"].(string); ok {
						server = srv
					} else if srv, ok := firstSrv["server"].(string); ok {
						server = srv
					}
				}
				if portRaw == nil {
					if p, ok := firstSrv["port"]; ok {
						portRaw = p
					} else if p, ok := firstSrv["server_port"]; ok {
						portRaw = p
					}
				}
				if password == "" {
					if pwd, ok := firstSrv["password"].(string); ok {
						password = pwd
					} else if pwd, ok := firstSrv["auth"].(string); ok {
						password = pwd
					}
				}
			}
		}

		if obfsType, ok := sMap["obfs_type"].(string); ok && obfsType != "" {
			obfsMap := map[string]interface{}{
				"type": obfsType,
			}
			if obfsPwd, ok := sMap["obfs_password"].(string); ok && obfsPwd != "" {
				obfsMap["password"] = obfsPwd
			}
			hyOb["obfs"] = obfsMap
		} else if obfsMapRaw, ok := sMap["obfs"].(map[string]interface{}); ok {
			hyOb["obfs"] = obfsMapRaw
		}

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
				if pwd, ok := hySettings["auth"].(string); ok {
					password = pwd
				} else if pwd, ok := hySettings["password"].(string); ok {
					password = pwd
				}
			}
		}
	}

	hyOb["server"] = server
	if password != "" {
		hyOb["password"] = password
	}

	// Port or Port Hopping / Server Ports
	if portRaw != nil {
		switch v := portRaw.(type) {
		case float64:
			hyOb["server_port"] = int(v)
		case int:
			hyOb["server_port"] = v
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
					hyOb["server_ports"] = ports
					hyOb["hop_interval"] = "30s"
				}
			} else {
				var pInt int
				if _, err := fmt.Sscanf(vTrim, "%d", &pInt); err == nil && pInt > 0 {
					hyOb["server_port"] = pInt
				} else {
					hyOb["server_port"] = 443
				}
			}
		}
	} else {
		hyOb["server_port"] = 443
	}

	// TLS
	tlsObj := map[string]interface{}{
		"enabled": true,
	}
	if tsMap != nil {
		if tlsSettings, ok := tsMap["tlsSettings"].(map[string]interface{}); ok {
			if sn, ok := tlsSettings["serverName"].(string); ok && sn != "" {
				tlsObj["server_name"] = sn
			}
			if insec, ok := tlsSettings["allowInsecure"].(bool); ok {
				tlsObj["insecure"] = insec
			}
		}
	}
	if _, ok := tlsObj["server_name"]; !ok {
		if sMap != nil {
			if sn, ok := sMap["server_name"].(string); ok && sn != "" {
				tlsObj["server_name"] = sn
			}
		}
	}
	if _, ok := tlsObj["server_name"]; !ok {
		if server != "" && !strings.Contains(server, ":") {
			tlsObj["server_name"] = server
		}
		tlsObj["insecure"] = true
	}
	hyOb["tls"] = tlsObj

	return hyOb
}

func compileRawVLESSOutbound(tag string, sMap, tsMap map[string]interface{}) map[string]interface{} {
	out := map[string]interface{}{
		"type": "vless",
		"tag":  tag,
	}
	server := ""
	serverPort := 443
	uuid := ""
	flow := ""

	if sMap != nil {
		if s, ok := sMap["address"].(string); ok {
			server = s
		} else if s, ok := sMap["server"].(string); ok {
			server = s
		}
		if p, ok := sMap["port"].(float64); ok {
			serverPort = int(p)
		} else if p, ok := sMap["port"].(int); ok {
			serverPort = p
		}
		if u, ok := sMap["uuid"].(string); ok {
			uuid = u
		} else if u, ok := sMap["id"].(string); ok {
			uuid = u
		}
		if f, ok := sMap["flow"].(string); ok {
			flow = f
		}
		if vnext, ok := sMap["vnext"].([]interface{}); ok && len(vnext) > 0 {
			if firstVn, ok := vnext[0].(map[string]interface{}); ok {
				if server == "" {
					server, _ = firstVn["address"].(string)
				}
				if p, ok := firstVn["port"].(float64); ok && p > 0 {
					serverPort = int(p)
				} else if p, ok := firstVn["port"].(int); ok && p > 0 {
					serverPort = p
				}
				if users, ok := firstVn["users"].([]interface{}); ok && len(users) > 0 {
					if firstU, ok := users[0].(map[string]interface{}); ok {
						if uuid == "" {
							uuid, _ = firstU["id"].(string)
						}
						if flow == "" {
							flow, _ = firstU["flow"].(string)
						}
					}
				}
			}
		}
	}

	out["server"] = server
	out["server_port"] = serverPort
	out["uuid"] = uuid
	if flow != "" {
		out["flow"] = flow
	}

	applyRawTLSAndTransport(out, sMap, tsMap, server)
	return out
}

func compileRawVMessOutbound(tag string, sMap, tsMap map[string]interface{}) map[string]interface{} {
	out := map[string]interface{}{
		"type":     "vmess",
		"tag":      tag,
		"security": "auto",
	}
	server := ""
	serverPort := 443
	uuid := ""

	if sMap != nil {
		if s, ok := sMap["address"].(string); ok {
			server = s
		}
		if p, ok := sMap["port"].(float64); ok {
			serverPort = int(p)
		} else if p, ok := sMap["port"].(int); ok {
			serverPort = p
		}
		if u, ok := sMap["uuid"].(string); ok {
			uuid = u
		} else if u, ok := sMap["id"].(string); ok {
			uuid = u
		}
		if vnext, ok := sMap["vnext"].([]interface{}); ok && len(vnext) > 0 {
			if firstVn, ok := vnext[0].(map[string]interface{}); ok {
				if server == "" {
					server, _ = firstVn["address"].(string)
				}
				if p, ok := firstVn["port"].(float64); ok && p > 0 {
					serverPort = int(p)
				} else if p, ok := firstVn["port"].(int); ok && p > 0 {
					serverPort = p
				}
				if users, ok := firstVn["users"].([]interface{}); ok && len(users) > 0 {
					if firstU, ok := users[0].(map[string]interface{}); ok {
						if uuid == "" {
							uuid, _ = firstU["id"].(string)
						}
					}
				}
			}
		}
	}

	out["server"] = server
	out["server_port"] = serverPort
	out["uuid"] = uuid

	applyRawTLSAndTransport(out, sMap, tsMap, server)
	return out
}

func compileRawTrojanOutbound(tag string, sMap, tsMap map[string]interface{}) map[string]interface{} {
	out := map[string]interface{}{
		"type": "trojan",
		"tag":  tag,
	}
	server := ""
	serverPort := 443
	password := ""

	if sMap != nil {
		if s, ok := sMap["address"].(string); ok {
			server = s
		}
		if p, ok := sMap["port"].(float64); ok {
			serverPort = int(p)
		} else if p, ok := sMap["port"].(int); ok {
			serverPort = p
		}
		if pwd, ok := sMap["password"].(string); ok {
			password = pwd
		}
		if servers, ok := sMap["servers"].([]interface{}); ok && len(servers) > 0 {
			if firstSrv, ok := servers[0].(map[string]interface{}); ok {
				if server == "" {
					server, _ = firstSrv["address"].(string)
				}
				if p, ok := firstSrv["port"].(float64); ok && p > 0 {
					serverPort = int(p)
				} else if p, ok := firstSrv["port"].(int); ok && p > 0 {
					serverPort = p
				}
				if password == "" {
					password, _ = firstSrv["password"].(string)
				}
			}
		}
	}

	out["server"] = server
	out["server_port"] = serverPort
	out["password"] = password

	applyRawTLSAndTransport(out, sMap, tsMap, server)
	return out
}

func compileRawShadowsocksOutbound(tag string, sMap, tsMap map[string]interface{}) map[string]interface{} {
	out := map[string]interface{}{
		"type":   "shadowsocks",
		"tag":    tag,
		"method": "aes-256-gcm",
	}
	server := ""
	serverPort := 8388
	password := ""

	if sMap != nil {
		if s, ok := sMap["address"].(string); ok {
			server = s
		}
		if p, ok := sMap["port"].(float64); ok {
			serverPort = int(p)
		} else if p, ok := sMap["port"].(int); ok {
			serverPort = p
		}
		if m, ok := sMap["method"].(string); ok && m != "" {
			out["method"] = m
		}
		if pwd, ok := sMap["password"].(string); ok {
			password = pwd
		}
		if servers, ok := sMap["servers"].([]interface{}); ok && len(servers) > 0 {
			if firstSrv, ok := servers[0].(map[string]interface{}); ok {
				if server == "" {
					server, _ = firstSrv["address"].(string)
				}
				if p, ok := firstSrv["port"].(float64); ok && p > 0 {
					serverPort = int(p)
				} else if p, ok := firstSrv["port"].(int); ok && p > 0 {
					serverPort = p
				}
				if m, ok := firstSrv["method"].(string); ok && m != "" {
					out["method"] = m
				}
				if password == "" {
					password, _ = firstSrv["password"].(string)
				}
			}
		}
	}

	out["server"] = server
	out["server_port"] = serverPort
	out["password"] = password
	return out
}

func compileRawWireguardOutbound(tag string, sMap, tsMap map[string]interface{}) map[string]interface{} {
	out := map[string]interface{}{
		"type": "wireguard",
		"tag":  tag,
	}
	if sMap != nil {
		if s, ok := sMap["address"].(string); ok {
			out["server"] = s
		}
		if p, ok := sMap["port"].(float64); ok {
			out["server_port"] = int(p)
		} else if p, ok := sMap["port"].(int); ok {
			out["server_port"] = p
		}
		if pk, ok := sMap["private_key"].(string); ok {
			out["private_key"] = pk
		} else if pk, ok := sMap["secret_key"].(string); ok {
			out["private_key"] = pk
		}
		if ppk, ok := sMap["peer_public_key"].(string); ok {
			out["peer_public_key"] = ppk
		} else if ppk, ok := sMap["public_key"].(string); ok {
			out["peer_public_key"] = ppk
		}
		if psk, ok := sMap["pre_shared_key"].(string); ok {
			out["pre_shared_key"] = psk
		}
		if la, ok := sMap["local_address"].([]interface{}); ok {
			out["local_address"] = la
		}
	}
	return out
}

func compileRawSocksHttpOutbound(tag, proto string, sMap, tsMap map[string]interface{}) map[string]interface{} {
	out := map[string]interface{}{
		"type": proto,
		"tag":  tag,
	}
	if sMap != nil {
		if s, ok := sMap["address"].(string); ok {
			out["server"] = s
		}
		if p, ok := sMap["port"].(float64); ok {
			out["server_port"] = int(p)
		} else if p, ok := sMap["port"].(int); ok {
			out["server_port"] = p
		}
		if u, ok := sMap["username"].(string); ok {
			out["username"] = u
		}
		if pwd, ok := sMap["password"].(string); ok {
			out["password"] = pwd
		}
		if servers, ok := sMap["servers"].([]interface{}); ok && len(servers) > 0 {
			if firstSrv, ok := servers[0].(map[string]interface{}); ok {
				if out["server"] == nil || out["server"] == "" {
					out["server"], _ = firstSrv["address"].(string)
				}
				if out["server_port"] == nil {
					if p, ok := firstSrv["port"].(float64); ok && p > 0 {
						out["server_port"] = int(p)
					} else if p, ok := firstSrv["port"].(int); ok && p > 0 {
						out["server_port"] = p
					}
				}
				if users, ok := firstSrv["users"].([]interface{}); ok && len(users) > 0 {
					if firstU, ok := users[0].(map[string]interface{}); ok {
						if u, ok := firstU["user"].(string); ok {
							out["username"] = u
						}
						if pwd, ok := firstU["pass"].(string); ok {
							out["password"] = pwd
						}
					}
				}
			}
		}
	}
	return out
}

func applyRawTLSAndTransport(out, sMap, tsMap map[string]interface{}, defaultServerName string) {
	if tsMap == nil {
		return
	}
	sec, _ := tsMap["security"].(string)
	net, _ := tsMap["network"].(string)

	if sec == "tls" || sec == "reality" {
		tlsObj := map[string]interface{}{
			"enabled": true,
		}
		if tlsSettings, ok := tsMap["tlsSettings"].(map[string]interface{}); ok {
			if sn, ok := tlsSettings["serverName"].(string); ok && sn != "" {
				tlsObj["server_name"] = sn
			}
			if insec, ok := tlsSettings["allowInsecure"].(bool); ok {
				tlsObj["insecure"] = insec
			}
			if alpn, ok := tlsSettings["alpn"].([]interface{}); ok {
				tlsObj["alpn"] = alpn
			}
			if fp, ok := tlsSettings["fingerprint"].(string); ok && fp != "" {
				tlsObj["utls"] = map[string]interface{}{
					"enabled":     true,
					"fingerprint": fp,
				}
			}
		}
		if sec == "reality" {
			if realitySettings, ok := tsMap["realitySettings"].(map[string]interface{}); ok {
				rMap := map[string]interface{}{
					"enabled": true,
				}
				if pbk, ok := realitySettings["publicKey"].(string); ok {
					rMap["public_key"] = pbk
				}
				if sid, ok := realitySettings["shortId"].(string); ok {
					rMap["short_id"] = sid
				}
				tlsObj["reality"] = rMap
				if sn, ok := realitySettings["serverName"].(string); ok && sn != "" {
					tlsObj["server_name"] = sn
				}
				if fp, ok := realitySettings["fingerprint"].(string); ok && fp != "" {
					tlsObj["utls"] = map[string]interface{}{
						"enabled":     true,
						"fingerprint": fp,
					}
				}
			}
		}
		if _, ok := tlsObj["server_name"]; !ok && defaultServerName != "" {
			tlsObj["server_name"] = defaultServerName
		}
		out["tls"] = tlsObj
	}

	switch net {
	case "ws":
		wsMap := map[string]interface{}{
			"type": "ws",
		}
		if wsSettings, ok := tsMap["wsSettings"].(map[string]interface{}); ok {
			if path, ok := wsSettings["path"].(string); ok {
				wsMap["path"] = path
			}
			if headers, ok := wsSettings["headers"].(map[string]interface{}); ok {
				wsMap["headers"] = headers
			}
		}
		out["transport"] = wsMap
	case "grpc":
		grpcMap := map[string]interface{}{
			"type": "grpc",
		}
		if grpcSettings, ok := tsMap["grpcSettings"].(map[string]interface{}); ok {
			if sn, ok := grpcSettings["serviceName"].(string); ok {
				grpcMap["service_name"] = sn
			}
		}
		out["transport"] = grpcMap
	case "httpupgrade":
		huMap := map[string]interface{}{
			"type": "httpupgrade",
		}
		if huSettings, ok := tsMap["httpupgradeSettings"].(map[string]interface{}); ok {
			if path, ok := huSettings["path"].(string); ok {
				huMap["path"] = path
			}
			if host, ok := huSettings["host"].(string); ok {
				huMap["host"] = host
			}
		}
		out["transport"] = huMap
	}
}

