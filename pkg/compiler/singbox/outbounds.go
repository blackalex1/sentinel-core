package singbox

import (
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
