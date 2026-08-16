package xray

import (
	"fmt"
	"strings"
	"github.com/blackalex1/sentinel-core/pkg/ast"
)

// BuildXrayOutbound converts an ast.ServerProfile into an Xray JSON outbound structure.
func BuildXrayOutbound(node *ast.ServerProfile) (map[string]interface{}, error) {
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
		return buildXrayVLESSOutbound(tag, node)
	case ast.ProtoVMess:
		return buildXrayVMessOutbound(tag, node)
	case ast.ProtoTrojan:
		return buildXrayTrojanOutbound(tag, node)
	case ast.ProtoShadowsocks:
		return buildXrayShadowsocksOutbound(tag, node)
	case ast.ProtoWireGuard:
		return buildXrayWireGuardOutbound(tag, node)
	case ast.ProtoHysteria2:
		return buildXrayHysteria2Outbound(tag, node)
	case ast.ProtoDirect:
		return map[string]interface{}{"protocol": "freedom", "tag": tag}, nil
	case ast.ProtoBlock:
		return map[string]interface{}{"protocol": "blackhole", "tag": tag}, nil
	default:
		return nil, fmt.Errorf("unsupported protocol for xray-core outbound: %s", proto)
	}
}

func buildXrayVLESSOutbound(tag string, node *ast.ServerProfile) (map[string]interface{}, error) {
	enc := "none"
	if node.Encryption != "" {
		enc = node.Encryption
	}

	vnext := []map[string]interface{}{
		{
			"address": node.Address,
			"port":    node.Port,
			"users": []map[string]interface{}{
				{
					"id":         node.UUID,
					"encryption": enc,
					"flow":       node.Flow,
				},
			},
		},
	}

	streamSettings := buildXrayStreamSettings(node)

	return map[string]interface{}{
		"protocol": "vless",
		"tag":      tag,
		"settings": map[string]interface{}{
			"vnext": vnext,
		},
		"streamSettings": streamSettings,
	}, nil
}

func buildXrayVMessOutbound(tag string, node *ast.ServerProfile) (map[string]interface{}, error) {
	vnext := []map[string]interface{}{
		{
			"address": node.Address,
			"port":    node.Port,
			"users": []map[string]interface{}{
				{
					"id":       node.UUID,
					"alterId":  0,
					"security": "auto",
				},
			},
		},
	}

	streamSettings := buildXrayStreamSettings(node)

	return map[string]interface{}{
		"protocol": "vmess",
		"tag":      tag,
		"settings": map[string]interface{}{
			"vnext": vnext,
		},
		"streamSettings": streamSettings,
	}, nil
}

func buildXrayTrojanOutbound(tag string, node *ast.ServerProfile) (map[string]interface{}, error) {
	servers := []map[string]interface{}{
		{
			"address":  node.Address,
			"port":     node.Port,
			"password": node.Password,
		},
	}

	streamSettings := buildXrayStreamSettings(node)

	return map[string]interface{}{
		"protocol": "trojan",
		"tag":      tag,
		"settings": map[string]interface{}{
			"servers": servers,
		},
		"streamSettings": streamSettings,
	}, nil
}

func buildXrayShadowsocksOutbound(tag string, node *ast.ServerProfile) (map[string]interface{}, error) {
	cipher := node.Cipher
	if cipher == "" {
		cipher = "2022-blake3-aes-128-gcm"
	}
	servers := []map[string]interface{}{
		{
			"address":  node.Address,
			"port":     node.Port,
			"method":   cipher,
			"password": node.Password,
		},
	}

	return map[string]interface{}{
		"protocol": "shadowsocks",
		"tag":      tag,
		"settings": map[string]interface{}{
			"servers": servers,
		},
	}, nil
}

func buildXrayWireGuardOutbound(tag string, node *ast.ServerProfile) (map[string]interface{}, error) {
	peers := []map[string]interface{}{
		{
			"publicKey": node.PeerPublicKey,
			"endpoint":  fmt.Sprintf("%s:%d", node.Address, node.Port),
		},
	}
	if node.PreSharedKey != "" {
		peers[0]["preSharedKey"] = node.PreSharedKey
	}

	return map[string]interface{}{
		"protocol": "wireguard",
		"tag":      tag,
		"settings": map[string]interface{}{
			"secretKey": node.PrivateKey,
			"address":   node.LocalAddress,
			"peers":     peers,
			"mtu":       node.MTU,
		},
	}, nil
}

func buildXrayStreamSettings(node *ast.ServerProfile) map[string]interface{} {
	network := node.Transport
	if network == "" {
		network = "tcp"
	}

	stream := map[string]interface{}{
		"network": network,
	}

	// Security: none, tls, reality
	security := node.Security
	if security == "" {
		if node.PublicKey != "" {
			security = "reality"
		} else if node.SNI != "" || node.Insecure {
			security = "tls"
		} else {
			security = "none"
		}
	}
	stream["security"] = security

	fp := node.Fingerprint
	if fp == "" {
		fp = "chrome"
	}

	if security == "reality" {
		realitySettings := map[string]interface{}{
			"show":        false,
			"fingerprint": fp,
			"serverName":  node.SNI,
			"publicKey":   node.PublicKey,
			"shortId":     node.ShortID,
			"spiderX":     node.SpiderX,
		}
		if node.PostQuantum {
			// Explicitly inject Post-Quantum hybrid curves into reality / TLS settings
			realitySettings["curves"] = []string{"X25519Kyber768Draft00", "X25519"}
		}
		stream["realitySettings"] = realitySettings
	} else if security == "tls" {
		tlsSettings := map[string]interface{}{
			"allowInsecure": node.Insecure,
			"fingerprint":   fp,
			"serverName":    node.SNI,
		}
		if len(node.ALPN) > 0 {
			tlsSettings["alpn"] = node.ALPN
		}
		if node.PostQuantum {
			tlsSettings["curves"] = []string{"X25519Kyber768Draft00", "X25519"}
		}
		stream["tlsSettings"] = tlsSettings
	}

	// Transport settings (gRPC, WS, xHTTP)
	switch network {
	case "grpc":
		serviceName := node.ServiceName
		if serviceName == "" {
			serviceName = node.Path
		}
		stream["grpcSettings"] = map[string]interface{}{
			"serviceName": serviceName,
			"multiMode":   true,
		}
	case "ws":
		wsSettings := map[string]interface{}{
			"path": node.Path,
		}
		if node.Host != "" {
			wsSettings["headers"] = map[string]interface{}{
				"Host": node.Host,
			}
		}
		stream["wsSettings"] = wsSettings
	case "xhttp", "splithttp":
		stream["xhttpSettings"] = map[string]interface{}{
			"path": node.Path,
			"host": node.Host,
			"mode": "auto",
		}
	}

	return stream
}

func buildXrayHysteria2Outbound(tag string, node *ast.ServerProfile) (map[string]interface{}, error) {
	// Xray connects to local Hysteria 2 client instance via SOCKS5 loopback
	localPort := 10808
	localHost := "127.0.0.1"
	if node.Address == "127.0.0.1" && node.Port > 0 {
		localPort = node.Port
	}
	return map[string]interface{}{
		"protocol": "socks",
		"tag":      tag,
		"settings": map[string]interface{}{
			"servers": []map[string]interface{}{
				{
					"address": localHost,
					"port":    localPort,
				},
			},
		},
	}, nil
}
