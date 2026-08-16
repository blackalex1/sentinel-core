package xray

import (
	"github.com/blackalex1/sentinel-core/pkg/ast"
)

// buildXrayStreamSettings constructs the Xray streamSettings object (transport, TLS, Reality).
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
	switch fp {
	case "chrome", "firefox", "safari", "ios", "edge", "qq", "360", "random", "randomized":
		// valid for xray
	default:
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
