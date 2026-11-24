package xray

import (
	"github.com/blackalex1/sentinel-core/pkg/ast"
	"github.com/blackalex1/sentinel-core/pkg/crypto"
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
	case "chrome", "firefox", "safari", "ios", "android", "edge", "qq", "360", "random", "randomized":
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
			realitySettings["curves"] = crypto.DefaultPostQuantumCurves()
		}
		stream["realitySettings"] = realitySettings
	} else if security == "tls" {
		tlsSettings := map[string]interface{}{
			"fingerprint": fp,
			"serverName":  node.SNI,
		}
		if len(node.ALPN) > 0 {
			tlsSettings["alpn"] = node.ALPN
		}
		if node.PinnedPeerCertSha256 != "" {
			tlsSettings["pinnedPeerCertSha256"] = node.PinnedPeerCertSha256
		}
		if node.PostQuantum {
			tlsSettings["curves"] = crypto.DefaultPostQuantumCurves()
		}
		stream["tlsSettings"] = tlsSettings
	}

	// Transport settings (TCP HTTP header, gRPC, WS, HTTPUpgrade, H2, xHTTP)
	switch network {
	case "tcp":
		if node.HeaderType == "http" {
			tcpReq := map[string]interface{}{
				"version": "1.1",
				"method":  "GET",
				"path":    []string{firstNonEmpty(node.Path, "/")},
			}
			if node.Host != "" {
				tcpReq["headers"] = map[string]interface{}{
					"Host": []string{node.Host},
				}
			}
			stream["tcpSettings"] = map[string]interface{}{
				"header": map[string]interface{}{
					"type":    "http",
					"request": tcpReq,
				},
			}
		}
	case "grpc":
		serviceName := node.ServiceName
		if serviceName == "" {
			serviceName = node.Path
		}
		grpcSettings := map[string]interface{}{
			"serviceName": serviceName,
		}
		if node.MultiMode {
			grpcSettings["multiMode"] = true
		}
		if node.Host != "" {
			grpcSettings["authority"] = node.Host
		}
		stream["grpcSettings"] = grpcSettings
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
	case "httpupgrade":
		huSettings := map[string]interface{}{
			"path": firstNonEmpty(node.Path, "/"),
		}
		if node.Host != "" {
			huSettings["host"] = node.Host
		}
		stream["httpupgradeSettings"] = huSettings
	case "h2", "http":
		httpSettings := map[string]interface{}{
			"path": firstNonEmpty(node.Path, "/"),
		}
		if node.Host != "" {
			httpSettings["host"] = []string{node.Host}
		}
		stream["httpSettings"] = httpSettings
	case "xhttp", "splithttp":
		mode := node.XHTTPMode
		if mode == "" {
			mode = "auto"
		}
		stream["xhttpSettings"] = map[string]interface{}{
			"path": node.Path,
			"host": node.Host,
			"mode": mode,
		}
	}

	return stream
}

func firstNonEmpty(val, fallback string) string {
	if val != "" {
		return val
	}
	return fallback
}
