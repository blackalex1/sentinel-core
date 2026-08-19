package singbox

import (
	"fmt"
	"strings"

	"github.com/blackalex1/sentinel-core/pkg/ast"
)

// buildInboundTLS extracts and builds TLS or Reality configuration for Sing-box
func buildInboundTLS(sb *ast.ServerInboundSpec) map[string]interface{} {
	sec := sb.Security
	if sec == "" && sb.StreamSettings != nil {
		if s, ok := sb.StreamSettings["security"].(string); ok {
			sec = s
		}
	}

	if sec == ast.SecurityReality || sec == "reality" {
		privateKey := sb.PrivateKey
		serverName := sb.SNI
		dest := "example.com:443"
		shortIDs := sb.ShortIDs

		if sb.StreamSettings != nil {
			if rs, ok := sb.StreamSettings["realitySettings"].(map[string]interface{}); ok {
				if pk, ok := rs["privateKey"].(string); ok && pk != "" {
					privateKey = pk
				}
				if d, ok := rs["dest"].(string); ok && d != "" {
					dest = d
				}
				if sns, ok := rs["serverNames"].([]interface{}); ok && len(sns) > 0 {
					if sn, ok := sns[0].(string); ok && sn != "" {
						serverName = sn
					}
				}
				if sids, ok := rs["shortIds"].([]interface{}); ok {
					for _, sid := range sids {
						if s, ok := sid.(string); ok {
							shortIDs = append(shortIDs, s)
						}
					}
				}
			}
		}

		destHost := serverName
		destPort := 443
		if strings.Contains(dest, ":") {
			parts := strings.Split(dest, ":")
			destHost = parts[0]
			fmt.Sscanf(parts[1], "%d", &destPort)
		}

		return map[string]interface{}{
			"enabled":     true,
			"server_name": serverName,
			"reality": map[string]interface{}{
				"enabled":     true,
				"private_key": privateKey,
				"short_id":    shortIDs,
				"handshake": map[string]interface{}{
					"server":      destHost,
					"server_port": destPort,
				},
			},
		}
	}

	if sec == ast.SecurityTLS || sec == "tls" {
		certPath := sb.CertPath
		keyPath := sb.KeyPath
		serverName := sb.SNI

		if sb.StreamSettings != nil {
			if ts, ok := sb.StreamSettings["tlsSettings"].(map[string]interface{}); ok {
				if sn, ok := ts["serverName"].(string); ok && sn != "" {
					serverName = sn
				}
				if cp, ok := ts["certificateFile"].(string); ok && cp != "" {
					certPath = cp
				}
				if kp, ok := ts["keyFile"].(string); ok && kp != "" {
					keyPath = kp
				}
			}
		}

		tlsMap := map[string]interface{}{
			"enabled":          true,
			"server_name":      serverName,
			"certificate_path": certPath,
			"key_path":         keyPath,
		}
		return tlsMap
	}

	return nil
}

// buildInboundTransport builds transport configuration for Sing-box (ws, grpc, http, httpupgrade)
func buildInboundTransport(sb *ast.ServerInboundSpec) map[string]interface{} {
	tr := sb.Transport
	if tr == "" && sb.StreamSettings != nil {
		if net, ok := sb.StreamSettings["network"].(string); ok {
			tr = net
		}
	}

	switch strings.ToLower(tr) {
	case "ws", "websocket":
		path := "/"
		if sb.StreamSettings != nil {
			if ws, ok := sb.StreamSettings["wsSettings"].(map[string]interface{}); ok {
				if p, ok := ws["path"].(string); ok && p != "" {
					path = p
				}
			}
		}
		return map[string]interface{}{
			"type": "ws",
			"path": path,
		}
	case "grpc":
		svcName := "grpc"
		if sb.StreamSettings != nil {
			if gs, ok := sb.StreamSettings["grpcSettings"].(map[string]interface{}); ok {
				if s, ok := gs["serviceName"].(string); ok && s != "" {
					svcName = s
				}
			}
		}
		return map[string]interface{}{
			"type":         "grpc",
			"service_name": svcName,
		}
	case "httpupgrade":
		path := "/"
		if sb.StreamSettings != nil {
			if hu, ok := sb.StreamSettings["httpupgradeSettings"].(map[string]interface{}); ok {
				if p, ok := hu["path"].(string); ok && p != "" {
					path = p
				}
			}
		}
		return map[string]interface{}{
			"type": "httpupgrade",
			"path": path,
		}
	}

	return nil
}

// parseInboundNetwork normalizes network values for Sing-box ("tcp", "udp", or "" for both)
func parseInboundNetwork(net string) string {
	n := strings.ToLower(strings.TrimSpace(net))
	if n == "tcp" {
		return "tcp"
	}
	if n == "udp" {
		return "udp"
	}
	return ""
}

// applyCommonInboundOptions applies multiplex and network settings (sniffing is handled via route rule actions)
func applyCommonInboundOptions(inbound map[string]interface{}, sb *ast.ServerInboundSpec) {
	if sb.Multiplex {
		inbound["multiplex"] = map[string]interface{}{
			"enabled": true,
		}
	}

	if sb.RawSettings != nil {
		if tfo, ok := sb.RawSettings["tcp_fast_open"].(bool); ok {
			inbound["tcp_fast_open"] = tfo
		}
		if tmp, ok := sb.RawSettings["tcp_multi_path"].(bool); ok {
			inbound["tcp_multi_path"] = tmp
		}
		if ut, ok := sb.RawSettings["udp_timeout"].(string); ok && ut != "" {
			inbound["udp_timeout"] = ut
		}
		if net, ok := sb.RawSettings["network"].(string); ok && net != "" {
			if parsedNet := parseInboundNetwork(net); parsedNet != "" {
				inbound["network"] = parsedNet
			}
		}
	}
}
