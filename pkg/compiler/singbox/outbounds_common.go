package singbox

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/blackalex1/sentinel-core/pkg/ast"
)

// parseMapOrJSON safely parses a map or JSON string into map[string]interface{}.
func parseMapOrJSON(val interface{}) map[string]interface{} {
	if val == nil {
		return nil
	}
	switch v := val.(type) {
	case map[string]interface{}:
		return v
	case string:
		vTrim := strings.TrimSpace(v)
		if vTrim == "" || vTrim == "{}" {
			return nil
		}
		var m map[string]interface{}
		if err := json.Unmarshal([]byte(vTrim), &m); err == nil {
			return m
		}
	}
	return nil
}

// buildSingBoxTLS extracts and builds TLS/Reality configuration map from an ast.ServerProfile.
func buildSingBoxTLS(node *ast.ServerProfile) map[string]interface{} {
	if node.Security == "" || node.Security == ast.SecurityNone {
		return nil
	}

	tlsMap := map[string]interface{}{
		"enabled": true,
	}

	if node.Insecure || node.PinnedPeerCertSha256 != "" {
		tlsMap["insecure"] = true
	}

	if node.SNI != "" {
		tlsMap["server_name"] = node.SNI
	}

	if len(node.ALPN) > 0 {
		tlsMap["alpn"] = node.ALPN
	}

	// Reality specific
	if node.Security == ast.SecurityReality {
		realityMap := map[string]interface{}{
			"enabled":    true,
			"public_key": node.PublicKey,
			"short_id":   node.ShortID,
		}
		tlsMap["reality"] = realityMap

		// Sing-box Reality client strictly requires uTLS enabled
		fp := node.Fingerprint
		if fp == "" {
			fp = "chrome"
		}
		tlsMap["utls"] = map[string]interface{}{
			"enabled":     true,
			"fingerprint": fp,
		}
	} else if node.Fingerprint != "" {
		// uTLS / Fingerprint for non-Reality TLS
		tlsMap["utls"] = map[string]interface{}{
			"enabled":     true,
			"fingerprint": node.Fingerprint,
		}
	}

	return tlsMap
}

// buildSingBoxTransport extracts and builds transport layer configuration from an ast.ServerProfile.
func buildSingBoxTransport(node *ast.ServerProfile) map[string]interface{} {
	if node.Transport == "" || node.Transport == ast.TransportTCP {
		return nil
	}

	switch node.Transport {
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

	case ast.TransportGRPC:
		grpcMap := map[string]interface{}{
			"type": "grpc",
		}
		if node.ServiceName != "" {
			grpcMap["service_name"] = node.ServiceName
		}
		return grpcMap

	case ast.TransportHTTPUpgrade:
		httpUpgradeMap := map[string]interface{}{
			"type": "httpupgrade",
		}
		if node.Path != "" {
			httpUpgradeMap["path"] = node.Path
		}
		if node.Host != "" {
			httpUpgradeMap["host"] = node.Host
		}
		return httpUpgradeMap

	default:
		return nil
	}
}

// parseBandwidth parses a bandwidth string (e.g. "100", "100 Mbps", "200mb") into an integer in Mbps.
func parseBandwidth(s string) int {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimSuffix(s, "mbps")
	s = strings.TrimSuffix(s, "mb")
	s = strings.TrimSuffix(s, "m")
	s = strings.TrimSpace(s)
	val, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return val
}

// applyRawTLSAndTransport extracts TLS/Reality and Transport settings from raw dictionaries.
func applyRawTLSAndTransport(out, sMap, tsMap map[string]interface{}, defaultServerName string) {
	security, _ := tsMap["security"].(string)
	if security == "" {
		if _, ok := tsMap["realitySettings"]; ok {
			security = "reality"
		} else if _, ok := tsMap["tlsSettings"]; ok {
			security = "tls"
		}
	}

	if security == "tls" || security == "reality" {
		tlsMap := map[string]interface{}{
			"enabled": true,
		}

		tlsSettings, _ := tsMap["tlsSettings"].(map[string]interface{})
		realitySettings, _ := tsMap["realitySettings"].(map[string]interface{})

		serverName := defaultServerName
		if tlsSettings != nil {
			if sn, ok := tlsSettings["serverName"].(string); ok && sn != "" {
				serverName = sn
			}
		}
		if realitySettings != nil {
			if sn, ok := realitySettings["serverName"].(string); ok && sn != "" {
				serverName = sn
			}
		}
		if serverName != "" {
			tlsMap["server_name"] = serverName
		}

		if tlsSettings != nil {
			if allowInsecure, ok := tlsSettings["allowInsecure"].(bool); ok && allowInsecure {
				tlsMap["insecure"] = true
			}
			if alpnRaw, ok := tlsSettings["alpn"]; ok {
				if alpnList, ok := alpnRaw.([]interface{}); ok {
					var alpnStr []string
					for _, item := range alpnList {
						if s, ok := item.(string); ok {
							alpnStr = append(alpnStr, s)
						}
					}
					if len(alpnStr) > 0 {
						tlsMap["alpn"] = alpnStr
					}
				} else if alpnSlice, ok := alpnRaw.([]string); ok {
					tlsMap["alpn"] = alpnSlice
				}
			}
		}

		if realitySettings != nil || security == "reality" {
			realityMap := map[string]interface{}{
				"enabled": true,
			}
			if realitySettings != nil {
				if pk, ok := realitySettings["publicKey"].(string); ok {
					realityMap["public_key"] = pk
				}
				if sid, ok := realitySettings["shortId"].(string); ok {
					realityMap["short_id"] = sid
				}
			}
			tlsMap["reality"] = realityMap
		}

		var fp string
		if realitySettings != nil {
			if f, ok := realitySettings["fingerprint"].(string); ok {
				fp = f
			}
		}
		if fp == "" && tlsSettings != nil {
			if f, ok := tlsSettings["fingerprint"].(string); ok {
				fp = f
			}
		}
		if fp != "" {
			tlsMap["utls"] = map[string]interface{}{
				"enabled":     true,
				"fingerprint": fp,
			}
		}

		out["tls"] = tlsMap
	}

	network, _ := tsMap["network"].(string)
	if network == "ws" {
		wsMap := map[string]interface{}{
			"type": "ws",
		}
		if wsSettings, ok := tsMap["wsSettings"].(map[string]interface{}); ok {
			if path, ok := wsSettings["path"].(string); ok && path != "" {
				wsMap["path"] = path
			}
			if headers, ok := wsSettings["headers"].(map[string]interface{}); ok {
				if host, ok := headers["Host"].(string); ok && host != "" {
					wsMap["headers"] = map[string]interface{}{
						"Host": host,
					}
				}
			}
		}
		out["transport"] = wsMap
	} else if network == "grpc" {
		grpcMap := map[string]interface{}{
			"type": "grpc",
		}
		if grpcSettings, ok := tsMap["grpcSettings"].(map[string]interface{}); ok {
			if serviceName, ok := grpcSettings["serviceName"].(string); ok && serviceName != "" {
				grpcMap["service_name"] = serviceName
			}
		}
		out["transport"] = grpcMap
	} else if network == "httpupgrade" {
		httpUpgradeMap := map[string]interface{}{
			"type": "httpupgrade",
		}
		if huSettings, ok := tsMap["httpupgradeSettings"].(map[string]interface{}); ok {
			if path, ok := huSettings["path"].(string); ok && path != "" {
				httpUpgradeMap["path"] = path
			}
			if host, ok := huSettings["host"].(string); ok && host != "" {
				httpUpgradeMap["host"] = host
			}
		}
		out["transport"] = httpUpgradeMap
	}
}
