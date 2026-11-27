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
	sec := strings.ToLower(strings.TrimSpace(node.Security))
	if sec == "" {
		if node.PublicKey != "" {
			sec = ast.SecurityReality
		} else if node.SNI != "" || node.Flow == "xtls-rprx-vision" {
			sec = ast.SecurityTLS
		}
	}
	if sec == "" || sec == ast.SecurityNone {
		return nil
	}

	tlsMap := map[string]interface{}{
		"enabled": true,
	}

	if node.Insecure {
		tlsMap["insecure"] = true
	}

	if node.SNI != "" {
		tlsMap["server_name"] = node.SNI
	}

	if len(node.ALPN) > 0 {
		tlsMap["alpn"] = node.ALPN
	}

	// Reality specific (requires valid public key)
	if (sec == ast.SecurityReality || node.PublicKey != "") && node.PublicKey != "" {
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

	case ast.TransportH2, ast.TransportHTTP:
		httpMap := map[string]interface{}{
			"type": "http",
		}
		if node.Path != "" {
			httpMap["path"] = node.Path
		}
		if node.Host != "" {
			httpMap["host"] = []string{node.Host}
		}
		return httpMap

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
	applyRawTLS(out, tsMap, defaultServerName)
	applyRawTransport(out, tsMap)
}

func applyRawTLS(out, tsMap map[string]interface{}, defaultServerName string) {
	security, _ := tsMap["security"].(string)
	if security == "" {
		if _, ok := tsMap["realitySettings"]; ok {
			security = "reality"
		} else if _, ok := tsMap["tlsSettings"]; ok {
			security = "tls"
		}
	}
	if security != "tls" && security != "reality" {
		return
	}

	tlsMap := map[string]interface{}{"enabled": true}
	tlsSettings, _ := tsMap["tlsSettings"].(map[string]interface{})
	realitySettings, _ := tsMap["realitySettings"].(map[string]interface{})

	serverName := defaultServerName
	if sn, ok := tlsSettings["serverName"].(string); ok && sn != "" {
		serverName = sn
	}
	if sn, ok := realitySettings["serverName"].(string); ok && sn != "" {
		serverName = sn
	}
	if serverName != "" {
		tlsMap["server_name"] = serverName
	}

	if tlsSettings != nil {
		if allowInsecure, ok := tlsSettings["allowInsecure"].(bool); ok && allowInsecure {
			tlsMap["insecure"] = true
		}
		if alpn := extractStringList(tlsSettings["alpn"]); len(alpn) > 0 {
			tlsMap["alpn"] = alpn
		}
	}

	if realitySettings != nil || security == "reality" {
		pk, _ := realitySettings["publicKey"].(string)
		sid, _ := realitySettings["shortId"].(string)
		if pk != "" {
			realityMap := map[string]interface{}{
				"enabled":    true,
				"public_key": pk,
			}
			if sid != "" {
				realityMap["short_id"] = sid
			}
			tlsMap["reality"] = realityMap
		}
	}

	fp, _ := realitySettings["fingerprint"].(string)
	if fp == "" {
		fp, _ = tlsSettings["fingerprint"].(string)
	}
	if fp != "" {
		tlsMap["utls"] = map[string]interface{}{
			"enabled":     true,
			"fingerprint": fp,
		}
	}

	out["tls"] = tlsMap
}

func extractStringList(raw interface{}) []string {
	switch v := raw.(type) {
	case []string:
		return v
	case []interface{}:
		var res []string
		for _, item := range v {
			if s, ok := item.(string); ok && s != "" {
				res = append(res, s)
			}
		}
		return res
	case string:
		if v != "" {
			return []string{v}
		}
	}
	return nil
}

func applyRawTransport(out, tsMap map[string]interface{}) {
	network, _ := tsMap["network"].(string)
	switch network {
	case "ws":
		wsMap := map[string]interface{}{"type": "ws"}
		if wsSettings, ok := tsMap["wsSettings"].(map[string]interface{}); ok {
			if path, ok := wsSettings["path"].(string); ok && path != "" {
				wsMap["path"] = path
			}
			if headers, ok := wsSettings["headers"].(map[string]interface{}); ok {
				if host, ok := headers["Host"].(string); ok && host != "" {
					wsMap["headers"] = map[string]interface{}{"Host": host}
				}
			}
		}
		out["transport"] = wsMap
	case "grpc":
		grpcMap := map[string]interface{}{"type": "grpc"}
		if grpcSettings, ok := tsMap["grpcSettings"].(map[string]interface{}); ok {
			if serviceName, ok := grpcSettings["serviceName"].(string); ok && serviceName != "" {
				grpcMap["service_name"] = serviceName
			}
		}
		out["transport"] = grpcMap
	case "httpupgrade":
		httpUpgradeMap := map[string]interface{}{"type": "httpupgrade"}
		if huSettings, ok := tsMap["httpupgradeSettings"].(map[string]interface{}); ok {
			if path, ok := huSettings["path"].(string); ok && path != "" {
				httpUpgradeMap["path"] = path
			}
			if host, ok := huSettings["host"].(string); ok && host != "" {
				httpUpgradeMap["host"] = host
			}
		}
		out["transport"] = httpUpgradeMap
	case "h2", "http":
		httpMap := map[string]interface{}{"type": "http"}
		if httpSettings, ok := tsMap["httpSettings"].(map[string]interface{}); ok {
			if path, ok := httpSettings["path"].(string); ok && path != "" {
				httpMap["path"] = path
			}
			if hosts := extractStringList(httpSettings["host"]); len(hosts) > 0 {
				httpMap["host"] = hosts
			}
		}
		out["transport"] = httpMap
	}
}
