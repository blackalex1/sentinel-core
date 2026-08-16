package singbox

import (
	"strings"
	"github.com/blackalex1/sentinel-core/pkg/ast"
)

// buildHysteria2Inbound compiles a complete Hysteria 2 inbound for Sing-box
func buildHysteria2Inbound(sb *ast.ServerInboundSpec) map[string]interface{} {
	listenAddr := sb.ListenAddress
	if listenAddr == "" {
		listenAddr = "::"
	}

	inbound := map[string]interface{}{
		"type":        "hysteria2",
		"tag":         sb.Tag,
		"listen":      listenAddr,
		"listen_port": sb.Port,
	}

	// 1. Users
	if len(sb.Clients) > 0 {
		users := make([]map[string]interface{}, 0, len(sb.Clients))
		for _, c := range sb.Clients {
			pwd := c.Password
			if pwd == "" {
				pwd = c.UUID
			}
			if pwd == "" {
				pwd = c.ID
			}
			userMap := map[string]interface{}{
				"name":     c.Email,
				"password": pwd,
			}
			users = append(users, userMap)
		}
		inbound["users"] = users
	}

	// 2. Bandwidth
	if sb.BandwidthUp != "" {
		inbound["up_mbps"] = parseBandwidth(sb.BandwidthUp)
	}
	if sb.BandwidthDown != "" {
		inbound["down_mbps"] = parseBandwidth(sb.BandwidthDown)
	}

	// 3. Obfuscation (Salamander)
	if sb.ObfsPassword != "" {
		obfsType := "salamander"
		if sb.ObfsType != "" {
			obfsType = sb.ObfsType
		}
		inbound["obfs"] = map[string]interface{}{
			"type":     obfsType,
			"password": sb.ObfsPassword,
		}
	}

	// 4. Masquerade
	if sb.MasqType != "" && sb.MasqValue != "" {
		masqMap := map[string]interface{}{
			"type": sb.MasqType,
		}
		if sb.MasqType == "file" {
			masqMap["dir"] = sb.MasqValue
		} else if sb.MasqType == "proxy" {
			urlVal := strings.TrimSpace(sb.MasqValue)
			if urlVal != "" && !strings.HasPrefix(urlVal, "http://") && !strings.HasPrefix(urlVal, "https://") {
				urlVal = "https://" + urlVal
			}
			masqMap["url"] = urlVal
		} else if sb.MasqType == "string" {
			masqMap["content"] = sb.MasqValue
		}
		if sb.MasqStatusCode > 0 {
			masqMap["status_code"] = sb.MasqStatusCode
		}
		inbound["masquerade"] = masqMap
	}

	// 5. TLS
	if tlsMap := buildInboundTLS(sb); tlsMap != nil {
		inbound["tls"] = tlsMap
	}

	// 6. Common options
	applyCommonInboundOptions(inbound, sb)

	return inbound
}
