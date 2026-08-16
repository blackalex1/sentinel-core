package xray

import (
	"github.com/blackalex1/sentinel-core/pkg/ast"
)

// buildInboundSniffing constructs sniffing options for Xray inbounds
func buildInboundSniffing(sb *ast.ServerInboundSpec) map[string]interface{} {
	sniffing := map[string]interface{}{
		"enabled":      true,
		"destOverride": []string{"http", "tls", "quic", "fakedns"},
		"routeOnly":    false,
	}
	if sb.Sniffing != nil && len(sb.Sniffing) > 0 {
		sniffing = sb.Sniffing
	}
	return sniffing
}

// buildInboundStreamSettings constructs streamSettings for Xray inbounds (TCP, TLS, Reality)
func buildInboundStreamSettings(sb *ast.ServerInboundSpec) map[string]interface{} {
	streamSettings := map[string]interface{}{
		"network": "tcp",
	}
	if sb.StreamSettings != nil && len(sb.StreamSettings) > 0 {
		for k, v := range sb.StreamSettings {
			streamSettings[k] = v
		}
	}

	if sb.Security == ast.SecurityReality || streamSettings["security"] == "reality" {
		streamSettings["security"] = "reality"
		if _, ok := streamSettings["realitySettings"]; !ok {
			streamSettings["realitySettings"] = map[string]interface{}{
				"show":        false,
				"dest":        sb.SNI + ":443",
				"xver":        0,
				"serverNames": []string{sb.SNI},
				"privateKey":  sb.PrivateKey,
				"shortIds":    sb.ShortIDs,
			}
		}
	} else if sb.Security == ast.SecurityTLS || streamSettings["security"] == "tls" {
		streamSettings["security"] = "tls"
		if _, ok := streamSettings["tlsSettings"]; !ok {
			streamSettings["tlsSettings"] = map[string]interface{}{
				"serverName": sb.SNI,
				"certificates": []map[string]interface{}{
					{
						"certificateFile": sb.CertPath,
						"keyFile":         sb.KeyPath,
					},
				},
			}
		}
	}

	return streamSettings
}
