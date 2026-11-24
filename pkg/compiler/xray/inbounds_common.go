package xray

import (
	"github.com/blackalex1/sentinel-core/pkg/ast"
)

// buildInboundSniffing constructs sniffing options for Xray inbounds
func buildInboundSniffing(sb *ast.ServerInboundSpec) map[string]interface{} {
	sniffing := map[string]interface{}{
		"enabled":      true,
		"destOverride": []string{"http", "tls", "quic"},
		"routeOnly":    false,
	}
	if sb.Sniffing != nil && len(sb.Sniffing) > 0 {
		sniffing = sb.Sniffing
	}
	return sniffing
}

// buildInboundStreamSettings constructs streamSettings for Xray inbounds (TCP, TLS, Reality)
func buildInboundStreamSettings(sb *ast.ServerInboundSpec) map[string]interface{} {
	network := sb.Transport
	if network == "" {
		network = "tcp"
	}
	streamSettings := map[string]interface{}{
		"network": network,
	}
	if sb.StreamSettings != nil && len(sb.StreamSettings) > 0 {
		for k, v := range sb.StreamSettings {
			streamSettings[k] = v
		}
		if netVal, ok := streamSettings["network"].(string); !ok || netVal == "" {
			streamSettings["network"] = network
		}
	}

	if sb.Security == ast.SecurityReality || streamSettings["security"] == "reality" {
		streamSettings["security"] = "reality"
		rs, hasRS := streamSettings["realitySettings"].(map[string]interface{})
		if !hasRS || rs == nil {
			rs = map[string]interface{}{}
		}
		if _, ok := rs["show"]; !ok {
			rs["show"] = false
		}
		if dest, ok := rs["dest"].(string); !ok || dest == "" {
			if sb.SNI != "" {
				rs["dest"] = sb.SNI + ":443"
			}
		}
		if _, ok := rs["xver"]; !ok {
			rs["xver"] = 0
		}
		if _, ok := rs["serverNames"]; !ok && sb.SNI != "" {
			rs["serverNames"] = []string{sb.SNI}
		}
		if pk, ok := rs["privateKey"].(string); !ok || pk == "" {
			rs["privateKey"] = sb.PrivateKey
		}
		if _, ok := rs["shortIds"]; !ok && len(sb.ShortIDs) > 0 {
			rs["shortIds"] = sb.ShortIDs
		}
		streamSettings["realitySettings"] = rs
	} else if sb.Security == ast.SecurityTLS || streamSettings["security"] == "tls" {
		streamSettings["security"] = "tls"
		ts, hasTS := streamSettings["tlsSettings"].(map[string]interface{})
		if !hasTS || ts == nil {
			ts = map[string]interface{}{}
		}
		if sn, ok := ts["serverName"].(string); !ok || sn == "" {
			ts["serverName"] = sb.SNI
		}
		if _, ok := ts["certificates"]; !ok && (sb.CertPath != "" || sb.KeyPath != "") {
			ts["certificates"] = []map[string]interface{}{
				{
					"certificateFile": sb.CertPath,
					"keyFile":         sb.KeyPath,
				},
			}
		}
		streamSettings["tlsSettings"] = ts
	}

	return streamSettings
}
