package xray

import (
	"github.com/blackalex1/sentinel-core/pkg/ast"
)

// buildXrayHysteria2Inbound compiles an ast.ServerInboundSpec into an Xray local SOCKS bridge listener for Hysteria 2.
func buildXrayHysteria2Inbound(sb *ast.ServerInboundSpec) map[string]interface{} {
	settings := map[string]interface{}{
		"udp":  true,
		"auth": "noauth",
	}

	return map[string]interface{}{
		"tag":            sb.Tag,
		"port":           sb.Port,
		"listen":         "127.0.0.1",
		"protocol":       "socks",
		"settings":       settings,
		"streamSettings": buildInboundStreamSettings(sb),
		"sniffing":       buildInboundSniffing(sb),
	}
}
