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
	case ast.ProtoSocks, "socks5":
		return buildXraySocksOutbound(tag, node)
	case ast.ProtoHTTP, "https":
		return buildXrayHttpOutbound(tag, node)
	case ast.ProtoDirect:
		return map[string]interface{}{"protocol": "freedom", "tag": tag}, nil
	case ast.ProtoBlock:
		return map[string]interface{}{"protocol": "blackhole", "tag": tag}, nil
	default:
		return nil, fmt.Errorf("unsupported protocol for xray-core outbound: %s", proto)
	}
}
