package singbox

import (
	"fmt"
	"strings"

	"github.com/blackalex1/sentinel-core/pkg/ast"
)

// BuildSingBoxOutbound converts an ast.ServerProfile into a Sing-box JSON outbound object.
func BuildSingBoxOutbound(node *ast.ServerProfile) (map[string]interface{}, error) {
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
		return buildVLESSOutbound(tag, node)
	case ast.ProtoHysteria2:
		return buildHysteria2Outbound(tag, node)
	case ast.ProtoTrojan:
		return buildTrojanOutbound(tag, node)
	case ast.ProtoShadowsocks:
		return buildShadowsocksOutbound(tag, node)
	case ast.ProtoShadowTLS:
		return buildShadowTLSOutbound(tag, node)
	case ast.ProtoTUIC:
		return buildTUICOutbound(tag, node)
	case ast.ProtoVMess:
		return buildVMessOutbound(tag, node)
	case ast.ProtoWireGuard:
		return buildWireGuardOutbound(tag, node)
	case ast.ProtoSocks:
		return buildSocksOutbound(tag, node)
	case ast.ProtoHTTP:
		return buildHTTPOutbound(tag, node)
	case ast.ProtoDirect:
		return map[string]interface{}{"type": "direct", "tag": tag}, nil
	case ast.ProtoBlock:
		return map[string]interface{}{"type": "block", "tag": tag}, nil
	default:
		return nil, fmt.Errorf("unsupported protocol for sing-box outbound: %s", proto)
	}
}

// CompileRawOutboundToSingbox converts raw DB / panel outbound settings into a Sing-box outbound configuration map.
func CompileRawOutboundToSingbox(ob map[string]interface{}) map[string]interface{} {
	if ob == nil {
		return nil
	}

	proto, _ := ob["protocol"].(string)
	proto = strings.ToLower(strings.TrimSpace(proto))
	tag, _ := ob["tag"].(string)
	if tag == "" {
		tag = "proxy"
	}

	// Direct & Block outbounds
	if proto == "direct" || proto == "freedom" {
		return map[string]interface{}{
			"type": "direct",
			"tag":  tag,
		}
	}
	if proto == "block" || proto == "blackhole" {
		return map[string]interface{}{
			"type": "block",
			"tag":  tag,
		}
	}

	// Parse settings and streamSettings payloads (can be map or JSON string)
	sMap := parseMapOrJSON(ob["settings"])
	tsMap := parseMapOrJSON(ob["stream_settings"])
	if tsMap == nil {
		tsMap = parseMapOrJSON(ob["streamSettings"])
	}

	switch proto {
	case "hysteria2", "hy2", "hysteria":
		return compileRawHysteria2Outbound(tag, sMap, tsMap)
	case "vless":
		return compileRawVLESSOutbound(tag, sMap, tsMap)
	case "vmess":
		return compileRawVMessOutbound(tag, sMap, tsMap)
	case "trojan":
		return compileRawTrojanOutbound(tag, sMap, tsMap)
	case "shadowsocks", "ss":
		return compileRawShadowsocksOutbound(tag, sMap, tsMap)
	case "wireguard", "wg":
		return compileRawWireguardOutbound(tag, sMap, tsMap)
	case "socks", "http":
		return compileRawSocksHttpOutbound(tag, proto, sMap, tsMap)
	default:
		return map[string]interface{}{
			"type": "direct",
			"tag":  tag,
		}
	}
}
