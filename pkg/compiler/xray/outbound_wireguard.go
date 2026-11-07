package xray

import (
	"fmt"
	"strings"

	"github.com/blackalex1/sentinel-core/pkg/ast"
)

// buildXrayWireGuardOutbound compiles an ast.ServerProfile into an Xray WireGuard outbound object.
func buildXrayWireGuardOutbound(tag string, node *ast.ServerProfile) (map[string]interface{}, error) {
	endpoint := fmt.Sprintf("%s:%d", node.Address, node.Port)
	if strings.Contains(node.Address, ":") && !strings.HasPrefix(node.Address, "[") {
		endpoint = fmt.Sprintf("[%s]:%d", strings.Trim(node.Address, "[]"), node.Port)
	}
	peers := []map[string]interface{}{
		{
			"publicKey": node.PeerPublicKey,
			"endpoint":  endpoint,
		},
	}
	if node.PreSharedKey != "" {
		peers[0]["preSharedKey"] = node.PreSharedKey
	}

	return map[string]interface{}{
		"protocol": "wireguard",
		"tag":      tag,
		"settings": map[string]interface{}{
			"secretKey": node.PrivateKey,
			"address":   node.LocalAddress,
			"peers":     peers,
			"mtu":       node.MTU,
		},
	}, nil
}
