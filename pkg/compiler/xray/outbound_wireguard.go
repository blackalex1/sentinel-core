package xray

import (
	"fmt"

	"github.com/blackalex1/sentinel-core/pkg/ast"
)

// buildXrayWireGuardOutbound compiles an ast.ServerProfile into an Xray WireGuard outbound object.
func buildXrayWireGuardOutbound(tag string, node *ast.ServerProfile) (map[string]interface{}, error) {
	peers := []map[string]interface{}{
		{
			"publicKey": node.PeerPublicKey,
			"endpoint":  fmt.Sprintf("%s:%d", node.Address, node.Port),
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
