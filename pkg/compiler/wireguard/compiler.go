package wireguard

import (
	"fmt"
	"strings"
	"github.com/blackalex1/sentinel-core/pkg/ast"
)

// BuildWireGuardConf converts an ast.ServerProfile into standard WireGuard INI config (.conf)
func BuildWireGuardConf(node *ast.ServerProfile) (string, error) {
	if node == nil {
		return "", fmt.Errorf("node profile cannot be nil")
	}

	var sb strings.Builder
	sb.WriteString("[Interface]\n")
	if node.PrivateKey != "" {
		sb.WriteString(fmt.Sprintf("PrivateKey = %s\n", node.PrivateKey))
	}
	if len(node.LocalAddress) > 0 {
		sb.WriteString(fmt.Sprintf("Address = %s\n", strings.Join(node.LocalAddress, ", ")))
	}
	if node.MTU > 0 {
		sb.WriteString(fmt.Sprintf("MTU = %d\n", node.MTU))
	}

	sb.WriteString("\n[Peer]\n")
	if node.PeerPublicKey != "" {
		sb.WriteString(fmt.Sprintf("PublicKey = %s\n", node.PeerPublicKey))
	}
	if node.PreSharedKey != "" {
		sb.WriteString(fmt.Sprintf("PresharedKey = %s\n", node.PreSharedKey))
	}
	sb.WriteString(fmt.Sprintf("Endpoint = %s:%d\n", node.Address, node.Port))
	sb.WriteString("AllowedIPs = 0.0.0.0/0, ::/0\n")
	sb.WriteString("PersistentKeepalive = 25\n")

	return sb.String(), nil
}
