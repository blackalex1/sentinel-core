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
		fmt.Fprintf(&sb, "PrivateKey = %s\n", node.PrivateKey)
	}
	if len(node.LocalAddress) > 0 {
		fmt.Fprintf(&sb, "Address = %s\n", strings.Join(node.LocalAddress, ", "))
	}
	if node.MTU > 0 {
		fmt.Fprintf(&sb, "MTU = %d\n", node.MTU)
	}

	sb.WriteString("\n[Peer]\n")
	if node.PeerPublicKey != "" {
		fmt.Fprintf(&sb, "PublicKey = %s\n", node.PeerPublicKey)
	}
	if node.PreSharedKey != "" {
		fmt.Fprintf(&sb, "PresharedKey = %s\n", node.PreSharedKey)
	}
	endpoint := fmt.Sprintf("%s:%d", node.Address, node.Port)
	if strings.Contains(node.Address, ":") && !strings.HasPrefix(node.Address, "[") {
		endpoint = fmt.Sprintf("[%s]:%d", strings.Trim(node.Address, "[]"), node.Port)
	}
	fmt.Fprintf(&sb, "Endpoint = %s\n", endpoint)
	sb.WriteString("AllowedIPs = 0.0.0.0/0, ::/0\n")
	sb.WriteString("PersistentKeepalive = 25\n")

	return sb.String(), nil
}
