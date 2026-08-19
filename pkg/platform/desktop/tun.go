package desktop

import (
	"github.com/blackalex1/sentinel-core/pkg/ast"
)

const (
	DefaultDesktopTunInterface = "sentinel-tun"
	DefaultDesktopTunStack     = "mixed"
	DefaultDesktopTunMTU       = 9000
	DefaultDesktopEndpointIP   = "172.19.0.1/30"
)

// DefaultDesktopTunSpec returns a standard Desktop TUN configuration (for Wintun / Linux TUN)
func DefaultDesktopTunSpec() ast.ClientInboundSpec {
	return ast.ClientInboundSpec{
		Mode:             ast.InboundModeDesktopTun,
		TunInterfaceName: DefaultDesktopTunInterface,
		TunStack:         DefaultDesktopTunStack,
		MTU:              DefaultDesktopTunMTU,
		StrictRoute:      true,
		AutoRoute:        true,
		EndpointIP:       DefaultDesktopEndpointIP,
	}
}

// BuildXrayDesktopTunInbound constructs the Xray TUN inbound dictionary for Desktop platforms
func BuildXrayDesktopTunInbound(cb *ast.ClientInboundSpec) map[string]interface{} {
	if cb == nil {
		return nil
	}

	tunName := cb.TunInterfaceName
	if tunName == "" {
		tunName = DefaultDesktopTunInterface
	}

	stack := cb.TunStack
	if stack == "" {
		stack = DefaultDesktopTunStack
	}

	mtu := cb.MTU
	if mtu <= 0 {
		mtu = DefaultDesktopTunMTU
	}

	tunSettings := map[string]interface{}{
		"name":  tunName,
		"mtu":   mtu,
		"stack": stack,
	}

	if cb.EndpointIP != "" {
		tunSettings["gateway"] = []string{cb.EndpointIP}
	}

	return map[string]interface{}{
		"tag":      "tun-in",
		"protocol": "tun",
		"settings": tunSettings,
		"sniffing": map[string]interface{}{
			"enabled":      true,
			"destOverride": []string{"http", "tls", "quic", "fakedns"},
			"routeOnly":    false,
		},
	}
}

// BuildSingBoxDesktopTunInbound constructs the Sing-box TUN inbound dictionary for Desktop platforms
func BuildSingBoxDesktopTunInbound(cb *ast.ClientInboundSpec) map[string]interface{} {
	if cb == nil {
		return nil
	}

	ifname := cb.TunInterfaceName
	if ifname == "" {
		ifname = DefaultDesktopTunInterface
	}

	stack := cb.TunStack
	if stack == "" {
		stack = DefaultDesktopTunStack
	}

	mtu := cb.MTU
	if mtu <= 0 {
		mtu = DefaultDesktopTunMTU
	}

	endpoint := cb.EndpointIP
	if endpoint == "" {
		endpoint = DefaultDesktopEndpointIP
	}

	tunIn := map[string]interface{}{
		"type":           "tun",
		"tag":            "tun-in",
		"interface_name": ifname,
		"inet4_address":  endpoint,
		"auto_route":     cb.AutoRoute,
		"strict_route":   cb.StrictRoute,
		"stack":          stack,
		"mtu":            mtu,
	}

	if cb.Inet6Address != "" {
		tunIn["inet6_address"] = cb.Inet6Address
	}

	if len(cb.IncludePackages) > 0 {
		tunIn["include_package"] = cb.IncludePackages
	}
	if len(cb.ExcludePackages) > 0 {
		tunIn["exclude_package"] = cb.ExcludePackages
	}

	return tunIn
}
