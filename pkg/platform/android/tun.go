package android

import (
	"github.com/blackalex1/sentinel-core/pkg/ast"
)

const (
	DefaultTunInterface = "tun0"
	DefaultTunStack     = "gvisor"
	DefaultTunMTU       = 1500
	DefaultIPv4Gateway  = "10.0.0.1/24"
	DefaultIPv6Gateway  = "fd00::1/64"
	DefaultClientIPv4   = "10.0.0.2/24"
	DefaultClientIPv6   = "fd00::2/64"
)

// DefaultTunSpec returns a standard Android VpnService TUN inbound configuration
func DefaultTunSpec() ast.ClientInboundSpec {
	return ast.ClientInboundSpec{
		Mode:             ast.InboundModeMobileVpn,
		TunInterfaceName: DefaultTunInterface,
		TunStack:         DefaultTunStack,
		MTU:              DefaultTunMTU,
		StrictRoute:      true,
		AutoRoute:        true,
		EndpointIP:       "172.19.0.1/30",
	}
}

// BuildXrayAndroidTunInbound constructs the Xray TUN inbound dictionary tailored for Android VpnService
func BuildXrayAndroidTunInbound(cb *ast.ClientInboundSpec) map[string]interface{} {
	if cb == nil {
		return nil
	}

	tunName := cb.TunInterfaceName
	if tunName == "" {
		tunName = DefaultTunInterface
	}

	stack := cb.TunStack
	if stack == "" {
		stack = DefaultTunStack
	}

	mtu := cb.MTU
	if mtu <= 0 {
		mtu = DefaultTunMTU
	}

	tunSettings := map[string]interface{}{
		"name":    tunName,
		"mtu":     mtu,
		"stack":   stack,
		"gateway": []string{DefaultIPv4Gateway, DefaultIPv6Gateway},
	}

	return map[string]interface{}{
		"tag":      "tun-in",
		"protocol": "tun",
		"settings": tunSettings,
		"sniffing": map[string]interface{}{
			"enabled":      true,
			"destOverride": []string{"http", "tls", "quic"},
			"routeOnly":    false,
		},
	}
}

// BuildSingBoxAndroidTunInbound constructs the Sing-box TUN inbound dictionary tailored for Android VpnService
func BuildSingBoxAndroidTunInbound(cb *ast.ClientInboundSpec) map[string]interface{} {
	if cb == nil {
		return nil
	}

	ifname := cb.TunInterfaceName
	if ifname == "" {
		ifname = DefaultTunInterface
	}

	stack := cb.TunStack
	if stack == "" {
		stack = DefaultTunStack
	}

	mtu := cb.MTU
	if mtu <= 0 {
		mtu = DefaultTunMTU
	}

	tunIn := map[string]interface{}{
		"type":                       "tun",
		"tag":                        "tun-in",
		"interface_name":             ifname,
		"stack":                      stack,
		"mtu":                        mtu,
		"auto_route":                 cb.AutoRoute,
		"strict_route":               cb.StrictRoute,
		"sniff":                      true,
		"sniff_override_destination": true,
	}

	var inet4Address []string
	if cb.Inet4Address != "" {
		inet4Address = append(inet4Address, cb.Inet4Address)
	} else {
		inet4Address = append(inet4Address, DefaultClientIPv4)
	}
	tunIn["inet4_address"] = inet4Address

	var inet6Address []string
	if cb.Inet6Address != "" {
		inet6Address = append(inet6Address, cb.Inet6Address)
	} else {
		inet6Address = append(inet6Address, DefaultClientIPv6)
	}
	tunIn["inet6_address"] = inet6Address

	if len(cb.IncludePackages) > 0 {
		tunIn["include_package"] = cb.IncludePackages
	}
	if len(cb.ExcludePackages) > 0 {
		tunIn["exclude_package"] = cb.ExcludePackages
	}

	return tunIn
}
