package singbox

import (
	"github.com/blackalex1/sentinel-core/pkg/ast"
	"github.com/blackalex1/sentinel-core/pkg/i18n"
	"github.com/blackalex1/sentinel-core/pkg/matrix/types"
)

func GetWireGuardCapability(lang string) types.ProtocolCapability {
	loc := i18n.Locale(lang)
	return types.ProtocolCapability{
		Protocol:         ast.ProtoWireGuard,
		DisplayName:      "WireGuard",
		Description:      i18n.T(loc, "PROTO_WIREGUARD_DESC"),
		DefaultPort:      51820,
		SupportedEngines:  []string{"xray-core", "sing-box"},
		SupportedSecurity: []string{"none"},
		Features:          []string{"reserved_bytes", "preshared_key"},
		Tabs:              []string{"basic", "protocol", "sniffing", "advanced"},
	}
}
