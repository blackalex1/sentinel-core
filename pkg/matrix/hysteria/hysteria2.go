package hysteria

import (
	"github.com/blackalex1/sentinel-core/pkg/ast"
	"github.com/blackalex1/sentinel-core/pkg/i18n"
	"github.com/blackalex1/sentinel-core/pkg/matrix/fields"
	"github.com/blackalex1/sentinel-core/pkg/matrix/types"
)

func GetHysteria2Capability(lang string) types.ProtocolCapability {
	loc := i18n.Locale(lang)
	return types.ProtocolCapability{
		Protocol:            ast.ProtoHysteria2,
		DisplayName:         "Hysteria 2",
		Description:         i18n.T(loc, "PROTO_HYSTERIA2_DESC"),
		DefaultPort:         443,
		SupportedEngines:    []string{"hysteria2", "sing-box"},
		SupportedTransports: []string{"quic"},
		SupportedSecurity:   []string{"tls"},
		Features:            []string{"port_hopping", "salamander_obfs", "bandwidth_up_down", "webhook_auth"},
		Tabs:                []string{"basic", "stream", "sniffing", "advanced"},
		TabDefinitions:      fields.BuildHysteria2TabDefinitions(lang),
	}
}
