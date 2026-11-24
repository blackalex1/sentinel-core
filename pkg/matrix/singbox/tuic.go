package singbox

import (
	"github.com/blackalex1/sentinel-core/pkg/ast"
	"github.com/blackalex1/sentinel-core/pkg/i18n"
	"github.com/blackalex1/sentinel-core/pkg/matrix/types"
)

func GetTUICCapability(lang string) types.ProtocolCapability {
	loc := i18n.Locale(lang)
	return types.ProtocolCapability{
		Protocol:            ast.ProtoTUIC,
		DisplayName:         "TUIC v5",
		Description:         i18n.T(loc, "PROTO_TUIC_DESC"),
		DefaultPort:         8443,
		DefaultTransport:    "quic",
		DefaultSecurity:     "tls",
		SupportedEngines:    []string{"sing-box"},
		SupportedTransports: []string{"quic"},
		SupportedSecurity:   []string{"tls"},
		EngineTransports: map[string][]string{
			"sing-box": {"quic"},
		},
		EngineSecurity: map[string][]string{
			"sing-box": {"tls"},
		},
		Features: []string{"congestion_control_bbr", "zero_rtt"},
		Tabs:     []string{"basic", "stream", "sniffing", "advanced"},
	}
}
