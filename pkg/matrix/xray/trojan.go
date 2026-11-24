package xray

import (
	"github.com/blackalex1/sentinel-core/pkg/ast"
	"github.com/blackalex1/sentinel-core/pkg/i18n"
	"github.com/blackalex1/sentinel-core/pkg/matrix/fields"
	"github.com/blackalex1/sentinel-core/pkg/matrix/types"
)

func GetTrojanCapability(lang string) types.ProtocolCapability {
	loc := i18n.Locale(lang)
	return types.ProtocolCapability{
		Protocol:            ast.ProtoTrojan,
		DisplayName:         "Trojan",
		Description:         i18n.T(loc, "PROTO_TROJAN_DESC"),
		DefaultPort:         443,
		DefaultTransport:    "tcp",
		DefaultSecurity:     "tls",
		SupportedEngines:    []string{"xray-core", "sing-box"},
		SupportedTransports: []string{"tcp", "ws", "grpc"},
		SupportedSecurity:   []string{"tls"},
		EngineTransports: map[string][]string{
			"xray-core": {"tcp", "ws", "grpc"},
			"sing-box":  {"tcp", "ws", "grpc"},
		},
		EngineSecurity: map[string][]string{
			"xray-core": {"tls"},
			"sing-box":  {"tls"},
		},
		EngineFingerprints: map[string][]string{
			"xray-core": fields.OutboundFingerprintValues(),
			"sing-box":  fields.OutboundFingerprintValues(),
		},
		Tabs: []string{"basic", "protocol", "stream", "security", "sniffing", "advanced"},
	}
}
