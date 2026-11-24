package xray

import (
	"github.com/blackalex1/sentinel-core/pkg/ast"
	"github.com/blackalex1/sentinel-core/pkg/i18n"
	"github.com/blackalex1/sentinel-core/pkg/matrix/fields"
	"github.com/blackalex1/sentinel-core/pkg/matrix/types"
)

func GetVMessCapability(lang string) types.ProtocolCapability {
	loc := i18n.Locale(lang)
	return types.ProtocolCapability{
		Protocol:            ast.ProtoVMess,
		DisplayName:         "VMess",
		Description:         i18n.T(loc, "PROTO_VMESS_DESC"),
		DefaultPort:         443,
		DefaultTransport:    "ws",
		DefaultSecurity:     "tls",
		SupportedEngines:    []string{"xray-core", "sing-box"},
		SupportedTransports: []string{"tcp", "ws", "grpc", "http"},
		SupportedSecurity:   []string{"tls", "none"},
		EngineTransports: map[string][]string{
			"xray-core": {"tcp", "ws", "grpc", "http"},
			"sing-box":  {"tcp", "ws", "grpc", "http"},
		},
		EngineSecurity: map[string][]string{
			"xray-core": {"tls", "none"},
			"sing-box":  {"tls", "none"},
		},
		EngineFingerprints: map[string][]string{
			"xray-core": fields.OutboundFingerprintValues(),
			"sing-box":  fields.OutboundFingerprintValues(),
		},
		Tabs: []string{"basic", "stream", "security", "sniffing", "advanced"},
	}
}
