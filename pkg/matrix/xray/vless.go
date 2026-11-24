package xray

import (
	"github.com/blackalex1/sentinel-core/pkg/ast"
	"github.com/blackalex1/sentinel-core/pkg/i18n"
	"github.com/blackalex1/sentinel-core/pkg/matrix/fields"
	"github.com/blackalex1/sentinel-core/pkg/matrix/types"
)

func GetVLESSCapability(lang string) types.ProtocolCapability {
	loc := i18n.Locale(lang)
	return types.ProtocolCapability{
		Protocol:            ast.ProtoVLESS,
		DisplayName:         "VLESS",
		Description:         i18n.T(loc, "PROTO_VLESS_DESC"),
		DefaultPort:         443,
		DefaultTransport:    "tcp",
		DefaultSecurity:     "reality",
		SupportedEngines:    []string{"xray-core", "sing-box"},
		SupportedTransports: []string{"tcp", "ws", "grpc", "xhttp", "httpupgrade", "h2", "mkcp"},
		SupportedSecurity:   []string{"reality", "tls", "none"},
		EngineTransports: map[string][]string{
			"xray-core": {"tcp", "ws", "grpc", "xhttp", "httpupgrade", "mkcp"},
			"sing-box":  {"tcp", "ws", "grpc", "httpupgrade", "h2"},
		},
		EngineSecurity: map[string][]string{
			"xray-core": {"reality", "tls", "none"},
			"sing-box":  {"reality", "tls", "none"},
		},
		EngineFingerprints: map[string][]string{
			"xray-core": fields.OutboundFingerprintValues(),
			"sing-box":  fields.OutboundFingerprintValues(),
		},
		SupportedFlows: map[string][]string{
			"reality": {"xtls-rprx-vision", "none"},
			"tls":     {"xtls-rprx-vision", "none"},
			"none":    {"none"},
		},
		Features:       []string{"post_quantum", "reality_short_ids", "spider_x"},
		Tabs:           []string{"basic", "protocol", "stream", "security", "sniffing", "advanced"},
		TabDefinitions: fields.BuildVLESSTabDefinitions(lang, true),
	}
}
