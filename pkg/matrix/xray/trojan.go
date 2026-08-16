package xray

import (
	"github.com/blackalex1/sentinel-core/pkg/ast"
	"github.com/blackalex1/sentinel-core/pkg/i18n"
	"github.com/blackalex1/sentinel-core/pkg/matrix/types"
)

func GetTrojanCapability(lang string) types.ProtocolCapability {
	loc := i18n.Locale(lang)
	return types.ProtocolCapability{
		Protocol:            ast.ProtoTrojan,
		DisplayName:         "Trojan",
		Description:         i18n.T(loc, "PROTO_TROJAN_DESC"),
		DefaultPort:         443,
		SupportedEngines:    []string{"xray-core", "sing-box"},
		SupportedTransports: []string{"tcp", "ws", "grpc"},
		SupportedSecurity:   []string{"tls"},
		Tabs:                []string{"basic", "protocol", "stream", "security", "sniffing", "advanced"},
	}
}
