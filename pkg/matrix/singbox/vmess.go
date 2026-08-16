package singbox

import (
	"github.com/blackalex1/sentinel-core/pkg/ast"
	"github.com/blackalex1/sentinel-core/pkg/i18n"
	"github.com/blackalex1/sentinel-core/pkg/matrix/types"
)

func GetVMessCapability(lang string) types.ProtocolCapability {
	loc := i18n.Locale(lang)
	return types.ProtocolCapability{
		Protocol:            ast.ProtoVMess,
		DisplayName:         "VMess",
		Description:         i18n.T(loc, "PROTO_VMESS_DESC"),
		DefaultPort:         443,
		SupportedEngines:    []string{"xray-core", "sing-box"},
		SupportedTransports: []string{"tcp", "ws", "grpc", "http"},
		SupportedSecurity:   []string{"tls", "none"},
		Tabs:                []string{"basic", "stream", "security", "sniffing", "advanced"},
	}
}
