package singbox

import (
	"github.com/blackalex1/sentinel-core/pkg/ast"
	"github.com/blackalex1/sentinel-core/pkg/i18n"
	"github.com/blackalex1/sentinel-core/pkg/matrix/types"
)

func GetShadowTLSCapability(lang string) types.ProtocolCapability {
	loc := i18n.Locale(lang)
	return types.ProtocolCapability{
		Protocol:          ast.ProtoShadowTLS,
		DisplayName:       "ShadowTLS",
		Description:       i18n.T(loc, "PROTO_SHADOWTLS_DESC"),
		DefaultPort:       443,
		SupportedEngines:   []string{"sing-box"},
		SupportedSecurity: []string{"shadowtls"},
		Features:          []string{"shadowtls_v3", "handshake_mimic"},
		Tabs:              []string{"basic", "stream", "security", "sniffing", "advanced"},
	}
}
