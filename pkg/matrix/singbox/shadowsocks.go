package singbox

import (
	"github.com/blackalex1/sentinel-core/pkg/ast"
	"github.com/blackalex1/sentinel-core/pkg/i18n"
	"github.com/blackalex1/sentinel-core/pkg/matrix/types"
)

func GetShadowsocksCapability(lang string) types.ProtocolCapability {
	loc := i18n.Locale(lang)
	return types.ProtocolCapability{
		Protocol:         ast.ProtoShadowsocks,
		DisplayName:      "Shadowsocks",
		Description:      i18n.T(loc, "PROTO_SHADOWSOCKS_DESC"),
		DefaultPort:      8388,
		SupportedEngines:  []string{"xray-core", "sing-box"},
		SupportedSecurity: []string{"none"},
		SupportedCiphers: []string{
			"2022-blake3-aes-128-gcm",
			"2022-blake3-aes-256-gcm",
			"2022-blake3-chacha20-poly1305",
			"aes-128-gcm",
			"aes-256-gcm",
			"chacha20-ietf-poly1305",
		},
		Tabs: []string{"basic", "protocol", "sniffing", "advanced"},
	}
}
