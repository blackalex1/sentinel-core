package matrix

import (
	"strings"

	"github.com/blackalex1/sentinel-core/pkg/ast"
	"github.com/blackalex1/sentinel-core/pkg/i18n"
	"github.com/blackalex1/sentinel-core/pkg/matrix/hysteria"
	"github.com/blackalex1/sentinel-core/pkg/matrix/singbox"
	"github.com/blackalex1/sentinel-core/pkg/matrix/types"
	"github.com/blackalex1/sentinel-core/pkg/matrix/xray"
	"github.com/blackalex1/sentinel-core/pkg/routing"
)

// GetConfigurationSchema returns the dynamic schema localized for the requested language ("ru" / "en")
func GetConfigurationSchema(lang string) *types.ConfigurationSchema {
	langLower := strings.ToLower(lang)
	if langLower == "" {
		langLower = string(i18n.GetLocale())
	}
	if langLower != "en" && langLower != "ru" {
		langLower = "ru"
	}

	return &types.ConfigurationSchema{
		Language: langLower,
		Engines: []types.EngineOption{
			xray.GetEngineOption(langLower),
			singbox.GetEngineOption(langLower),
			hysteria.GetEngineOption(langLower),
		},
		Protocols: map[string]types.ProtocolCapability{
			ast.ProtoVLESS:       xray.GetVLESSCapability(langLower),
			ast.ProtoHysteria2:   hysteria.GetHysteria2Capability(langLower),
			ast.ProtoTrojan:      xray.GetTrojanCapability(langLower),
			ast.ProtoShadowsocks: xray.GetShadowsocksCapability(langLower),
			ast.ProtoTUIC:        singbox.GetTUICCapability(langLower),
			ast.ProtoShadowTLS:   singbox.GetShadowTLSCapability(langLower),
			ast.ProtoWireGuard:   xray.GetWireGuardCapability(langLower),
			ast.ProtoVMess:       xray.GetVMessCapability(langLower),
		},
		OutboundProtocols: map[string]types.ProtocolCapability{
			"freedom":            xray.GetOutboundFreedomCapability(langLower),
			"direct":             xray.GetOutboundDirectCapability(langLower),
			"blackhole":          xray.GetOutboundBlackholeCapability(langLower),
			"block":              xray.GetOutboundBlockCapability(langLower),
			ast.ProtoVLESS:       xray.GetOutboundVLESSCapability(langLower),
			ast.ProtoHysteria2:   hysteria.GetOutboundHysteria2Capability(langLower),
			ast.ProtoTrojan:      xray.GetOutboundTrojanCapability(langLower),
			ast.ProtoShadowsocks: xray.GetOutboundShadowsocksCapability(langLower),
			"ss":                 xray.GetOutboundSSCapability(langLower),
			ast.ProtoVMess:       xray.GetOutboundVMessCapability(langLower),
			ast.ProtoWireGuard:   xray.GetOutboundWireGuardCapability(langLower),
			"wg":                 xray.GetOutboundWGCapability(langLower),
			"warp":               xray.GetOutboundWARPCapability(langLower),
			"socks":              xray.GetOutboundSocksCapability(langLower),
			"socks5":             xray.GetOutboundSocks5Capability(langLower),
			"http":               xray.GetOutboundHTTPCapability(langLower),
		},
		SniffingOptions: GetSniffingOptions(langLower),
		Presets:         routing.GetAvailablePresetsLocalized(langLower),
	}
}
