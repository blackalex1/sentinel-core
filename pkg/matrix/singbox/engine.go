package singbox

import (
	"github.com/blackalex1/sentinel-core/pkg/ast"
	"github.com/blackalex1/sentinel-core/pkg/i18n"
	"github.com/blackalex1/sentinel-core/pkg/matrix/types"
)

func GetEngineOption(lang string) types.EngineOption {
	loc := i18n.Locale(lang)
	return types.EngineOption{
		ID:          "sing-box",
		Name:        i18n.T(loc, "ENGINE_SINGBOX_NAME"),
		Description: i18n.T(loc, "ENGINE_SINGBOX_DESC"),
		Protocols:   []string{ast.ProtoVLESS, ast.ProtoHysteria2, ast.ProtoTUIC, ast.ProtoTrojan, ast.ProtoShadowsocks, ast.ProtoShadowTLS, ast.ProtoWireGuard, ast.ProtoVMess},
	}
}
