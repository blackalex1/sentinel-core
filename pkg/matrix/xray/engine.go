package xray

import (
	"github.com/blackalex1/sentinel-core/pkg/ast"
	"github.com/blackalex1/sentinel-core/pkg/i18n"
	"github.com/blackalex1/sentinel-core/pkg/matrix/types"
)

func GetEngineOption(lang string) types.EngineOption {
	loc := i18n.Locale(lang)
	return types.EngineOption{
		ID:          "xray-core",
		Name:        i18n.T(loc, "ENGINE_XRAY_NAME"),
		Description: i18n.T(loc, "ENGINE_XRAY_DESC"),
		Protocols:   []string{ast.ProtoVLESS, ast.ProtoTrojan, ast.ProtoShadowsocks, ast.ProtoVMess, ast.ProtoWireGuard},
	}
}
