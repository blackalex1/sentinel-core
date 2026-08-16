package hysteria

import (
	"github.com/blackalex1/sentinel-core/pkg/ast"
	"github.com/blackalex1/sentinel-core/pkg/i18n"
	"github.com/blackalex1/sentinel-core/pkg/matrix/types"
)

func GetEngineOption(lang string) types.EngineOption {
	loc := i18n.Locale(lang)
	return types.EngineOption{
		ID:          "hysteria2",
		Name:        i18n.T(loc, "ENGINE_HYSTERIA_NAME"),
		Description: i18n.T(loc, "ENGINE_HYSTERIA_DESC"),
		Protocols:   []string{ast.ProtoHysteria2},
	}
}
