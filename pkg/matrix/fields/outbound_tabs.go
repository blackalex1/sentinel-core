package fields

import (
	"github.com/blackalex1/sentinel-core/pkg/i18n"
	"github.com/blackalex1/sentinel-core/pkg/matrix/types"
)

// BuildOutboundFallbackTab returns the standard fallback and failover route tab definition
func BuildOutboundFallbackTab(lang string) types.TabDefinition {
	loc := i18n.Locale(lang)
	return types.TabDefinition{
		ID:    "fallbacks",
		Title: i18n.T(loc, "UI_TAB_FALLBACKS"),
		Icon:  "fa-shield-halved",
		Groups: []types.FieldGroup{
			{
				ID:          "fallback_group",
				Title:       i18n.T(loc, "UI_GROUP_FALLBACKS"),
				Description: i18n.T(loc, "UI_GROUP_FALLBACKS_DESC"),
				Fields: []types.FormField{
					{
						ID:          "fallback_outbound",
						TargetField: "fallback_outbound",
						Type:        "select",
						Label:       i18n.T(loc, "UI_FIELD_FALLBACK_ROUTE"),
						HelpText:    i18n.T(loc, "UI_HELP_FALLBACK_ROUTE"),
						GridColumn:  "col-12",
					},
				},
			},
		},
	}
}
