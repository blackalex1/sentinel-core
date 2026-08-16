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
					{
						ID:          "fallback_strategy",
						TargetField: "fallback_strategy",
						Type:        "select",
						Label:       i18n.T(loc, "UI_FIELD_FALLBACK_STRATEGY"),
						HelpText:    i18n.T(loc, "UI_HELP_FALLBACK_STRATEGY"),
						Default:     "priority",
						Options: []types.SelectOption{
							{Value: "priority", Label: i18n.T(loc, "UI_STRATEGY_PRIORITY")},
							{Value: "least_ping", Label: i18n.T(loc, "UI_STRATEGY_LEAST_PING")},
							{Value: "round_robin", Label: i18n.T(loc, "UI_STRATEGY_ROUND_ROBIN")},
						},
						GridColumn: "col-12",
					},
					{
						ID:          "health_check_interval",
						TargetField: "health_check_interval",
						Type:        "number",
						Label:       i18n.T(loc, "UI_FIELD_HEALTH_CHECK_INT"),
						HelpText:    i18n.T(loc, "UI_HELP_HEALTH_CHECK_INT"),
						Default:     300,
						GridColumn:  "col-6",
					},
				},
			},
		},
	}
}
