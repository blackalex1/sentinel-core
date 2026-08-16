package xray

import (
	"github.com/blackalex1/sentinel-core/pkg/i18n"
	"github.com/blackalex1/sentinel-core/pkg/matrix/types"
)

// GetOutboundBlackholeCapability returns the capability definition for Blackhole/Block outbound
func GetOutboundBlackholeCapability(lang string) types.ProtocolCapability {
	loc := i18n.Locale(lang)
	return types.ProtocolCapability{
		Protocol:         "blackhole",
		DisplayName:      "Blackhole / Block (" + i18n.T(loc, "UI_OUTBOUND_BLOCK") + ")",
		Description:      i18n.T(loc, "UI_OUTBOUND_BLOCK_DESC"),
		SupportedEngines: []string{"xray-core", "sing-box"},
		Tabs:             []string{"basic"},
		TabDefinitions: []types.TabDefinition{
			{
				ID:    "basic",
				Title: i18n.T(loc, "UI_TAB_BASIC"),
				Icon:  "fa-sliders",
				Groups: []types.FieldGroup{
					{
						ID: "basic_group",
						Fields: []types.FormField{
							{
								ID:          "ob-remark",
								TargetField: "remark",
								Type:        "text",
								Label:       i18n.T(loc, "UI_FIELD_REMARK"),
								Placeholder: "Block Outbound",
								GridColumn:  "col-6",
							},
							{
								ID:          "ob-tag",
								TargetField: "tag",
								Type:        "text",
								Label:       i18n.T(loc, "UI_FIELD_TAG"),
								Placeholder: "blocked",
								Default:     "blocked",
								GridColumn:  "col-6",
							},
						},
					},
				},
			},
		},
	}
}

// GetOutboundBlockCapability is an alias for Blackhole
func GetOutboundBlockCapability(lang string) types.ProtocolCapability {
	cap := GetOutboundBlackholeCapability(lang)
	cap.Protocol = "block"
	return cap
}
