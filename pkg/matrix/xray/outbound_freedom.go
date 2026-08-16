package xray

import (
	"github.com/blackalex1/sentinel-core/pkg/i18n"
	"github.com/blackalex1/sentinel-core/pkg/matrix/types"
)

// GetOutboundFreedomCapability returns the capability definition for Freedom/Direct outbound
func GetOutboundFreedomCapability(lang string) types.ProtocolCapability {
	loc := i18n.Locale(lang)
	return types.ProtocolCapability{
		Protocol:         "freedom",
		DisplayName:      "Freedom / Direct (" + i18n.T(loc, "UI_OUTBOUND_DIRECT") + ")",
		Description:      i18n.T(loc, "UI_OUTBOUND_DIRECT_DESC"),
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
								Placeholder: "Direct Outbound",
								GridColumn:  "col-6",
							},
							{
								ID:          "ob-tag",
								TargetField: "tag",
								Type:        "text",
								Label:       i18n.T(loc, "UI_FIELD_TAG"),
								Placeholder: "direct",
								Default:     "direct",
								GridColumn:  "col-6",
							},
							{
								ID:          "ob-domain-strategy",
								TargetField: "domainStrategy",
								Type:        "select",
								Label:       i18n.T(loc, "UI_FIELD_DOMAIN_STRATEGY"),
								Default:     "AsIs",
								Options: []types.SelectOption{
									{Value: "AsIs", Label: "AsIs (Без резолва)"},
									{Value: "UseIP", Label: "UseIP (Резолв DNS)"},
									{Value: "UseIPv4", Label: "UseIPv4"},
									{Value: "UseIPv6", Label: "UseIPv6"},
								},
								GridColumn: "col-12",
							},
						},
					},
				},
			},
		},
	}
}

// GetOutboundDirectCapability is an alias for Freedom
func GetOutboundDirectCapability(lang string) types.ProtocolCapability {
	cap := GetOutboundFreedomCapability(lang)
	cap.Protocol = "direct"
	return cap
}
