package xray

import (
	"github.com/blackalex1/sentinel-core/pkg/i18n"
	"github.com/blackalex1/sentinel-core/pkg/matrix/fields"
	"github.com/blackalex1/sentinel-core/pkg/matrix/types"
)

// GetOutboundSocksCapability returns the capability definition for SOCKS5 outbound
func GetOutboundSocksCapability(lang string) types.ProtocolCapability {
	loc := i18n.Locale(lang)
	return types.ProtocolCapability{
		Protocol:         "socks",
		DisplayName:      "SOCKS5",
		Description:      i18n.T(loc, "UI_OUTBOUND_SOCKS_DESC"),
		DefaultPort:      1080,
		SupportedEngines: []string{"xray-core", "sing-box"},
		Tabs:             []string{"basic", "fallbacks"},
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
								Placeholder: "socks-proxy",
								GridColumn:  "col-6",
							},
							{
								ID:          "ob-tag",
								TargetField: "tag",
								Type:        "text",
								Label:       i18n.T(loc, "UI_FIELD_TAG"),
								Placeholder: "socks-out",
								GridColumn:  "col-6",
							},
							{
								ID:          "ob-host",
								TargetField: "host",
								Type:        "text",
								Label:       i18n.T(loc, "UI_FIELD_SERVER_HOST"),
								Placeholder: "127.0.0.1",
								GridColumn:  "col-8",
							},
							{
								ID:          "ob-port",
								TargetField: "port",
								Type:        "text",
								Label:       i18n.T(loc, "UI_FIELD_PORT"),
								Default:     1080,
								GridColumn:  "col-4",
							},
							{
								ID:          "ob-user",
								TargetField: "user",
								Type:        "text",
								Label:       i18n.T(loc, "UI_FIELD_USERNAME"),
								Placeholder: "user (optional)",
								GridColumn:  "col-6",
							},
							{
								ID:          "ob-pass",
								TargetField: "pass",
								Type:        "password",
								Label:       i18n.T(loc, "UI_FIELD_PASSWORD"),
								Placeholder: "pass (optional)",
								GridColumn:  "col-6",
							},
						},
					},
				},
			},
			fields.BuildOutboundFallbackTab(lang),
		},
	}
}

// GetOutboundSocks5Capability is an alias for SOCKS5
func GetOutboundSocks5Capability(lang string) types.ProtocolCapability {
	cap := GetOutboundSocksCapability(lang)
	cap.Protocol = "socks5"
	return cap
}
