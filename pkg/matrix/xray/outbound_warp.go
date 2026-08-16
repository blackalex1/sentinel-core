package xray

import (
	"github.com/blackalex1/sentinel-core/pkg/i18n"
	"github.com/blackalex1/sentinel-core/pkg/matrix/fields"
	"github.com/blackalex1/sentinel-core/pkg/matrix/types"
)

// GetOutboundWARPCapability returns the capability definition for Cloudflare WARP outbound
func GetOutboundWARPCapability(lang string) types.ProtocolCapability {
	loc := i18n.Locale(lang)
	return types.ProtocolCapability{
		Protocol:         "warp",
		DisplayName:      "Cloudflare WARP",
		Description:      i18n.T(loc, "UI_OUTBOUND_WARP_DESC"),
		DefaultPort:      2408,
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
								Placeholder: "warp-direct",
								Default:     "WARP Direct",
								GridColumn:  "col-6",
							},
							{
								ID:          "ob-tag",
								TargetField: "tag",
								Type:        "text",
								Label:       i18n.T(loc, "UI_FIELD_TAG"),
								Placeholder: "warp",
								Default:     "warp",
								GridColumn:  "col-6",
							},
							{
								ID:          "ob-host",
								TargetField: "host",
								Type:        "text",
								Label:       i18n.T(loc, "UI_FIELD_SERVER_HOST"),
								Placeholder: "162.159.192.1",
								Default:     "162.159.192.1",
								GridColumn:  "col-8",
							},
							{
								ID:          "ob-port",
								TargetField: "port",
								Type:        "number",
								Label:       i18n.T(loc, "UI_FIELD_PORT"),
								Default:     2408,
								GridColumn:  "col-4",
							},
							{
								ID:          "ob-private-key",
								TargetField: "privateKey",
								Type:        "password",
								Label:       i18n.T(loc, "UI_FIELD_PRIVATE_KEY"),
								Placeholder: "WARP Private Key",
								GridColumn:  "col-6",
							},
							{
								ID:          "ob-peer-public-key",
								TargetField: "peerPublicKey",
								Type:        "text",
								Label:       i18n.T(loc, "UI_FIELD_PEER_PUBLIC_KEY"),
								Placeholder: "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
								Default:     "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
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
