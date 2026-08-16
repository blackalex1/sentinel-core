package xray

import (
	"github.com/blackalex1/sentinel-core/pkg/ast"
	"github.com/blackalex1/sentinel-core/pkg/i18n"
	"github.com/blackalex1/sentinel-core/pkg/matrix/fields"
	"github.com/blackalex1/sentinel-core/pkg/matrix/types"
)

// GetOutboundShadowsocksCapability returns the capability definition for Shadowsocks outbound
func GetOutboundShadowsocksCapability(lang string) types.ProtocolCapability {
	loc := i18n.Locale(lang)
	return types.ProtocolCapability{
		Protocol:         ast.ProtoShadowsocks,
		DisplayName:      "Shadowsocks",
		Description:      i18n.T(loc, "UI_OUTBOUND_SS_DESC"),
		DefaultPort:      8388,
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
								Placeholder: "ss-proxy",
								GridColumn:  "col-6",
							},
							{
								ID:          "ob-tag",
								TargetField: "tag",
								Type:        "text",
								Label:       i18n.T(loc, "UI_FIELD_TAG"),
								Placeholder: "ss-out",
								GridColumn:  "col-6",
							},
							{
								ID:          "ob-host",
								TargetField: "host",
								Type:        "text",
								Label:       i18n.T(loc, "UI_FIELD_SERVER_HOST"),
								Placeholder: "1.2.3.4",
								GridColumn:  "col-8",
							},
							{
								ID:          "ob-port",
								TargetField: "port",
								Type:        "number",
								Label:       i18n.T(loc, "UI_FIELD_PORT"),
								Default:     8388,
								GridColumn:  "col-4",
							},
							{
								ID:          "ob-method",
								TargetField: "method",
								Type:        "select",
								Label:       i18n.T(loc, "UI_FIELD_SS_METHOD"),
								Default:     "2022-blake3-aes-128-gcm",
								Options: []types.SelectOption{
									{Value: "2022-blake3-aes-128-gcm", Label: "2022-blake3-aes-128-gcm"},
									{Value: "2022-blake3-aes-256-gcm", Label: "2022-blake3-aes-256-gcm"},
									{Value: "2022-blake3-chacha20-poly1305", Label: "2022-blake3-chacha20-poly1305"},
									{Value: "aes-256-gcm", Label: "aes-256-gcm"},
									{Value: "aes-128-gcm", Label: "aes-128-gcm"},
									{Value: "chacha20-ietf-poly1305", Label: "chacha20-ietf-poly1305"},
								},
								GridColumn: "col-6",
							},
							{
								ID:          "ob-password",
								TargetField: "password",
								Type:        "password",
								Label:       i18n.T(loc, "UI_FIELD_PASSWORD"),
								Placeholder: "Base64 Key or Password",
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

// GetOutboundSSCapability is an alias for Shadowsocks
func GetOutboundSSCapability(lang string) types.ProtocolCapability {
	cap := GetOutboundShadowsocksCapability(lang)
	cap.Protocol = "ss"
	return cap
}
