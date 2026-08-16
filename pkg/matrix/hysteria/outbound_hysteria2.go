package hysteria

import (
	"github.com/blackalex1/sentinel-core/pkg/ast"
	"github.com/blackalex1/sentinel-core/pkg/i18n"
	"github.com/blackalex1/sentinel-core/pkg/matrix/fields"
	"github.com/blackalex1/sentinel-core/pkg/matrix/types"
)

// GetOutboundHysteria2Capability returns the capability definition for Hysteria 2 outbound
func GetOutboundHysteria2Capability(lang string) types.ProtocolCapability {
	loc := i18n.Locale(lang)
	return types.ProtocolCapability{
		Protocol:         ast.ProtoHysteria2,
		DisplayName:      "Hysteria 2",
		Description:      i18n.T(loc, "UI_OUTBOUND_HYSTERIA2_DESC"),
		DefaultPort:      443,
		SupportedEngines: []string{"hysteria2", "sing-box"},
		Tabs:             []string{"basic", "security", "fallbacks"},
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
								Placeholder: "hy2-proxy",
								GridColumn:  "col-6",
							},
							{
								ID:          "ob-tag",
								TargetField: "tag",
								Type:        "text",
								Label:       i18n.T(loc, "UI_FIELD_TAG"),
								Placeholder: "hysteria2-out",
								GridColumn:  "col-6",
							},
							{
								ID:          "ob-host",
								TargetField: "host",
								Type:        "text",
								Label:       i18n.T(loc, "UI_FIELD_SERVER_HOST"),
								Placeholder: "hy2.example.com",
								GridColumn:  "col-8",
							},
							{
								ID:          "ob-port",
								TargetField: "port",
								Type:        "text",
								Label:       i18n.T(loc, "UI_FIELD_PORT"),
								Placeholder: "443",
								Default:     443,
								GridColumn:  "col-4",
							},
							{
								ID:          "ob-password",
								TargetField: "password",
								Type:        "password",
								Label:       i18n.T(loc, "UI_FIELD_PASSWORD"),
								Placeholder: "Hysteria2 Auth Password",
								GridColumn:  "col-12",
							},
							{
								ID:          "ob-up-mbps",
								TargetField: "upMbps",
								Type:        "number",
								Label:       i18n.T(loc, "UI_FIELD_UP_MBPS"),
								Default:     100,
								GridColumn:  "col-6",
							},
							{
								ID:          "ob-down-mbps",
								TargetField: "downMbps",
								Type:        "number",
								Label:       i18n.T(loc, "UI_FIELD_DOWN_MBPS"),
								Default:     100,
								GridColumn:  "col-6",
							},
						},
					},
				},
			},
			{
				ID:    "security",
				Title: i18n.T(loc, "UI_TAB_SECURITY"),
				Icon:  "fa-lock",
				Groups: []types.FieldGroup{
					{
						ID: "security_group",
						Fields: []types.FormField{
							{
								ID:          "ob-sni",
								TargetField: "sni",
								Type:        "text",
								Label:       i18n.T(loc, "UI_FIELD_SNI"),
								Placeholder: "hy2.example.com",
								GridColumn:  "col-6",
							},
							{
								ID:          "ob-pin-sha256",
								TargetField: "pinnedPeerCertSha256",
								Type:        "text",
								Label:       i18n.T(loc, "UI_FIELD_PIN_SHA256"),
								Placeholder: "SHA256 Fingerprint",
								GridColumn:  "col-6",
							},
							{
								ID:          "ob-obfs-type",
								TargetField: "obfs",
								Type:        "select",
								Label:       i18n.T(loc, "UI_FIELD_OBFS_TYPE"),
								Default:     "",
								Options: []types.SelectOption{
									{Value: "", Label: i18n.T(loc, "UI_OPT_NONE")},
									{Value: "salamander", Label: "Salamander (Обфускация)"},
								},
								GridColumn: "col-6",
							},
							{
								ID:          "ob-obfs-password",
								TargetField: "obfsPassword",
								Type:        "password",
								Label:       i18n.T(loc, "UI_FIELD_OBFS_PASSWORD"),
								Placeholder: "Salamander Secret",
								GridColumn:  "col-6",
							},
							{
								ID:          "ob-insecure",
								TargetField: "allowInsecure",
								Type:        "checkbox",
								Label:       i18n.T(loc, "UI_FIELD_ALLOW_INSECURE"),
								Default:     false,
								GridColumn:  "col-12",
							},
						},
					},
				},
			},
			fields.BuildOutboundFallbackTab(lang),
		},
	}
}
