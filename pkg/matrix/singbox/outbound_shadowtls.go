package singbox

import (
	"github.com/blackalex1/sentinel-core/pkg/ast"
	"github.com/blackalex1/sentinel-core/pkg/i18n"
	"github.com/blackalex1/sentinel-core/pkg/matrix/fields"
	"github.com/blackalex1/sentinel-core/pkg/matrix/types"
)

// GetOutboundShadowTLSCapability returns the capability definition for ShadowTLS outbound (sing-box only).
func GetOutboundShadowTLSCapability(lang string) types.ProtocolCapability {
	loc := i18n.Locale(lang)
	return types.ProtocolCapability{
		Protocol:            ast.ProtoShadowTLS,
		DisplayName:         "ShadowTLS",
		Description:         i18n.T(loc, "UI_OUTBOUND_SHADOWTLS_DESC"),
		DefaultPort:         443,
		DefaultTransport:    "tcp",
		DefaultSecurity:     "tls",
		SupportedEngines:    []string{"sing-box"},
		SupportedTransports: []string{"tcp"},
		SupportedSecurity:   []string{"tls"},
		EngineTransports: map[string][]string{
			"sing-box": {"tcp"},
		},
		EngineSecurity: map[string][]string{
			"sing-box": {"tls"},
		},
		Tabs: []string{"basic", "security", "fallbacks"},
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
								Placeholder: "shadowtls-proxy",
								GridColumn:  "col-6",
							},
							{
								ID:          "ob-tag",
								TargetField: "tag",
								Type:        "text",
								Label:       i18n.T(loc, "UI_FIELD_TAG"),
								Placeholder: "shadowtls-out",
								GridColumn:  "col-6",
							},
							{
								ID:          "ob-host",
								TargetField: "host",
								Type:        "text",
								Label:       i18n.T(loc, "UI_FIELD_SERVER_HOST"),
								Placeholder: "shadowtls.example.com",
								GridColumn:  "col-8",
							},
							{
								ID:          "ob-port",
								TargetField: "port",
								Type:        "text",
								Label:       i18n.T(loc, "UI_FIELD_PORT"),
								Default:     443,
								GridColumn:  "col-4",
							},
							{
								ID:               "ob-shadowtls-version",
								TargetField:      "shadowTlsVersion",
								Type:             "select",
								Label:            i18n.T(loc, "UI_FIELD_SHADOWTLS_VERSION"),
								Default:          "3",
								Options:          fields.OutboundShadowTLSVersionOptions(),
								SupportedEngines: []string{"sing-box"},
								GridColumn:       "col-4",
							},
							{
								ID:          "ob-password",
								TargetField: "password",
								Type:        "password",
								Label:       i18n.T(loc, "UI_FIELD_PASSWORD"),
								Placeholder: "ShadowTLS Password",
								GridColumn:  "col-8",
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
								Label:       i18n.T(loc, "UI_FIELD_SHADOWTLS_SNI"),
								Placeholder: "www.apple.com",
								GridColumn:  "col-6",
							},
							{
								ID:          "ob-fp",
								TargetField: "fingerprint",
								Type:        "select",
								Label:       i18n.T(loc, "UI_FIELD_FINGERPRINT"),
								Default:     "chrome",
								Options:     fields.OutboundFingerprintOptions(),
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
