package singbox

import (
	"github.com/blackalex1/sentinel-core/pkg/ast"
	"github.com/blackalex1/sentinel-core/pkg/i18n"
	"github.com/blackalex1/sentinel-core/pkg/matrix/fields"
	"github.com/blackalex1/sentinel-core/pkg/matrix/types"
)

// GetOutboundTUICCapability returns the capability definition for TUIC v5 outbound (sing-box only).
func GetOutboundTUICCapability(lang string) types.ProtocolCapability {
	loc := i18n.Locale(lang)
	return types.ProtocolCapability{
		Protocol:            ast.ProtoTUIC,
		DisplayName:         "TUIC v5",
		Description:         i18n.T(loc, "UI_OUTBOUND_TUIC_DESC"),
		DefaultPort:         8443,
		DefaultTransport:    "quic",
		DefaultSecurity:     "tls",
		SupportedEngines:    []string{"sing-box"},
		SupportedTransports: []string{"quic"},
		SupportedSecurity:   []string{"tls"},
		EngineTransports: map[string][]string{
			"sing-box": {"quic"},
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
								Placeholder: "tuic-proxy",
								GridColumn:  "col-6",
							},
							{
								ID:          "ob-tag",
								TargetField: "tag",
								Type:        "text",
								Label:       i18n.T(loc, "UI_FIELD_TAG"),
								Placeholder: "tuic-out",
								GridColumn:  "col-6",
							},
							{
								ID:          "ob-host",
								TargetField: "host",
								Type:        "text",
								Label:       i18n.T(loc, "UI_FIELD_SERVER_HOST"),
								Placeholder: "tuic.example.com",
								GridColumn:  "col-8",
							},
							{
								ID:          "ob-port",
								TargetField: "port",
								Type:        "text",
								Label:       i18n.T(loc, "UI_FIELD_PORT"),
								Default:     8443,
								GridColumn:  "col-4",
							},
							{
								ID:          "ob-uuid",
								TargetField: "uuid",
								Type:        "text",
								Label:       i18n.T(loc, "UI_FIELD_UUID"),
								Placeholder: "00000000-0000-0000-0000-000000000000",
								GridColumn:  "col-6",
							},
							{
								ID:          "ob-password",
								TargetField: "password",
								Type:        "password",
								Label:       i18n.T(loc, "UI_FIELD_PASSWORD"),
								Placeholder: "TUIC Password",
								GridColumn:  "col-6",
							},
							{
								ID:               "ob-tuic-cc",
								TargetField:      "congestionControl",
								Type:             "select",
								Label:            i18n.T(loc, "UI_FIELD_TUIC_CC"),
								Default:          "bbr",
								Options:          fields.OutboundTUICCongestionOptions(),
								SupportedEngines: []string{"sing-box"},
								GridColumn:       "col-4",
							},
							{
								ID:               "ob-tuic-udp-relay",
								TargetField:      "udpRelayMode",
								Type:             "select",
								Label:            i18n.T(loc, "UI_FIELD_TUIC_UDP_RELAY"),
								Default:          "native",
								Options:          fields.OutboundTUICUDPRelayOptions(),
								SupportedEngines: []string{"sing-box"},
								GridColumn:       "col-4",
							},
							{
								ID:               "ob-tuic-zero-rtt",
								TargetField:      "zeroRttHandshake",
								Type:             "checkbox",
								Label:            i18n.T(loc, "UI_FIELD_TUIC_ZERO_RTT"),
								Default:          false,
								SupportedEngines: []string{"sing-box"},
								GridColumn:       "col-4",
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
								Placeholder: "tuic.example.com",
								GridColumn:  "col-6",
							},
							{
								ID:          "ob-alpn",
								TargetField: "alpn",
								Type:        "text",
								Label:       i18n.T(loc, "UI_FIELD_ALPN"),
								Default:     "h3",
								Options:     fields.OutboundHysteriaALPNOptions(lang),
								Placeholder: "h3",
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
