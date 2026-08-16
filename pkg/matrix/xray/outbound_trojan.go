package xray

import (
	"github.com/blackalex1/sentinel-core/pkg/ast"
	"github.com/blackalex1/sentinel-core/pkg/i18n"
	"github.com/blackalex1/sentinel-core/pkg/matrix/fields"
	"github.com/blackalex1/sentinel-core/pkg/matrix/types"
)

// GetOutboundTrojanCapability returns the capability definition for Trojan outbound
func GetOutboundTrojanCapability(lang string) types.ProtocolCapability {
	loc := i18n.Locale(lang)
	return types.ProtocolCapability{
		Protocol:            ast.ProtoTrojan,
		DisplayName:         "Trojan",
		Description:         i18n.T(loc, "UI_OUTBOUND_TROJAN_DESC"),
		DefaultPort:         443,
		SupportedEngines:    []string{"xray-core", "sing-box"},
		SupportedTransports: []string{"tcp", "ws", "grpc"},
		SupportedSecurity:   []string{"tls", "reality", "none"},
		Tabs:                []string{"basic", "transport", "security", "fallbacks"},
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
								Placeholder: "trojan-proxy",
								GridColumn:  "col-6",
							},
							{
								ID:          "ob-tag",
								TargetField: "tag",
								Type:        "text",
								Label:       i18n.T(loc, "UI_FIELD_TAG"),
								Placeholder: "trojan-out",
								GridColumn:  "col-6",
							},
							{
								ID:          "ob-host",
								TargetField: "host",
								Type:        "text",
								Label:       i18n.T(loc, "UI_FIELD_SERVER_HOST"),
								Placeholder: "trojan.example.com",
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
								ID:          "ob-password",
								TargetField: "password",
								Type:        "password",
								Label:       i18n.T(loc, "UI_FIELD_PASSWORD"),
								Placeholder: "Trojan Password",
								GridColumn:  "col-12",
							},
						},
					},
				},
			},
			{
				ID:    "transport",
				Title: i18n.T(loc, "UI_TAB_TRANSPORT"),
				Icon:  "fa-network-wired",
				Groups: []types.FieldGroup{
					{
						ID: "transport_group",
						Fields: []types.FormField{
							{
								ID:          "ob-network",
								TargetField: "network",
								Type:        "select",
								Label:       i18n.T(loc, "UI_FIELD_NETWORK"),
								Default:     "tcp",
								Options: []types.SelectOption{
									{Value: "tcp", Label: "TCP"},
									{Value: "ws", Label: "WebSocket (WS)"},
									{Value: "grpc", Label: "gRPC"},
								},
								GridColumn: "col-12",
							},
							{
								ID:          "ob-path",
								TargetField: "path",
								Type:        "text",
								Label:       i18n.T(loc, "UI_FIELD_PATH"),
								Placeholder: "/trojan-ws",
								GridColumn:  "col-6",
							},
							{
								ID:          "ob-service-name",
								TargetField: "serviceName",
								Type:        "text",
								Label:       i18n.T(loc, "UI_FIELD_GRPC_SERVICE_NAME"),
								Placeholder: "trojan-grpc",
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
								ID:          "ob-security",
								TargetField: "security",
								Type:        "select",
								Label:       i18n.T(loc, "UI_FIELD_SECURITY"),
								Default:     "tls",
								Options: []types.SelectOption{
									{Value: "tls", Label: "TLS"},
									{Value: "reality", Label: "REALITY"},
									{Value: "none", Label: "None"},
								},
								GridColumn: "col-12",
							},
							{
								ID:          "ob-sni",
								TargetField: "sni",
								Type:        "text",
								Label:       i18n.T(loc, "UI_FIELD_SNI"),
								Placeholder: "trojan.example.com",
								GridColumn:  "col-6",
							},
							{
								ID:          "ob-fp",
								TargetField: "fingerprint",
								Type:        "select",
								Label:       i18n.T(loc, "UI_FIELD_FINGERPRINT"),
								Default:     "chrome",
								Options: []types.SelectOption{
									{Value: "chrome", Label: "Chrome"},
									{Value: "firefox", Label: "Firefox"},
									{Value: "safari", Label: "Safari"},
								},
								GridColumn: "col-6",
							},
							{
								ID:          "ob-alpn",
								TargetField: "alpn",
								Type:        "text",
								Label:       i18n.T(loc, "UI_FIELD_ALPN"),
								Placeholder: "h2,http/1.1",
								GridColumn:  "col-6",
							},
							{
								ID:          "ob-insecure",
								TargetField: "allowInsecure",
								Type:        "checkbox",
								Label:       i18n.T(loc, "UI_FIELD_ALLOW_INSECURE"),
								Default:     false,
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
