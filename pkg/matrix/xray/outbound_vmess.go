package xray

import (
	"github.com/blackalex1/sentinel-core/pkg/ast"
	"github.com/blackalex1/sentinel-core/pkg/i18n"
	"github.com/blackalex1/sentinel-core/pkg/matrix/fields"
	"github.com/blackalex1/sentinel-core/pkg/matrix/types"
)

// GetOutboundVMessCapability returns the capability definition for VMess outbound
func GetOutboundVMessCapability(lang string) types.ProtocolCapability {
	loc := i18n.Locale(lang)
	return types.ProtocolCapability{
		Protocol:            ast.ProtoVMess,
		DisplayName:         "VMess",
		Description:         i18n.T(loc, "UI_OUTBOUND_VMESS_DESC"),
		DefaultPort:         443,
		SupportedEngines:    []string{"xray-core", "sing-box"},
		SupportedTransports: []string{"tcp", "ws", "grpc", "httpupgrade"},
		SupportedSecurity:   []string{"tls", "none"},
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
								Placeholder: "vmess-proxy",
								GridColumn:  "col-6",
							},
							{
								ID:          "ob-tag",
								TargetField: "tag",
								Type:        "text",
								Label:       i18n.T(loc, "UI_FIELD_TAG"),
								Placeholder: "vmess-out",
								GridColumn:  "col-6",
							},
							{
								ID:          "ob-host",
								TargetField: "host",
								Type:        "text",
								Label:       i18n.T(loc, "UI_FIELD_SERVER_HOST"),
								Placeholder: "vmess.example.com",
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
								ID:          "ob-uuid",
								TargetField: "uuid",
								Type:        "text",
								Label:       i18n.T(loc, "UI_FIELD_UUID"),
								Placeholder: "00000000-0000-0000-0000-000000000000",
								GridColumn:  "col-8",
							},
							{
								ID:          "ob-alterid",
								TargetField: "alterId",
								Type:        "number",
								Label:       i18n.T(loc, "UI_FIELD_ALTER_ID"),
								Default:     0,
								GridColumn:  "col-4",
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
								Default:     "ws",
								Options: []types.SelectOption{
									{Value: "ws", Label: "WebSocket (WS)"},
									{Value: "tcp", Label: "TCP"},
									{Value: "grpc", Label: "gRPC"},
									{Value: "httpupgrade", Label: "HTTPUpgrade"},
								},
								GridColumn: "col-12",
							},
							{
								ID:          "ob-path",
								TargetField: "path",
								Type:        "text",
								Label:       i18n.T(loc, "UI_FIELD_PATH"),
								Placeholder: "/vmess-ws",
								GridColumn:  "col-6",
							},
							{
								ID:          "ob-ws-host",
								TargetField: "wsHost",
								Type:        "text",
								Label:       i18n.T(loc, "UI_FIELD_WS_HOST"),
								Placeholder: "domain.com",
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
									{Value: "none", Label: "None"},
								},
								GridColumn: "col-12",
							},
							{
								ID:          "ob-sni",
								TargetField: "sni",
								Type:        "text",
								Label:       i18n.T(loc, "UI_FIELD_SNI"),
								Placeholder: "vmess.example.com",
								GridColumn:  "col-6",
							},
							{
								ID:          "ob-alpn",
								TargetField: "alpn",
								Type:        "text",
								Label:       i18n.T(loc, "UI_FIELD_ALPN"),
								Placeholder: "h2,http/1.1",
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
