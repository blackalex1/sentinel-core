package xray

import (
	"github.com/blackalex1/sentinel-core/pkg/ast"
	"github.com/blackalex1/sentinel-core/pkg/i18n"
	"github.com/blackalex1/sentinel-core/pkg/matrix/fields"
	"github.com/blackalex1/sentinel-core/pkg/matrix/types"
)

// GetOutboundVLESSCapability returns the capability definition for VLESS outbound
func GetOutboundVLESSCapability(lang string) types.ProtocolCapability {
	loc := i18n.Locale(lang)
	return types.ProtocolCapability{
		Protocol:            ast.ProtoVLESS,
		DisplayName:         "VLESS",
		Description:         i18n.T(loc, "UI_OUTBOUND_VLESS_DESC"),
		DefaultPort:         443,
		SupportedEngines:    []string{"xray-core", "sing-box"},
		SupportedTransports: []string{"tcp", "ws", "grpc", "httpupgrade", "xhttp"},
		SupportedSecurity:   []string{"reality", "tls", "none"},
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
								Placeholder: "vless-proxy",
								GridColumn:  "col-6",
							},
							{
								ID:          "ob-tag",
								TargetField: "tag",
								Type:        "text",
								Label:       i18n.T(loc, "UI_FIELD_TAG"),
								Placeholder: "vless-out",
								GridColumn:  "col-6",
							},
							{
								ID:          "ob-host",
								TargetField: "host",
								Type:        "text",
								Label:       i18n.T(loc, "UI_FIELD_SERVER_HOST"),
								Placeholder: "192.168.1.1 or example.com",
								GridColumn:  "col-8",
							},
							{
								ID:          "ob-port",
								TargetField: "port",
								Type:        "number",
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
								GridColumn:  "col-12",
							},
							{
								ID:          "ob-flow",
								TargetField: "flow",
								Type:        "select",
								Label:       i18n.T(loc, "UI_FIELD_FLOW"),
								Default:     "",
								Options: []types.SelectOption{
									{Value: "", Label: i18n.T(loc, "UI_OPT_NO_FLOW")},
									{Value: "xtls-rprx-vision", Label: "xtls-rprx-vision"},
								},
								GridColumn: "col-6",
							},
							{
								ID:          "ob-vless-encryption",
								TargetField: "encryption",
								Type:        "text",
								Label:       i18n.T(loc, "UI_FIELD_VLESS_ENC"),
								Placeholder: "mlkem768x25519plus.native.OrtH...",
								GridColumn:  "col-6",
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
									{Value: "httpupgrade", Label: "HTTPUpgrade"},
									{Value: "xhttp", Label: "XHTTP / Split-HTTP"},
								},
								GridColumn: "col-12",
							},
							{
								ID:          "ob-path",
								TargetField: "path",
								Type:        "text",
								Label:       i18n.T(loc, "UI_FIELD_PATH"),
								Placeholder: "/ws",
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
							{
								ID:          "ob-service-name",
								TargetField: "serviceName",
								Type:        "text",
								Label:       i18n.T(loc, "UI_FIELD_GRPC_SERVICE_NAME"),
								Placeholder: "grpc-service",
								GridColumn:  "col-12",
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
								Default:     "reality",
								Options: []types.SelectOption{
									{Value: "reality", Label: "REALITY"},
									{Value: "tls", Label: "TLS"},
									{Value: "none", Label: "None (" + i18n.T(loc, "UI_OPT_NO_ENCRYPTION") + ")"},
								},
								GridColumn: "col-12",
							},
							{
								ID:          "ob-sni",
								TargetField: "sni",
								Type:        "text",
								Label:       i18n.T(loc, "UI_FIELD_SNI"),
								Placeholder: "www.microsoft.com",
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
									{Value: "ios", Label: "iOS"},
									{Value: "android", Label: "Android"},
									{Value: "edge", Label: "Edge"},
									{Value: "random", Label: "Random"},
								},
								GridColumn: "col-6",
							},
							{
								ID:          "ob-pbk",
								TargetField: "publicKey",
								Type:        "text",
								Label:       i18n.T(loc, "UI_FIELD_REALITY_PBK"),
								Placeholder: "Reality Public Key (x25519)",
								ShowIf:      map[string]interface{}{"security": "reality"},
								GridColumn:  "col-12",
							},
							{
								ID:          "ob-sid",
								TargetField: "shortId",
								Type:        "text",
								Label:       i18n.T(loc, "UI_FIELD_SHORT_ID"),
								Placeholder: "0123456789abcdef",
								ShowIf:      map[string]interface{}{"security": "reality"},
								GridColumn:  "col-6",
							},
							{
								ID:          "ob-spx",
								TargetField: "spiderX",
								Type:        "text",
								Label:       i18n.T(loc, "UI_FIELD_SPIDER_X"),
								Placeholder: "/",
								ShowIf:      map[string]interface{}{"security": "reality"},
								GridColumn:  "col-6",
							},
							{
								ID:          "ob-alpn",
								TargetField: "alpn",
								Type:        "text",
								Label:       i18n.T(loc, "UI_FIELD_ALPN"),
								Placeholder: "h2,http/1.1",
								ShowIf:      map[string]interface{}{"security": "tls"},
								GridColumn:  "col-6",
							},
							{
								ID:          "ob-insecure",
								TargetField: "allowInsecure",
								Type:        "checkbox",
								Label:       i18n.T(loc, "UI_FIELD_ALLOW_INSECURE"),
								ShowIf:      map[string]interface{}{"security": "tls"},
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
