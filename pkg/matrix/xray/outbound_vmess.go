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
	engineTransports := map[string][]string{
		"xray-core": {"ws", "tcp", "grpc", "httpupgrade"},
		"sing-box":  {"ws", "tcp", "grpc", "httpupgrade", "h2"},
	}
	engineSecurity := map[string][]string{
		"xray-core": {"tls", "none"},
		"sing-box":  {"tls", "none"},
	}
	return types.ProtocolCapability{
		Protocol:            ast.ProtoVMess,
		DisplayName:         "VMess",
		Description:         i18n.T(loc, "UI_OUTBOUND_VMESS_DESC"),
		DefaultPort:         443,
		DefaultTransport:    "ws",
		DefaultSecurity:     "tls",
		SupportedEngines:    []string{"xray-core", "sing-box"},
		SupportedTransports: []string{"tcp", "ws", "grpc", "httpupgrade", "h2"},
		SupportedSecurity:   []string{"tls", "none"},
		EngineTransports:    engineTransports,
		EngineSecurity:      engineSecurity,
		EngineFingerprints: map[string][]string{
			"xray-core": fields.OutboundFingerprintValues(),
			"sing-box":  fields.OutboundFingerprintValues(),
		},
		Tabs: []string{"basic", "transport", "security", "fallbacks"},
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
								Options:     fields.OutboundNetworkOptionsFor([]string{"ws", "tcp", "grpc", "httpupgrade", "h2"}, engineTransports),
								GridColumn:  "col-12",
							},
							{
								ID:               "ob-header-type",
								TargetField:      "headerType",
								Type:             "select",
								Label:            i18n.T(loc, "UI_FIELD_HEADER_TYPE"),
								Default:          "",
								Options:          fields.OutboundTCPHeaderTypeOptions(lang),
								SupportedEngines: []string{"xray-core"},
								ShowIf:           map[string]interface{}{"network": "tcp"},
								GridColumn:       "col-12",
							},
							{
								ID:          "ob-path",
								TargetField: "path",
								Type:        "text",
								Label:       i18n.T(loc, "UI_FIELD_PATH"),
								Placeholder: "/vmess-ws",
								ShowIf:      map[string]interface{}{"network": []string{"ws", "httpupgrade", "h2"}},
								GridColumn:  "col-6",
							},
							{
								ID:          "ob-ws-host",
								TargetField: "wsHost",
								Type:        "text",
								Label:       i18n.T(loc, "UI_FIELD_WS_HOST"),
								Placeholder: "domain.com",
								ShowIf:      map[string]interface{}{"network": []string{"ws", "httpupgrade", "h2"}},
								GridColumn:  "col-6",
							},
							{
								ID:          "ob-service-name",
								TargetField: "serviceName",
								Type:        "text",
								Label:       i18n.T(loc, "UI_FIELD_GRPC_SERVICE_NAME"),
								Placeholder: "vmess-grpc",
								ShowIf:      map[string]interface{}{"network": "grpc"},
								GridColumn:  "col-8",
							},
							{
								ID:               "ob-grpc-multi-mode",
								TargetField:      "multiMode",
								Type:             "checkbox",
								Label:            i18n.T(loc, "UI_FIELD_GRPC_MULTI_MODE"),
								Default:          false,
								SupportedEngines: []string{"xray-core"},
								ShowIf:           map[string]interface{}{"network": "grpc"},
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
								ID:          "ob-security",
								TargetField: "security",
								Type:        "select",
								Label:       i18n.T(loc, "UI_FIELD_SECURITY"),
								Default:     "tls",
								Options:     fields.OutboundSecurityOptions([]string{"tls", "none"}, engineSecurity, lang),
								GridColumn:  "col-12",
							},
							{
								ID:          "ob-sni",
								TargetField: "sni",
								Type:        "text",
								Label:       i18n.T(loc, "UI_FIELD_SNI"),
								Placeholder: "vmess.example.com",
								ShowIf:      map[string]interface{}{"security": "tls"},
								GridColumn:  "col-6",
							},
							{
								ID:          "ob-fp",
								TargetField: "fingerprint",
								Type:        "select",
								Label:       i18n.T(loc, "UI_FIELD_FINGERPRINT"),
								Default:     "chrome",
								Options:     fields.OutboundFingerprintOptions(),
								ShowIf:      map[string]interface{}{"security": "tls"},
								GridColumn:  "col-6",
							},
							{
								ID:          "ob-alpn",
								TargetField: "alpn",
								Type:        "text",
								Label:       i18n.T(loc, "UI_FIELD_ALPN"),
								Default:     "",
								Options:     fields.OutboundALPNOptions(lang),
								Placeholder: "h2,http/1.1",
								ShowIf:      map[string]interface{}{"security": "tls"},
								GridColumn:  "col-6",
							},
							{
								ID:          "ob-insecure",
								TargetField: "allowInsecure",
								Type:        "checkbox",
								Label:       i18n.T(loc, "UI_FIELD_ALLOW_INSECURE"),
								Default:     false,
								ShowIf:      map[string]interface{}{"security": "tls"},
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
