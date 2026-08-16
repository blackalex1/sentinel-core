package xray

import (
	"github.com/blackalex1/sentinel-core/pkg/ast"
	"github.com/blackalex1/sentinel-core/pkg/i18n"
	"github.com/blackalex1/sentinel-core/pkg/matrix/fields"
	"github.com/blackalex1/sentinel-core/pkg/matrix/types"
)

// GetOutboundWireGuardCapability returns the capability definition for WireGuard outbound
func GetOutboundWireGuardCapability(lang string) types.ProtocolCapability {
	loc := i18n.Locale(lang)
	return types.ProtocolCapability{
		Protocol:         ast.ProtoWireGuard,
		DisplayName:      "WireGuard",
		Description:      i18n.T(loc, "UI_OUTBOUND_WG_DESC"),
		DefaultPort:      51820,
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
								Placeholder: "wg-proxy",
								GridColumn:  "col-6",
							},
							{
								ID:          "ob-tag",
								TargetField: "tag",
								Type:        "text",
								Label:       i18n.T(loc, "UI_FIELD_TAG"),
								Placeholder: "wg-out",
								GridColumn:  "col-6",
							},
							{
								ID:          "ob-host",
								TargetField: "host",
								Type:        "text",
								Label:       i18n.T(loc, "UI_FIELD_SERVER_HOST"),
								Placeholder: "wg.example.com",
								GridColumn:  "col-8",
							},
							{
								ID:          "ob-port",
								TargetField: "port",
								Type:        "text",
								Label:       i18n.T(loc, "UI_FIELD_PORT"),
								Default:     51820,
								GridColumn:  "col-4",
							},
							{
								ID:          "ob-private-key",
								TargetField: "privateKey",
								Type:        "password",
								Label:       i18n.T(loc, "UI_FIELD_PRIVATE_KEY"),
								Placeholder: "WireGuard Private Key",
								GridColumn:  "col-6",
							},
							{
								ID:          "ob-peer-public-key",
								TargetField: "peerPublicKey",
								Type:        "text",
								Label:       i18n.T(loc, "UI_FIELD_PEER_PUBLIC_KEY"),
								Placeholder: "Server Public Key",
								GridColumn:  "col-6",
							},
							{
								ID:          "ob-local-address",
								TargetField: "localAddress",
								Type:        "text",
								Label:       i18n.T(loc, "UI_FIELD_LOCAL_ADDRESS"),
								Placeholder: "10.0.0.2/32, fd00::2/128",
								GridColumn:  "col-6",
							},
							{
								ID:          "ob-mtu",
								TargetField: "mtu",
								Type:        "number",
								Label:       i18n.T(loc, "UI_FIELD_MTU"),
								Default:     1420,
								GridColumn:  "col-3",
							},
							{
								ID:          "ob-reserved",
								TargetField: "reserved",
								Type:        "text",
								Label:       i18n.T(loc, "UI_FIELD_RESERVED"),
								Placeholder: "0,0,0",
								GridColumn:  "col-3",
							},
						},
					},
				},
			},
			fields.BuildOutboundFallbackTab(lang),
		},
	}
}

// GetOutboundWGCapability is an alias for WireGuard
func GetOutboundWGCapability(lang string) types.ProtocolCapability {
	cap := GetOutboundWireGuardCapability(lang)
	cap.Protocol = "wg"
	return cap
}
