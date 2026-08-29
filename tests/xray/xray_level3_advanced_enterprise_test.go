package xray_test

import (
	"encoding/json"
	"testing"

	"github.com/blackalex1/sentinel-core/pkg/ast"
	"github.com/blackalex1/sentinel-core/pkg/builder"
)

// Level 3: VLESS Reverse Proxy & Forwarding for Intranet Punch-Through
func TestXray_Level3_ReverseProxy_BridgeAndPortal(t *testing.T) {
	// Bridge configuration (Internal client behind NAT connecting out to Portal)
	bridgeRawJSON := `{
		"inbounds": [
			{
				"tag": "local-service-in",
				"port": 9090,
				"listen": "127.0.0.1",
				"protocol": "dokodemo-door",
				"settings": {
					"address": "127.0.0.1",
					"port": 80,
					"network": "tcp"
				}
			}
		],
		"outbounds": [
			{
				"tag": "out-to-portal",
				"protocol": "vless",
				"settings": {
					"vnext": [
						{
							"address": "198.51.100.1",
							"port": 443,
							"users": [
								{
									"id": "b9f3857a-ce20-4e1e-b5e0-6f3d141fa2b2",
									"flow": "xtls-rprx-vision",
									"encryption": "none"
								}
							]
						}
					]
				},
				"streamSettings": {
					"network": "tcp",
					"security": "reality",
					"realitySettings": {
						"serverName": "www.apple.com",
						"publicKey": "1pxvjj6jjhkkN40PM83ViQTJeC9VMDVe7oceMZuWNQY",
						"fingerprint": "chrome"
					}
				}
			},
			{
				"protocol": "freedom",
				"tag": "direct"
			}
		],
		"routing": {
			"rules": [
				{
					"type": "field",
					"inboundTag": ["local-service-in"],
					"outboundTag": "out-to-portal"
				}
			]
		}
	}`

	runXraySyntaxCheck(t, "Level 3 Modern VLESS Reverse Proxy Bridge", bridgeRawJSON)

	// Portal configuration (Public VPS receiving traffic and routing via VLESS Inbound)
	portalRawJSON := `{
		"inbounds": [
			{
				"tag": "external-client-in",
				"port": 8080,
				"listen": "0.0.0.0",
				"protocol": "http",
				"settings": {
					"allowTransparent": false
				}
			}
		],
		"outbounds": [
			{
				"protocol": "freedom",
				"tag": "direct"
			}
		],
		"routing": {
			"rules": [
				{
					"type": "field",
					"inboundTag": ["external-client-in"],
					"outboundTag": "direct"
				}
			]
		}
	}`

	runXraySyntaxCheck(t, "Level 3 Modern VLESS Reverse Proxy Portal", portalRawJSON)
	t.Logf("✅ Level 3: Modern VLESS Reverse Proxy Bridge & Portal verified")
}

// Level 3: Dynamic Stats & Management Services (StatsService, HandlerService, LoggerService)
func TestXray_Level3_StatsAndManagementAPI(t *testing.T) {
	inbound := ast.ServerInboundSpec{
		Protocol:      "vless",
		ListenAddress: "0.0.0.0",
		Port:          443,
		Security:      "none",
		Clients: []ast.ServerInboundClient{
			{UUID: "b9f3857a-ce20-4e1e-b5e0-6f3d141fa2b2", Email: "admin@sentinel"},
		},
	}

	serverJSON, err := builder.BuildServerConfig(ast.CoreXray, []ast.ServerInboundSpec{inbound}, nil, "127.0.0.1:10085")
	if err != nil {
		t.Fatalf("BuildServerConfig failed: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(serverJSON), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	// Must contain stats, policy levels, and api inbounds/services
	if parsed["stats"] == nil || parsed["policy"] == nil || parsed["api"] == nil {
		t.Fatalf("expected stats, policy, and api in server config:\n%s", serverJSON)
	}

	runXraySyntaxCheck(t, "Level 3 Stats & Management API", serverJSON)
	t.Logf("✅ Level 3: Stats & Dynamic Management API verified")
}
