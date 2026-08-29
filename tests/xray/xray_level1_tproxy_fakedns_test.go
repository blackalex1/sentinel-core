package xray_test

import (
	"encoding/json"
	"testing"

	"github.com/blackalex1/sentinel-core/pkg/ast"
	"github.com/blackalex1/sentinel-core/pkg/builder"
)

// Level 1: TProxy / Transparent Proxying via Dokodemo-Door Inbound
func TestXray_Level1_TProxy_TransparentProxy(t *testing.T) {
	node := &ast.ServerProfile{
		Protocol:  ast.ProtoVLESS,
		Address:   "198.51.100.1",
		Port:      443,
		UUID:      "b9f3857a-ce20-4e1e-b5e0-6f3d141fa2b2",
		Transport: "tcp",
		Security:  "reality",
		PublicKey: "1pxvjj6jjhkkN40PM83ViQTJeC9VMDVe7oceMZuWNQY",
		SNI:       "www.microsoft.com",
		Flow:      "xtls-rprx-vision",
		Name:      "vless-tproxy-out",
	}

	spec := buildClientTestSpec(node)
	// Add TProxy Inbound (Linux Gateway / Router mode)
	spec.RawJSONConfig = `{
		"inbounds": [
			{
				"tag": "tproxy-in",
				"port": 12345,
				"protocol": "dokodemo-door",
				"settings": {
					"network": "tcp,udp",
					"followRedirect": true
				},
				"streamSettings": {
					"sockopt": {
						"tproxy": "tproxy"
					}
				},
				"sniffing": {
					"enabled": true,
					"destOverride": ["http", "tls", "quic", "fakedns"],
					"routeOnly": false
				}
			}
		],
		"outbounds": [
			{
				"protocol": "vless",
				"tag": "proxy",
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
						"serverName": "www.microsoft.com",
						"publicKey": "1pxvjj6jjhkkN40PM83ViQTJeC9VMDVe7oceMZuWNQY",
						"fingerprint": "chrome"
					}
				}
			},
			{
				"protocol": "freedom",
				"tag": "direct"
			},
			{
				"protocol": "blackhole",
				"tag": "block"
			}
		],
		"routing": {
			"domainStrategy": "IPIfNonMatch",
			"rules": [
				{
					"inboundTag": ["tproxy-in"],
					"outboundTag": "proxy",
					"type": "field"
				}
			]
		}
	}`

	res, err := builder.BuildClientConfig(spec)
	if err != nil {
		t.Fatalf("BuildClientConfig failed: %v", err)
	}

	runXraySyntaxCheck(t, "Level 1 TProxy Dokodemo-Door", res.ConfigJSON)
	t.Logf("✅ Level 1: TProxy / Transparent proxying with Dokodemo-Door verified")
}

// Level 1: FakeDNS and Inbound Sniffing Integration
func TestXray_Level1_FakeDNS_And_Sniffing(t *testing.T) {
	node := &ast.ServerProfile{
		Protocol:  ast.ProtoVLESS,
		Address:   "198.51.100.1",
		Port:      443,
		UUID:      "b9f3857a-ce20-4e1e-b5e0-6f3d141fa2b2",
		Transport: "tcp",
		Security:  "reality",
		PublicKey: "1pxvjj6jjhkkN40PM83ViQTJeC9VMDVe7oceMZuWNQY",
		SNI:       "www.apple.com",
		Flow:      "xtls-rprx-vision",
		Name:      "vless-fakedns-out",
	}

	spec := buildClientTestSpec(node)
	spec.RawJSONConfig = `{
		"dns": {
			"servers": [
				"fakedns",
				"https://1.1.1.1/dns-query",
				"8.8.8.8"
			],
			"queryStrategy": "UseIPv4"
		},
		"fakedns": [
			{
				"ipPool": "198.18.0.0/15",
				"poolSize": 65535
			}
		],
		"inbounds": [
			{
				"tag": "socks-in",
				"port": 10818,
				"listen": "127.0.0.1",
				"protocol": "socks",
				"settings": {
					"udp": true,
					"auth": "noauth"
				},
				"sniffing": {
					"enabled": true,
					"destOverride": ["http", "tls", "quic", "fakedns"],
					"routeOnly": false
				}
			}
		],
		"outbounds": [
			{
				"protocol": "freedom",
				"tag": "direct"
			},
			{
				"protocol": "blackhole",
				"tag": "block"
			}
		],
		"routing": {
			"domainStrategy": "IPIfNonMatch",
			"rules": [
				{
					"inboundTag": ["socks-in"],
					"outboundTag": "direct",
					"type": "field"
				}
			]
		}
	}`

	res, err := builder.BuildClientConfig(spec)
	if err != nil {
		t.Fatalf("BuildClientConfig failed: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(res.ConfigJSON), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	runXraySyntaxCheck(t, "Level 1 FakeDNS and Sniffing", res.ConfigJSON)
	t.Logf("✅ Level 1: FakeDNS & Inbound Sniffing verified")
}
