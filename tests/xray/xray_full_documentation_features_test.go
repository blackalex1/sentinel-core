package xray_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/blackalex1/sentinel-core/pkg/ast"
	"github.com/blackalex1/sentinel-core/pkg/builder"
	"github.com/blackalex1/sentinel-core/pkg/crypto"
	"github.com/blackalex1/sentinel-core/pkg/routing"
)

// Level 1: Multi-SNI Fallbacks & Nginx/HAProxy TLS Tunnel with PROXY Protocol (xver: 1/2)
// Corresponds to: Level-1 Fallbacks & Level-2 Nginx/HAProxy TLS Tunnel
func TestXray_Doc_MultiSNI_Fallbacks_With_ProxyProtocol(t *testing.T) {
	certPath, keyPath, cleanup := createTestCertAndKey(t)
	defer cleanup()

	// Server Inbound listening on 443 with Fallback to Nginx on 80/8080 using PROXY protocol
	inbound := ast.ServerInboundSpec{
		Protocol:      "vless",
		ListenAddress: "0.0.0.0",
		Port:          443,
		Security:      "tls",
		SNI:           "vpn.example.com",
		CertPath:      certPath,
		KeyPath:       keyPath,
		Clients: []ast.ServerInboundClient{
			{UUID: "b9f3857a-ce20-4e1e-b5e0-6f3d141fa2b2", Email: "client@sentinel", Flow: "xtls-rprx-vision"},
		},
		Fallbacks: []map[string]interface{}{
			{
				"dest": 80, // Default HTTP fallback to Nginx
				"xver": 1,  // PROXY Protocol v1
			},
			{
				"alpn": "h2",
				"dest": 8082, // HTTP/2 web page fallback
				"xver": 2,    // PROXY Protocol v2
			},
			{
				"path": "/websocket-service",
				"dest": 10080,
				"xver": 1,
			},
		},
	}

	serverJSON, err := builder.BuildServerConfig(ast.CoreXray, []ast.ServerInboundSpec{inbound}, nil, "")
	if err != nil {
		t.Fatalf("BuildServerConfig failed: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(serverJSON), &parsed); err != nil {
		t.Fatalf("invalid server JSON: %v", err)
	}

	inbounds := parsed["inbounds"].([]interface{})
	primaryInbound := inbounds[0].(map[string]interface{})
	settings := primaryInbound["settings"].(map[string]interface{})
	fallbacks, ok := settings["fallbacks"].([]interface{})
	if !ok || len(fallbacks) != 3 {
		t.Fatalf("expected 3 fallbacks with PROXY protocol, got: %v", settings["fallbacks"])
	}

	runXraySyntaxCheck(t, "Multi-SNI Fallbacks & Proxy Protocol", serverJSON)
	t.Logf("✅ Level 1/2: Multi-SNI Fallbacks & Nginx PROXY Protocol (xver: 1/2) dynamically generated and verified")
}

// Level 1: Traffic Splitting via DNS (DoH Remote + UDP Direct DNS + DNS Hijacking)
// Corresponds to: Level-1 Traffic Splitting via DNS
func TestXray_Doc_TrafficSplitting_Via_DNS(t *testing.T) {
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
		Name:      "vless-node",
	}

	engine := routing.NewEngine()
	policy := routing.DefaultSmartPolicy()

	spec := &ast.ConfigSpec{
		TargetCore: ast.CoreXray,
		LogLevel:   "info",
		ClientInbound: &ast.ClientInboundSpec{
			Mode:      ast.InboundModeSystemProxy,
			SocksPort: 10818,
			HTTPPort:  10819,
		},
		ServerNode: node,
		Routing:    engine.CompilePolicy(policy),
		DNS: &ast.DNSSpec{
			RemoteServer: "https://1.1.1.1/dns-query",
			DirectServer: "8.8.8.8",
			Strategy:     "ipv4_only",
		},
	}

	res, err := builder.BuildClientConfig(spec)
	if err != nil {
		t.Fatalf("BuildClientConfig failed: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(res.ConfigJSON), &parsed); err != nil {
		t.Fatalf("invalid client JSON: %v", err)
	}

	dnsMap := parsed["dns"].(map[string]interface{})
	servers := dnsMap["servers"].([]interface{})
	if len(servers) < 2 {
		t.Fatalf("expected remote DoH and local DNS servers, got: %v", servers)
	}

	// Verify DNS query routing rule (port 53 -> dns-out)
	routingMap := parsed["routing"].(map[string]interface{})
	rules := routingMap["rules"].([]interface{})
	hasDNSRule := false
	for _, r := range rules {
		rm := r.(map[string]interface{})
		if rm["outboundTag"] == "dns-out" {
			hasDNSRule = true
			break
		}
	}
	if !hasDNSRule {
		t.Fatalf("expected DNS hijacking rule to dns-out tag")
	}

	runXraySyntaxCheck(t, "Traffic Splitting via DNS", res.ConfigJSON)
	t.Logf("✅ Level 1: Traffic Splitting via DNS dynamically generated and verified")
}

// Level 2: Outbound Redirection & Cloudflare WARP Outbound Chaining
// Corresponds to: Level-2 Enhance Security with Cloudflare WARP / Redirect
func TestXray_Doc_CloudflareWARP_OutboundChaining(t *testing.T) {
	realityKeys, err := crypto.GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("failed to generate reality keys: %v", err)
	}

	valid32Key := "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="

	serverJSON := `{
		"inbounds": [
			{
				"tag": "vless-in",
				"port": 443,
				"protocol": "vless",
				"settings": {
					"clients": [
						{
							"id": "b9f3857a-ce20-4e1e-b5e0-6f3d141fa2b2",
							"flow": "xtls-rprx-vision"
						}
					],
					"decryption": "none"
				},
				"streamSettings": {
					"network": "tcp",
					"security": "reality",
					"realitySettings": {
						"show": false,
						"dest": "www.apple.com:443",
						"serverNames": ["www.apple.com"],
						"privateKey": "` + realityKeys.PrivateKey + `",
						"shortIds": ["0123456789abcdef"]
					}
				}
			}
		],
		"outbounds": [
			{
				"tag": "warp-out",
				"protocol": "wireguard",
				"settings": {
					"secretKey": "` + valid32Key + `",
					"address": ["172.16.0.2/32", "2606:4700:110:8f81::1/128"],
					"peers": [
						{
							"publicKey": "` + valid32Key + `",
							"endpoint": "engage.cloudflareclient.com:2408"
						}
					],
					"mtu": 1280
				}
			},
			{
				"tag": "direct",
				"protocol": "freedom"
			},
			{
				"tag": "block",
				"protocol": "blackhole"
			}
		],
		"routing": {
			"domainStrategy": "IPIfNonMatch",
			"rules": [
				{
					"type": "field",
					"ip": ["geoip:ru"],
					"outboundTag": "direct"
				},
				{
					"type": "field",
					"inboundTag": ["vless-in"],
					"outboundTag": "warp-out"
				}
			]
		}
	}`

	runXraySyntaxCheck(t, "Cloudflare WARP Outbound Chaining", serverJSON)
	t.Logf("✅ Level 2: Cloudflare WARP WireGuard outbound chaining verified")
}

// Level 2: Traffic Statistics & Per-User Billing Policy
// Corresponds to: Level-2 Traffic Statistics
func TestXray_Doc_TrafficStatistics_And_Policy(t *testing.T) {
	inbound := ast.ServerInboundSpec{
		Protocol:      "vless",
		ListenAddress: "0.0.0.0",
		Port:          443,
		Security:      "none",
		Clients: []ast.ServerInboundClient{
			{UUID: "b9f3857a-ce20-4e1e-b5e0-6f3d141fa2b2", Email: "user1@sentinel"},
			{UUID: "c8e2746b-bd19-3d0d-a4df-5e2c030e91a1", Email: "user2@sentinel"},
		},
	}

	serverJSON, err := builder.BuildServerConfig(ast.CoreXray, []ast.ServerInboundSpec{inbound}, nil, "127.0.0.1:10085")
	if err != nil {
		t.Fatalf("BuildServerConfig failed: %v", err)
	}

	if !strings.Contains(serverJSON, "statsUserUplink") || !strings.Contains(serverJSON, "statsUserDownlink") {
		t.Fatalf("expected per-user traffic stats policy in server config:\n%s", serverJSON)
	}

	runXraySyntaxCheck(t, "Traffic Statistics and Policy", serverJSON)
	t.Logf("✅ Level 2: Per-user traffic statistics & policy levels verified")
}
