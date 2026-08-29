package singbox_test

import (
	"encoding/json"
	"testing"

	"github.com/blackalex1/sentinel-core/pkg/ast"
	"github.com/blackalex1/sentinel-core/pkg/builder"
	"github.com/blackalex1/sentinel-core/pkg/parser"
)

// 1. SOCKS5 & HTTP Outbound Proxies (Chaining) in Sing-box
func TestSingbox_Socks_And_HTTP_Outbounds(t *testing.T) {
	// SOCKS5 Outbound
	socksProfile, err := parser.ParseURI("socks5://admin:secretPass@198.51.100.60:1080#Singbox-Socks-Out")
	if err != nil {
		t.Fatalf("failed to parse socks URI: %v", err)
	}

	specSocks := buildClientTestSpec(socksProfile)
	resSocks, err := builder.BuildClientConfig(specSocks)
	if err != nil {
		t.Fatalf("BuildClientConfig for SOCKS failed: %v", err)
	}

	runSingboxSyntaxCheck(t, "SOCKS5 Outbound in Sing-box", resSocks.ConfigJSON)
	t.Logf("✅ Sing-box SOCKS5 Outbound verified")

	// HTTP Proxy Outbound (with TLS)
	httpProfile, err := parser.ParseURI("http://proxyUser:proxyPass@198.51.100.61:8080?security=tls&sni=http-proxy.example.com#Singbox-HTTP-Out")
	if err != nil {
		t.Fatalf("failed to parse http URI: %v", err)
	}

	specHTTP := buildClientTestSpec(httpProfile)
	resHTTP, err := builder.BuildClientConfig(specHTTP)
	if err != nil {
		t.Fatalf("BuildClientConfig for HTTP failed: %v", err)
	}

	runSingboxSyntaxCheck(t, "HTTP Outbound in Sing-box", resHTTP.ConfigJSON)
	t.Logf("✅ Sing-box HTTP Proxy Outbound verified")
}

// 2. Hysteria 2 Server Inbound in Sing-box
func TestSingbox_Hysteria2_Server_Inbound(t *testing.T) {
	certPath, keyPath, cleanup := createTestCertAndKey(t)
	defer cleanup()

	inbound := ast.ServerInboundSpec{
		Protocol:      "hysteria2",
		ListenAddress: "0.0.0.0",
		Port:          443,
		Security:      "tls",
		SNI:           "hy2.sentinel.internal",
		CertPath:      certPath,
		KeyPath:       keyPath,
		BandwidthUp:   "100 mbps",
		BandwidthDown: "500 mbps",
		ObfsType:      "salamander",
		ObfsPassword:  "salamanderSecretKey",
		Clients: []ast.ServerInboundClient{
			{Password: "hy2UserPassword1", Email: "user1@sentinel"},
			{Password: "hy2UserPassword2", Email: "user2@sentinel"},
		},
	}

	serverJSON, err := builder.BuildServerConfig(ast.CoreSingBox, []ast.ServerInboundSpec{inbound}, nil, "")
	if err != nil {
		t.Fatalf("BuildServerConfig failed: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(serverJSON), &parsed); err != nil {
		t.Fatalf("invalid server JSON: %v", err)
	}

	inbounds := parsed["inbounds"].([]interface{})
	primary := inbounds[0].(map[string]interface{})
	if primary["type"] != "hysteria2" {
		t.Fatalf("expected type hysteria2, got %v", primary["type"])
	}

	runSingboxSyntaxCheck(t, "Hysteria 2 Server Inbound in Sing-box", serverJSON)
	t.Logf("✅ Sing-box Hysteria 2 Server Inbound verified")
}

// 3. TUIC v5 Server Inbound in Sing-box
func TestSingbox_TUIC_Server_Inbound(t *testing.T) {
	certPath, keyPath, cleanup := createTestCertAndKey(t)
	defer cleanup()

	inbound := ast.ServerInboundSpec{
		Protocol:      "tuic",
		ListenAddress: "0.0.0.0",
		Port:          8443,
		Security:      "tls",
		SNI:           "tuic.sentinel.internal",
		CertPath:      certPath,
		KeyPath:       keyPath,
		Clients: []ast.ServerInboundClient{
			{UUID: "b9f3857a-ce20-4e1e-b5e0-6f3d141fa2b2", Password: "tuicUserPassword1", Email: "user1@sentinel"},
			{UUID: "c8e2746b-bd19-3d0d-a4df-5e2c030e91a1", Password: "tuicUserPassword2", Email: "user2@sentinel"},
		},
		RawSettings: map[string]interface{}{
			"congestion_controller": "bbr",
			"zero_rtt_handshake":    true,
		},
	}

	serverJSON, err := builder.BuildServerConfig(ast.CoreSingBox, []ast.ServerInboundSpec{inbound}, nil, "")
	if err != nil {
		t.Fatalf("BuildServerConfig failed: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(serverJSON), &parsed); err != nil {
		t.Fatalf("invalid server JSON: %v", err)
	}

	inbounds := parsed["inbounds"].([]interface{})
	primary := inbounds[0].(map[string]interface{})
	if primary["type"] != "tuic" {
		t.Fatalf("expected type tuic, got %v", primary["type"])
	}

	runSingboxSyntaxCheck(t, "TUIC Server Inbound in Sing-box", serverJSON)
	t.Logf("✅ Sing-box TUIC Server Inbound verified")
}

// 4. URLTest & Selector Group Outbounds in Sing-box
func TestSingbox_URLTest_And_Selector_Outbounds(t *testing.T) {
	node1 := &ast.ServerProfile{
		Protocol:  ast.ProtoVLESS,
		Address:   "198.51.100.1",
		Port:      443,
		UUID:      "b9f3857a-ce20-4e1e-b5e0-6f3d141fa2b2",
		Transport: "tcp",
		Security:  "reality",
		PublicKey: "1pxvjj6jjhkkN40PM83ViQTJeC9VMDVe7oceMZuWNQY",
		SNI:       "www.apple.com",
		Flow:      "xtls-rprx-vision",
		Name:      "Node-Primary",
	}

	node2 := &ast.ServerProfile{
		Protocol:  ast.ProtoHysteria2,
		Address:   "198.51.100.2",
		Port:      443,
		Password:  "secretPass",
		SNI:       "hy2.example.com",
		Name:      "Node-Backup",
	}

	node1.BackupProfiles = []*ast.ServerProfile{node2}

	spec := buildClientTestSpec(node1)
	res, err := builder.BuildClientConfig(spec)
	if err != nil {
		t.Fatalf("BuildClientConfig failed: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(res.ConfigJSON), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	outbounds := parsed["outbounds"].([]interface{})
	primary := outbounds[0].(map[string]interface{})
	if primary["type"] != "urltest" {
		t.Fatalf("expected primary outbound type urltest, got %v", primary["type"])
	}

	runSingboxSyntaxCheck(t, "URLTest Group Outbound in Sing-box", res.ConfigJSON)
	t.Logf("✅ Sing-box URLTest Group Outbound verified")
}

// 5. Multi-Hop Chained Outbounds (Detour Routing) in Sing-box
func TestSingbox_MultiHop_Chained_Outbounds(t *testing.T) {
	// 16-byte key for 2022-blake3-aes-128-gcm
	valid16Key := "MDEyMzQ1Njc4OWFiY2RlZg=="

	configJSON := `{
		"outbounds": [
			{
				"type": "shadowsocks",
				"tag": "ss-inner",
				"server": "198.51.100.10",
				"server_port": 8388,
				"method": "2022-blake3-aes-128-gcm",
				"password": "` + valid16Key + `",
				"detour": "shadowtls-outer"
			},
			{
				"type": "shadowtls",
				"tag": "shadowtls-outer",
				"server": "198.51.100.10",
				"server_port": 443,
				"version": 3,
				"password": "shadowtlsPassword",
				"tls": {
					"enabled": true,
					"server_name": "www.microsoft.com",
					"utls": {
						"enabled": true,
						"fingerprint": "chrome"
					}
				}
			},
			{
				"type": "direct",
				"tag": "direct"
			},
			{
				"type": "block",
				"tag": "block"
			}
		],
		"route": {
			"rules": [
				{
					"outbound": "ss-inner"
				}
			]
		}
	}`

	runSingboxSyntaxCheck(t, "Multi-Hop Chained Outbound in Sing-box", configJSON)
	t.Logf("✅ Sing-box Multi-Hop Chained Outbound (Detour) verified")
}

// 6. Transparent Gateway Inbounds (TProxy & Redirect) in Sing-box
func TestSingbox_TProxy_And_Redirect_Inbounds(t *testing.T) {
	configJSON := `{
		"inbounds": [
			{
				"type": "tproxy",
				"tag": "tproxy-in",
				"listen": "::",
				"listen_port": 12345
			},
			{
				"type": "redirect",
				"tag": "redirect-in",
				"listen": "::",
				"listen_port": 12346
			}
		],
		"outbounds": [
			{
				"type": "direct",
				"tag": "direct"
			}
		],
		"route": {
			"rules": [
				{
					"action": "sniff"
				},
				{
					"inbound": ["tproxy-in", "redirect-in"],
					"outbound": "direct"
				}
			]
		}
	}`

	runSingboxSyntaxCheck(t, "TProxy & Redirect Inbounds in Sing-box", configJSON)
	t.Logf("✅ Sing-box TProxy & Redirect Inbounds verified")
}
