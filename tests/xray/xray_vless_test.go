package xray_test

import (
	"encoding/json"
	"testing"

	"github.com/blackalex1/sentinel-core/pkg/ast"
	"github.com/blackalex1/sentinel-core/pkg/builder"
	"github.com/blackalex1/sentinel-core/pkg/crypto"
	"github.com/blackalex1/sentinel-core/pkg/parser"
)

// 1. VLESS Reality TCP + XTLS Vision (The standard anti-censorship setup)
func TestXray_VLESS_Reality_TCP_Vision(t *testing.T) {
	raw := "vless://b9f3857a-ce20-4e1e-b5e0-6f3d141fa2b2@198.51.100.50:443?type=tcp&security=reality&pbk=1pxvjj6jjhkkN40PM83ViQTJeC9VMDVe7oceMZuWNQY&fp=chrome&sni=www.apple.com&sid=0123456789abcdef&spx=%2F&flow=xtls-rprx-vision#Reality-TCP-Vision"
	profile, err := parser.ParseURI(raw)
	if err != nil {
		t.Fatalf("failed to parse URI: %v", err)
	}

	spec := buildClientTestSpec(profile)
	res, err := builder.BuildClientConfig(spec)
	if err != nil {
		t.Fatalf("BuildClientConfig failed: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(res.ConfigJSON), &parsed); err != nil {
		t.Fatalf("invalid JSON generated: %v", err)
	}

	outbounds := parsed["outbounds"].([]interface{})
	primary := outbounds[0].(map[string]interface{})
	if primary["protocol"] != "vless" {
		t.Fatalf("expected protocol vless, got %v", primary["protocol"])
	}

	stream := primary["streamSettings"].(map[string]interface{})
	if stream["security"] != "reality" {
		t.Errorf("expected security reality, got %v", stream["security"])
	}
	reality := stream["realitySettings"].(map[string]interface{})
	if reality["serverName"] != "www.apple.com" || reality["shortId"] != "0123456789abcdef" {
		t.Errorf("unexpected reality settings: %v", reality)
	}

	runXraySyntaxCheck(t, "VLESS Reality TCP Vision", res.ConfigJSON)
	t.Logf("✅ Xray VLESS Reality TCP Vision passed live verification")
}

// 2. VLESS Reality gRPC
func TestXray_VLESS_Reality_gRPC(t *testing.T) {
	raw := "vless://b9f3857a-ce20-4e1e-b5e0-6f3d141fa2b2@198.51.100.51:8443?type=grpc&security=reality&pbk=1pxvjj6jjhkkN40PM83ViQTJeC9VMDVe7oceMZuWNQY&fp=firefox&sni=www.microsoft.com&sid=abcdef0123456789&serviceName=vless-grpc#Reality-gRPC"
	profile, err := parser.ParseURI(raw)
	if err != nil {
		t.Fatalf("failed to parse URI: %v", err)
	}

	spec := buildClientTestSpec(profile)
	res, err := builder.BuildClientConfig(spec)
	if err != nil {
		t.Fatalf("BuildClientConfig failed: %v", err)
	}

	var parsed map[string]interface{}
	json.Unmarshal([]byte(res.ConfigJSON), &parsed)

	outbounds := parsed["outbounds"].([]interface{})
	primary := outbounds[0].(map[string]interface{})
	stream := primary["streamSettings"].(map[string]interface{})
	if stream["network"] != "grpc" {
		t.Errorf("expected network grpc, got %v", stream["network"])
	}

	runXraySyntaxCheck(t, "VLESS Reality gRPC", res.ConfigJSON)
	t.Logf("✅ Xray VLESS Reality gRPC passed live verification")
}

// 3. VLESS TCP TLS + XTLS Vision
func TestXray_VLESS_TLS_TCP_Vision(t *testing.T) {
	raw := "vless://a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d@tls.node.org:443?type=tcp&security=tls&sni=tls.node.org&fp=chrome&flow=xtls-rprx-vision&alpn=h2%2Chttp%2F1.1#VLESS-TLS-TCP"
	profile, err := parser.ParseURI(raw)
	if err != nil {
		t.Fatalf("failed to parse URI: %v", err)
	}

	spec := buildClientTestSpec(profile)
	res, err := builder.BuildClientConfig(spec)
	if err != nil {
		t.Fatalf("BuildClientConfig failed: %v", err)
	}

	runXraySyntaxCheck(t, "VLESS TLS TCP Vision", res.ConfigJSON)
	t.Logf("✅ Xray VLESS TLS TCP Vision passed live verification")
}

// 4. VLESS WebSocket + TLS (CDN / Cloudflare Workers)
func TestXray_VLESS_TLS_WebSocket(t *testing.T) {
	raw := "vless://a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d@cdn.cloudflare.com:443?type=ws&security=tls&sni=worker.example.workers.dev&path=%2Fvless-ws-path&host=worker.example.workers.dev#VLESS-WS-CDN"
	profile, err := parser.ParseURI(raw)
	if err != nil {
		t.Fatalf("failed to parse URI: %v", err)
	}

	spec := buildClientTestSpec(profile)
	res, err := builder.BuildClientConfig(spec)
	if err != nil {
		t.Fatalf("BuildClientConfig failed: %v", err)
	}

	var parsed map[string]interface{}
	json.Unmarshal([]byte(res.ConfigJSON), &parsed)

	outbounds := parsed["outbounds"].([]interface{})
	primary := outbounds[0].(map[string]interface{})
	stream := primary["streamSettings"].(map[string]interface{})
	if stream["network"] != "ws" {
		t.Errorf("expected network ws, got %v", stream["network"])
	}
	wsSettings := stream["wsSettings"].(map[string]interface{})
	if wsSettings["path"] != "/vless-ws-path" {
		t.Errorf("expected path /vless-ws-path, got %v", wsSettings["path"])
	}

	runXraySyntaxCheck(t, "VLESS TLS WebSocket", res.ConfigJSON)
	t.Logf("✅ Xray VLESS TLS WebSocket passed live verification")
}

// 5. VLESS Plain No TLS (Direct / Local Relay)
func TestXray_VLESS_Plain_NoTLS(t *testing.T) {
	raw := "vless://a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d@198.51.100.60:8080?type=tcp&security=none#VLESS-Plain-Direct"
	profile, err := parser.ParseURI(raw)
	if err != nil {
		t.Fatalf("failed to parse URI: %v", err)
	}

	spec := buildClientTestSpec(profile)
	res, err := builder.BuildClientConfig(spec)
	if err != nil {
		t.Fatalf("BuildClientConfig failed: %v", err)
	}

	runXraySyntaxCheck(t, "VLESS Plain No TLS", res.ConfigJSON)
	t.Logf("✅ Xray VLESS Plain No TLS passed live verification")
}

// 6. VLESS Server Inbound with Multi-User, Reality and Fallbacks
func TestXray_VLESS_Server_RealityAndFallbacks(t *testing.T) {
	certPath, keyPath, cleanup := createTestCertAndKey(t)
	defer cleanup()

	realityKeys, err := crypto.GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("failed to generate reality keys: %v", err)
	}

	inbound := ast.ServerInboundSpec{
		Protocol:      "vless",
		ListenAddress: "0.0.0.0",
		Port:          443,
		Security:      "reality",
		SNI:           "www.microsoft.com",
		CertPath:      certPath,
		KeyPath:       keyPath,
		PrivateKey:    realityKeys.PrivateKey,
		ShortIDs:      []string{"0123456789abcdef", ""},
		Clients: []ast.ServerInboundClient{
			{UUID: "b9f3857a-ce20-4e1e-b5e0-6f3d141fa2b2", Email: "user1@sentinel", Flow: "xtls-rprx-vision"},
			{UUID: "c8e2746b-bd19-3d0d-a4df-5e2c030e91a1", Email: "user2@sentinel", Flow: "xtls-rprx-vision"},
		},
		Fallbacks: []map[string]interface{}{
			{"dest": 80, "xver": 1},
			{"path": "/ws", "dest": 10880, "xver": 1},
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
	if primaryInbound["protocol"] != "vless" {
		t.Errorf("expected protocol vless, got %v", primaryInbound["protocol"])
	}

	settings := primaryInbound["settings"].(map[string]interface{})
	clients := settings["clients"].([]interface{})
	if len(clients) != 2 {
		t.Errorf("expected 2 clients, got %d", len(clients))
	}

	runXraySyntaxCheck(t, "VLESS Server Inbound", serverJSON)
	t.Logf("✅ Xray VLESS Server Inbound with Multi-User & Reality verified")
}
