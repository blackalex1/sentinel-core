package xray_test

import (
	"encoding/json"
	"testing"

	"github.com/blackalex1/sentinel-core/pkg/ast"
	"github.com/blackalex1/sentinel-core/pkg/builder"
	"github.com/blackalex1/sentinel-core/pkg/parser"
)

// 1. Trojan TCP + TLS
func TestXray_Trojan_TCP_TLS(t *testing.T) {
	raw := "trojan://SuperTrojanPass123@node.trojan.org:443?sni=node.trojan.org&security=tls#Trojan-TCP-TLS"
	profile, err := parser.ParseURI(raw)
	if err != nil {
		t.Fatalf("failed to parse Trojan URI: %v", err)
	}

	spec := buildClientTestSpec(profile)
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
	if primary["protocol"] != "trojan" {
		t.Fatalf("expected protocol trojan, got %v", primary["protocol"])
	}

	runXraySyntaxCheck(t, "Trojan TCP TLS", res.ConfigJSON)
	t.Logf("✅ Xray Trojan TCP TLS passed live verification")
}

// 2. Trojan WebSocket + TLS (CDN)
func TestXray_Trojan_WebSocket_TLS(t *testing.T) {
	raw := "trojan://SuperTrojanPass123@cdn.example.com:443?type=ws&security=tls&sni=my-sub.workers.dev&path=%2Ftrojan-ws&host=my-sub.workers.dev#Trojan-WS-CDN"
	profile, err := parser.ParseURI(raw)
	if err != nil {
		t.Fatalf("failed to parse Trojan WS URI: %v", err)
	}

	spec := buildClientTestSpec(profile)
	res, err := builder.BuildClientConfig(spec)
	if err != nil {
		t.Fatalf("BuildClientConfig failed: %v", err)
	}

	runXraySyntaxCheck(t, "Trojan WebSocket TLS", res.ConfigJSON)
	t.Logf("✅ Xray Trojan WebSocket TLS passed live verification")
}

// 3. Trojan gRPC + TLS
func TestXray_Trojan_gRPC_TLS(t *testing.T) {
	raw := "trojan://SuperTrojanPass123@grpc.trojan.org:8443?type=grpc&security=tls&sni=grpc.trojan.org&serviceName=trojan-grpc#Trojan-gRPC"
	profile, err := parser.ParseURI(raw)
	if err != nil {
		t.Fatalf("failed to parse Trojan gRPC URI: %v", err)
	}

	spec := buildClientTestSpec(profile)
	res, err := builder.BuildClientConfig(spec)
	if err != nil {
		t.Fatalf("BuildClientConfig failed: %v", err)
	}

	runXraySyntaxCheck(t, "Trojan gRPC TLS", res.ConfigJSON)
	t.Logf("✅ Xray Trojan gRPC TLS passed live verification")
}

// 4. Trojan Server Inbound with Multiple Passwords & Fallbacks
func TestXray_Trojan_Server_Inbound(t *testing.T) {
	certPath, keyPath, cleanup := createTestCertAndKey(t)
	defer cleanup()

	inbound := ast.ServerInboundSpec{
		Protocol:      "trojan",
		ListenAddress: "0.0.0.0",
		Port:          443,
		Security:      "tls",
		SNI:           "xray.sentinel.internal",
		CertPath:      certPath,
		KeyPath:       keyPath,
		Clients: []ast.ServerInboundClient{
			{Password: "TrojanPassAlice", Email: "alice@trojan"},
			{Password: "TrojanPassBob", Email: "bob@trojan"},
		},
		Fallbacks: []map[string]interface{}{
			{"dest": 80},
		},
	}

	serverJSON, err := builder.BuildServerConfig(ast.CoreXray, []ast.ServerInboundSpec{inbound}, nil, "")
	if err != nil {
		t.Fatalf("BuildServerConfig failed: %v", err)
	}

	runXraySyntaxCheck(t, "Trojan Server Inbound", serverJSON)
	t.Logf("✅ Xray Trojan Server Inbound verified")
}
