package singbox_test

import (
	"encoding/json"
	"testing"

	"github.com/blackalex1/sentinel-core/pkg/ast"
	"github.com/blackalex1/sentinel-core/pkg/builder"
	"github.com/blackalex1/sentinel-core/pkg/parser"
)

// 1. Trojan TCP TLS in Sing-box
func TestSingbox_Trojan_TCP_TLS(t *testing.T) {
	raw := "trojan://secretTrojanPass@198.51.100.30:443?security=tls&sni=trojan.example.com#Singbox-Trojan-TCP"
	profile, err := parser.ParseURI(raw)
	if err != nil {
		t.Fatalf("ParseURI failed: %v", err)
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
	if primary["type"] != "trojan" {
		t.Fatalf("expected outbound type trojan, got %v", primary["type"])
	}

	runSingboxSyntaxCheck(t, "Trojan TCP TLS in Sing-box", res.ConfigJSON)
	t.Logf("✅ Sing-box Trojan TCP TLS passed live verification")
}

// 2. Trojan WebSocket TLS in Sing-box
func TestSingbox_Trojan_WebSocket_TLS(t *testing.T) {
	raw := "trojan://secretTrojanPass@198.51.100.31:443?type=ws&path=/trojan-ws&host=trojan.example.com&security=tls&sni=trojan.example.com#Singbox-Trojan-WS"
	profile, err := parser.ParseURI(raw)
	if err != nil {
		t.Fatalf("ParseURI failed: %v", err)
	}

	spec := buildClientTestSpec(profile)
	res, err := builder.BuildClientConfig(spec)
	if err != nil {
		t.Fatalf("BuildClientConfig failed: %v", err)
	}

	runSingboxSyntaxCheck(t, "Trojan WebSocket TLS in Sing-box", res.ConfigJSON)
	t.Logf("✅ Sing-box Trojan WebSocket TLS passed live verification")
}

// 3. Trojan gRPC TLS in Sing-box
func TestSingbox_Trojan_gRPC_TLS(t *testing.T) {
	raw := "trojan://secretTrojanPass@198.51.100.32:443?type=grpc&serviceName=trojan-grpc&security=tls&sni=trojan.example.com#Singbox-Trojan-gRPC"
	profile, err := parser.ParseURI(raw)
	if err != nil {
		t.Fatalf("ParseURI failed: %v", err)
	}

	spec := buildClientTestSpec(profile)
	res, err := builder.BuildClientConfig(spec)
	if err != nil {
		t.Fatalf("BuildClientConfig failed: %v", err)
	}

	runSingboxSyntaxCheck(t, "Trojan gRPC TLS in Sing-box", res.ConfigJSON)
	t.Logf("✅ Sing-box Trojan gRPC TLS passed live verification")
}

// 4. Trojan Server Inbound in Sing-box
func TestSingbox_Trojan_Server_Inbound(t *testing.T) {
	certPath, keyPath, cleanup := createTestCertAndKey(t)
	defer cleanup()

	inbound := ast.ServerInboundSpec{
		Protocol:      "trojan",
		ListenAddress: "0.0.0.0",
		Port:          443,
		Security:      "tls",
		SNI:           "trojan.sentinel.internal",
		CertPath:      certPath,
		KeyPath:       keyPath,
		Clients: []ast.ServerInboundClient{
			{Password: "trojanSecretUser1", Email: "user1@sentinel"},
			{Password: "trojanSecretUser2", Email: "user2@sentinel"},
		},
	}

	serverJSON, err := builder.BuildServerConfig(ast.CoreSingBox, []ast.ServerInboundSpec{inbound}, nil, "")
	if err != nil {
		t.Fatalf("BuildServerConfig failed: %v", err)
	}

	runSingboxSyntaxCheck(t, "Trojan Server Inbound in Sing-box", serverJSON)
	t.Logf("✅ Sing-box Trojan Server Inbound verified")
}

// 5. VMess TCP TLS in Sing-box
func TestSingbox_VMess_TCP_TLS(t *testing.T) {
	node := &ast.ServerProfile{
		Protocol:  ast.ProtoVMess,
		Address:   "198.51.100.40",
		Port:      443,
		UUID:      "b9f3857a-ce20-4e1e-b5e0-6f3d141fa2b2",
		Transport: "tcp",
		Security:  "tls",
		SNI:       "vmess.example.com",
		Cipher:    "auto",
		Name:      "Singbox-VMess-TCP",
	}

	spec := buildClientTestSpec(node)
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
	if primary["type"] != "vmess" {
		t.Fatalf("expected outbound type vmess, got %v", primary["type"])
	}

	runSingboxSyntaxCheck(t, "VMess TCP TLS in Sing-box", res.ConfigJSON)
	t.Logf("✅ Sing-box VMess TCP TLS passed live verification")
}

// 6. VMess WebSocket TLS in Sing-box
func TestSingbox_VMess_WebSocket_TLS(t *testing.T) {
	node := &ast.ServerProfile{
		Protocol:  ast.ProtoVMess,
		Address:   "198.51.100.41",
		Port:      443,
		UUID:      "b9f3857a-ce20-4e1e-b5e0-6f3d141fa2b2",
		Transport: "ws",
		Path:      "/vmess-ws",
		Host:      "vmess.example.com",
		Security:  "tls",
		SNI:       "vmess.example.com",
		Cipher:    "auto",
		Name:      "Singbox-VMess-WS",
	}

	spec := buildClientTestSpec(node)
	res, err := builder.BuildClientConfig(spec)
	if err != nil {
		t.Fatalf("BuildClientConfig failed: %v", err)
	}

	runSingboxSyntaxCheck(t, "VMess WebSocket TLS in Sing-box", res.ConfigJSON)
	t.Logf("✅ Sing-box VMess WebSocket TLS passed live verification")
}

// 7. VMess gRPC TLS in Sing-box
func TestSingbox_VMess_gRPC_TLS(t *testing.T) {
	node := &ast.ServerProfile{
		Protocol:    ast.ProtoVMess,
		Address:     "198.51.100.42",
		Port:        443,
		UUID:        "b9f3857a-ce20-4e1e-b5e0-6f3d141fa2b2",
		Transport:   "grpc",
		ServiceName: "vmess-grpc",
		Security:    "tls",
		SNI:         "vmess.example.com",
		Cipher:      "auto",
		Name:        "Singbox-VMess-gRPC",
	}

	spec := buildClientTestSpec(node)
	res, err := builder.BuildClientConfig(spec)
	if err != nil {
		t.Fatalf("BuildClientConfig failed: %v", err)
	}

	runSingboxSyntaxCheck(t, "VMess gRPC TLS in Sing-box", res.ConfigJSON)
	t.Logf("✅ Sing-box VMess gRPC TLS passed live verification")
}

// 8. VMess Server Inbound in Sing-box
func TestSingbox_VMess_Server_Inbound(t *testing.T) {
	inbound := ast.ServerInboundSpec{
		Protocol:      "vmess",
		ListenAddress: "0.0.0.0",
		Port:          8443,
		Security:      "none",
		Clients: []ast.ServerInboundClient{
			{UUID: "b9f3857a-ce20-4e1e-b5e0-6f3d141fa2b2", Email: "user1@sentinel"},
			{UUID: "c8e2746b-bd19-3d0d-a4df-5e2c030e91a1", Email: "user2@sentinel"},
		},
	}

	serverJSON, err := builder.BuildServerConfig(ast.CoreSingBox, []ast.ServerInboundSpec{inbound}, nil, "")
	if err != nil {
		t.Fatalf("BuildServerConfig failed: %v", err)
	}

	runSingboxSyntaxCheck(t, "VMess Server Inbound in Sing-box", serverJSON)
	t.Logf("✅ Sing-box VMess Server Inbound verified")
}
