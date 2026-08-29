package singbox_test

import (
	"encoding/json"
	"testing"

	"github.com/blackalex1/sentinel-core/pkg/ast"
	"github.com/blackalex1/sentinel-core/pkg/builder"
	"github.com/blackalex1/sentinel-core/pkg/crypto"
	"github.com/blackalex1/sentinel-core/pkg/parser"
)

// 1. VLESS Reality with TCP & XTLS Vision in Sing-box
func TestSingbox_VLESS_Reality_TCP_Vision(t *testing.T) {
	raw := "vless://b9f3857a-ce20-4e1e-b5e0-6f3d141fa2b2@198.51.100.1:443?type=tcp&security=reality&pbk=1pxvjj6jjhkkN40PM83ViQTJeC9VMDVe7oceMZuWNQY&sni=www.microsoft.com&sid=0123456789abcdef&fp=chrome&flow=xtls-rprx-vision#Singbox-VLESS-Reality"
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
	if primary["type"] != "vless" {
		t.Fatalf("expected outbound type vless, got %v", primary["type"])
	}

	tlsMap := primary["tls"].(map[string]interface{})
	realityMap := tlsMap["reality"].(map[string]interface{})
	if realityMap["public_key"] != "1pxvjj6jjhkkN40PM83ViQTJeC9VMDVe7oceMZuWNQY" {
		t.Fatalf("unexpected reality public_key: %v", realityMap["public_key"])
	}

	runSingboxSyntaxCheck(t, "VLESS Reality TCP Vision in Sing-box", res.ConfigJSON)
	t.Logf("✅ Sing-box VLESS Reality TCP Vision passed live verification")
}

// 2. VLESS Reality with gRPC in Sing-box
func TestSingbox_VLESS_Reality_gRPC(t *testing.T) {
	raw := "vless://b9f3857a-ce20-4e1e-b5e0-6f3d141fa2b2@198.51.100.2:443?type=grpc&serviceName=vless-grpc&security=reality&pbk=1pxvjj6jjhkkN40PM83ViQTJeC9VMDVe7oceMZuWNQY&sni=www.apple.com&sid=0123456789abcdef&fp=chrome#Singbox-VLESS-gRPC"
	profile, err := parser.ParseURI(raw)
	if err != nil {
		t.Fatalf("failed to parse URI: %v", err)
	}

	spec := buildClientTestSpec(profile)
	res, err := builder.BuildClientConfig(spec)
	if err != nil {
		t.Fatalf("BuildClientConfig failed: %v", err)
	}

	runSingboxSyntaxCheck(t, "VLESS Reality gRPC in Sing-box", res.ConfigJSON)
	t.Logf("✅ Sing-box VLESS Reality gRPC passed live verification")
}

// 3. VLESS Reality with WebSocket in Sing-box (Supported natively by Sing-box)
func TestSingbox_VLESS_Reality_WebSocket(t *testing.T) {
	raw := "vless://b9f3857a-ce20-4e1e-b5e0-6f3d141fa2b2@198.51.100.3:443?type=ws&path=/vless-ws&host=my-domain.com&security=reality&pbk=1pxvjj6jjhkkN40PM83ViQTJeC9VMDVe7oceMZuWNQY&sni=www.google.com&sid=0123456789abcdef&fp=chrome#Singbox-VLESS-WS-Reality"
	profile, err := parser.ParseURI(raw)
	if err != nil {
		t.Fatalf("failed to parse URI: %v", err)
	}

	spec := buildClientTestSpec(profile)
	res, err := builder.BuildClientConfig(spec)
	if err != nil {
		t.Fatalf("BuildClientConfig failed: %v", err)
	}

	runSingboxSyntaxCheck(t, "VLESS Reality WebSocket in Sing-box", res.ConfigJSON)
	t.Logf("✅ Sing-box VLESS Reality WebSocket passed live verification")
}

// 4. VLESS Reality with HTTPUpgrade in Sing-box
func TestSingbox_VLESS_Reality_HTTPUpgrade(t *testing.T) {
	raw := "vless://b9f3857a-ce20-4e1e-b5e0-6f3d141fa2b2@198.51.100.4:443?type=httpupgrade&path=/vless-httpupgrade&host=upgrade.domain.com&security=reality&pbk=1pxvjj6jjhkkN40PM83ViQTJeC9VMDVe7oceMZuWNQY&sni=www.microsoft.com&sid=0123456789abcdef&fp=chrome#Singbox-VLESS-HTTPUpgrade-Reality"
	profile, err := parser.ParseURI(raw)
	if err != nil {
		t.Fatalf("failed to parse URI: %v", err)
	}

	spec := buildClientTestSpec(profile)
	res, err := builder.BuildClientConfig(spec)
	if err != nil {
		t.Fatalf("BuildClientConfig failed: %v", err)
	}

	runSingboxSyntaxCheck(t, "VLESS Reality HTTPUpgrade in Sing-box", res.ConfigJSON)
	t.Logf("✅ Sing-box VLESS Reality HTTPUpgrade passed live verification")
}

// 5. VLESS TLS with TCP Vision in Sing-box
func TestSingbox_VLESS_TLS_TCP_Vision(t *testing.T) {
	raw := "vless://b9f3857a-ce20-4e1e-b5e0-6f3d141fa2b2@198.51.100.5:443?type=tcp&security=tls&sni=node.mydomain.com&fp=chrome&flow=xtls-rprx-vision#Singbox-VLESS-TLS"
	profile, err := parser.ParseURI(raw)
	if err != nil {
		t.Fatalf("failed to parse URI: %v", err)
	}

	spec := buildClientTestSpec(profile)
	res, err := builder.BuildClientConfig(spec)
	if err != nil {
		t.Fatalf("BuildClientConfig failed: %v", err)
	}

	runSingboxSyntaxCheck(t, "VLESS TLS TCP Vision in Sing-box", res.ConfigJSON)
	t.Logf("✅ Sing-box VLESS TLS TCP Vision passed live verification")
}

// 6. VLESS TLS with WebSocket in Sing-box
func TestSingbox_VLESS_TLS_WebSocket(t *testing.T) {
	raw := "vless://b9f3857a-ce20-4e1e-b5e0-6f3d141fa2b2@198.51.100.6:443?type=ws&path=/vless-tls-ws&host=node.mydomain.com&security=tls&sni=node.mydomain.com#Singbox-VLESS-TLS-WS"
	profile, err := parser.ParseURI(raw)
	if err != nil {
		t.Fatalf("failed to parse URI: %v", err)
	}

	spec := buildClientTestSpec(profile)
	res, err := builder.BuildClientConfig(spec)
	if err != nil {
		t.Fatalf("BuildClientConfig failed: %v", err)
	}

	runSingboxSyntaxCheck(t, "VLESS TLS WebSocket in Sing-box", res.ConfigJSON)
	t.Logf("✅ Sing-box VLESS TLS WebSocket passed live verification")
}

// 7. VLESS Plain (No TLS) in Sing-box
func TestSingbox_VLESS_Plain_NoTLS(t *testing.T) {
	raw := "vless://b9f3857a-ce20-4e1e-b5e0-6f3d141fa2b2@198.51.100.7:8080?type=tcp&security=none#Singbox-VLESS-Plain"
	profile, err := parser.ParseURI(raw)
	if err != nil {
		t.Fatalf("failed to parse URI: %v", err)
	}

	spec := buildClientTestSpec(profile)
	res, err := builder.BuildClientConfig(spec)
	if err != nil {
		t.Fatalf("BuildClientConfig failed: %v", err)
	}

	runSingboxSyntaxCheck(t, "VLESS Plain in Sing-box", res.ConfigJSON)
	t.Logf("✅ Sing-box VLESS Plain No TLS passed live verification")
}

// 8. VLESS Server Inbound with Multi-User & Reality in Sing-box
func TestSingbox_VLESS_Server_Reality_Multiplexing(t *testing.T) {
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
	}

	serverJSON, err := builder.BuildServerConfig(ast.CoreSingBox, []ast.ServerInboundSpec{inbound}, nil, "")
	if err != nil {
		t.Fatalf("BuildServerConfig failed: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(serverJSON), &parsed); err != nil {
		t.Fatalf("invalid server JSON: %v", err)
	}

	runSingboxSyntaxCheck(t, "VLESS Server Inbound with Reality in Sing-box", serverJSON)
	t.Logf("✅ Sing-box VLESS Server Inbound with Reality verified")
}
