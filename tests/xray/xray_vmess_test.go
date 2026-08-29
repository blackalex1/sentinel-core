package xray_test

import (
	"encoding/json"
	"testing"

	"github.com/blackalex1/sentinel-core/pkg/ast"
	"github.com/blackalex1/sentinel-core/pkg/builder"
	"github.com/blackalex1/sentinel-core/pkg/parser"
)

// 1. VMess TCP + TLS
func TestXray_VMess_TCP_TLS(t *testing.T) {
	raw := "vmess://eyJhZGQiOiJub2RlLnZtZXNzLm5ldCIsImFpZCI6MCwiaG9zdCI6Im5vZGUudm1lc3MubmV0IiwiaWQiOiJiOWYzODU3YS1jZTIwLTRlMWUtYjVlMC02ZjNkMTQxZmEyYjIiLCJuZXQiOiJ0Y3AiLCJwYXRoIjoiIiwicG9ydCI6NDQzLCJwcyI6IlZNZXNzLVRDUFRMUyIsInNjeSI6ImF1dG8iLCJzbmkiOiJub2RlLnZtZXNzLm5ldCIsInRscyI6InRscyIsInR5cGUiOiJub25lIiwidiI6Mn0="
	profile, err := parser.ParseURI(raw)
	if err != nil {
		t.Fatalf("failed to parse VMess URI: %v", err)
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
	if primary["protocol"] != "vmess" {
		t.Fatalf("expected protocol vmess, got %v", primary["protocol"])
	}

	runXraySyntaxCheck(t, "VMess TCP TLS", res.ConfigJSON)
	t.Logf("✅ Xray VMess TCP TLS passed live verification")
}

// 2. VMess WebSocket + TLS (CDN / Cloudflare)
func TestXray_VMess_WebSocket_TLS(t *testing.T) {
	raw := "vmess://eyJhZGQiOiJjZG4uY2xvdWRmbGFyZS5jb20iLCJhaWQiOjAsImhvc3QiOiJteS1hcHAud29ya2Vycy5kZXYiLCJpZCI6ImI5ZjM4NTdhLWNlMjAtNGUxZS1iNWUwLTZmM2QxNDFmYTJiMiIsIm5ldCI6IndzIiwicGF0aCI6Ii92bWVzcy13cyIsInBvcnQiOjQ0MywicHMiOiJWTWVzcy1XUy1UTFMiLCJzY3kiOiJhdXRvIiwic25pIjoibXktYXBwLndvcmtlcnMuZGV2IiwidGxzIjoidGxzIiwidHlwZSI6Im5vbmUiLCJ2IjoyfQ=="
	profile, err := parser.ParseURI(raw)
	if err != nil {
		t.Fatalf("failed to parse VMess WS URI: %v", err)
	}

	spec := buildClientTestSpec(profile)
	res, err := builder.BuildClientConfig(spec)
	if err != nil {
		t.Fatalf("BuildClientConfig failed: %v", err)
	}

	runXraySyntaxCheck(t, "VMess WebSocket TLS", res.ConfigJSON)
	t.Logf("✅ Xray VMess WebSocket TLS passed live verification")
}

// 3. VMess gRPC + TLS
func TestXray_VMess_gRPC_TLS(t *testing.T) {
	profile := &ast.ServerProfile{
		Protocol:  ast.ProtoVMess,
		Address:   "grpc.vmess.org",
		Port:      8443,
		UUID:      "b9f3857a-ce20-4e1e-b5e0-6f3d141fa2b2",
		Transport: "grpc",
		Path:      "vmess-service",
		Security:  "tls",
		SNI:       "grpc.vmess.org",
		Cipher:    "auto",
		Name:      "VMess-gRPC",
	}

	spec := buildClientTestSpec(profile)
	res, err := builder.BuildClientConfig(spec)
	if err != nil {
		t.Fatalf("BuildClientConfig failed: %v", err)
	}

	runXraySyntaxCheck(t, "VMess gRPC TLS", res.ConfigJSON)
	t.Logf("✅ Xray VMess gRPC TLS passed live verification")
}

// 4. VMess Security Ciphers: auto, aes-128-gcm, chacha20-poly1305, zero, none
func TestXray_VMess_SecurityCiphers(t *testing.T) {
	ciphers := []string{"auto", "aes-128-gcm", "chacha20-poly1305", "zero", "none"}

	for _, c := range ciphers {
		t.Run("Cipher_"+c, func(t *testing.T) {
			profile := &ast.ServerProfile{
				Protocol:  ast.ProtoVMess,
				Address:   "198.51.100.80",
				Port:      10086,
				UUID:      "b9f3857a-ce20-4e1e-b5e0-6f3d141fa2b2",
				Transport: "tcp",
				Cipher:    c,
				Name:      "VMess-" + c,
			}

			spec := buildClientTestSpec(profile)
			res, err := builder.BuildClientConfig(spec)
			if err != nil {
				t.Fatalf("BuildClientConfig failed for cipher %s: %v", c, err)
			}

			runXraySyntaxCheck(t, "VMess Cipher "+c, res.ConfigJSON)
		})
	}
}

// 5. VMess Server Inbound
func TestXray_VMess_Server_Inbound(t *testing.T) {
	certPath, keyPath, cleanup := createTestCertAndKey(t)
	defer cleanup()

	inbound := ast.ServerInboundSpec{
		Protocol:      "vmess",
		ListenAddress: "0.0.0.0",
		Port:          10443,
		Security:      "tls",
		SNI:           "xray.sentinel.internal",
		CertPath:      certPath,
		KeyPath:       keyPath,
		Clients: []ast.ServerInboundClient{
			{UUID: "b9f3857a-ce20-4e1e-b5e0-6f3d141fa2b2", Email: "vmess1@sentinel"},
			{UUID: "c8e2746b-bd19-3d0d-a4df-5e2c030e91a1", Email: "vmess2@sentinel"},
		},
	}

	serverJSON, err := builder.BuildServerConfig(ast.CoreXray, []ast.ServerInboundSpec{inbound}, nil, "")
	if err != nil {
		t.Fatalf("BuildServerConfig failed: %v", err)
	}

	runXraySyntaxCheck(t, "VMess Server Inbound", serverJSON)
	t.Logf("✅ Xray VMess Server Inbound verified")
}
