package hysteria_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/blackalex1/sentinel-core/pkg/ast"
	"github.com/blackalex1/sentinel-core/pkg/builder"
	"github.com/blackalex1/sentinel-core/pkg/compiler/hysteria"
)

func createTestCertAndKey(t *testing.T) (certPath, keyPath string, cleanup func()) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Sentinel Unit Test"},
			CommonName:   "mock.sentinel.internal",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	certFile, err := os.CreateTemp("", "testcert-*.crt")
	if err != nil {
		t.Fatalf("failed to create temp cert file: %v", err)
	}
	pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	certFile.Close()

	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("failed to marshal private key: %v", err)
	}
	keyFile, err := os.CreateTemp("", "testkey-*.key")
	if err != nil {
		t.Fatalf("failed to create temp key file: %v", err)
	}
	pem.Encode(keyFile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	keyFile.Close()

	cleanup = func() {
		os.Remove(certFile.Name())
		os.Remove(keyFile.Name())
	}
	return certFile.Name(), keyFile.Name(), cleanup
}

// 1. Standalone Hysteria 2 Server with Single/Multi-Client Password Auth
func TestHysteria2_Server_PasswordAuth(t *testing.T) {
	certPath, keyPath, cleanup := createTestCertAndKey(t)
	defer cleanup()

	inbound := ast.ServerInboundSpec{
		Protocol:      ast.ProtoHysteria2,
		ListenAddress: "::",
		Port:          8443,
		CertPath:      certPath,
		KeyPath:       keyPath,
		Clients: []ast.ServerInboundClient{
			{Email: "alice", Password: "AlicePassword123!"},
			{Email: "bob", Password: "BobPassword456!"},
		},
		ObfsType:      "salamander",
		ObfsPassword:  "SalamanderSecretPass",
		BandwidthUp:   "100 mbps",
		BandwidthDown: "1000 mbps",
	}

	sc := hysteria.NewServerCompiler()
	serverJSON, err := sc.CompileServer(inbound, 0, "info")
	if err != nil {
		t.Fatalf("failed to compile Hysteria 2 server config: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(serverJSON), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v\nJSON:\n%s", err, serverJSON)
	}

	if parsed["listen"] != ":8443" && parsed["listen"] != "[::]:8443" {
		t.Errorf("expected listen :8443, got %v", parsed["listen"])
	}

	tlsMap := parsed["tls"].(map[string]interface{})
	if tlsMap["cert"] != certPath || tlsMap["key"] != keyPath {
		t.Errorf("unexpected TLS paths: %v", tlsMap)
	}

	obfsMap := parsed["obfs"].(map[string]interface{})
	if obfsMap["type"] != "salamander" {
		t.Errorf("expected salamander obfs, got %v", obfsMap)
	}

	authMap := parsed["auth"].(map[string]interface{})
	if authMap["type"] != "userpass" && authMap["type"] != "password" {
		t.Errorf("expected userpass or password auth, got %v", authMap["type"])
	}

	t.Logf("✅ Hysteria 2 Server Password Auth verified")
}

// 2. Hysteria 2 Server with HTTP Webhook Authentication Backend
func TestHysteria2_Server_HTTPWebhookAuth(t *testing.T) {
	certPath, keyPath, cleanup := createTestCertAndKey(t)
	defer cleanup()

	webhookURL := "https://auth.sentinel-panel.com/v2/hysteria/auth"

	inbound := ast.ServerInboundSpec{
		Protocol:      ast.ProtoHysteria2,
		Port:          443,
		CertPath:      certPath,
		KeyPath:       keyPath,
		AuthURL:       webhookURL,
		Clients: []ast.ServerInboundClient{
			{
				Email:    "webhook-backend",
				Password: webhookURL,
			},
		},
	}

	sc := hysteria.NewServerCompiler()
	serverJSON, err := sc.CompileServer(inbound, 0, "info")
	if err != nil {
		t.Fatalf("failed to compile HTTP webhook auth server config: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(serverJSON), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	authMap := parsed["auth"].(map[string]interface{})
	if authMap["type"] != "http" {
		t.Errorf("expected auth type http, got %v", authMap["type"])
	}
	httpSub := authMap["http"].(map[string]interface{})
	if httpSub["url"] != webhookURL {
		t.Errorf("expected url %s, got %v", webhookURL, httpSub["url"])
	}

	t.Logf("✅ Hysteria 2 Server HTTP Webhook Auth verified")
}

// 3. Hysteria 2 Server Forwarding to Local Routing Core (Xray/Sing-box Cascade)
func TestHysteria2_Server_CascadeForwardingToRoutingCore(t *testing.T) {
	certPath, keyPath, cleanup := createTestCertAndKey(t)
	defer cleanup()

	inbound := ast.ServerInboundSpec{
		Protocol: ast.ProtoHysteria2,
		Port:     443,
		CertPath: certPath,
		KeyPath:  keyPath,
		Clients: []ast.ServerInboundClient{
			{Email: "user1", Password: "Pass1"},
		},
	}

	// Server forwardPort = 20808 (local SOCKS5 routing listener)
	serverJSON, err := builder.BuildServerConfig(ast.CoreHysteria2, []ast.ServerInboundSpec{inbound}, &ast.RoutingSpec{
		Rules: []ast.RoutingRule{
			{Action: ast.ActionDirect, Domains: []string{"geosite:category-ru"}},
		},
	}, "")
	if err != nil {
		t.Fatalf("BuildServerConfig failed: %v", err)
	}

	if !strings.Contains(serverJSON, `127.0.0.1:20808`) {
		t.Errorf("expected forwarding to local routing port 127.0.0.1:20808, got:\n%s", serverJSON)
	}

	t.Logf("✅ Hysteria 2 Server Cascade Forwarding verified")
}
