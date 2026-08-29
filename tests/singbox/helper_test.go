package singbox_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/blackalex1/sentinel-core/pkg/ast"
	"github.com/blackalex1/sentinel-core/pkg/routing"
)

func findSingboxBin() string {
	candidates := []string{
		"../../bin/sing-box.exe",
		"../../bin/sing-box",
		"../../../panel/bin/sing-box.exe",
		"../../../panel/bin/sing-box",
		"../../panel/bin/sing-box.exe",
		"../../panel/bin/sing-box",
		"../bin/sing-box.exe",
		"../bin/sing-box",
		"bin/sing-box.exe",
		"bin/sing-box",
	}
	for _, c := range candidates {
		if fi, err := os.Stat(c); err == nil && !fi.IsDir() {
			return c
		}
	}
	if lp, err := exec.LookPath("sing-box"); err == nil {
		return lp
	}
	return ""
}

func runSingboxSyntaxCheck(t *testing.T, testName, configJSON string) {
	t.Helper()
	singboxBin := findSingboxBin()
	if singboxBin == "" {
		t.Skip("sing-box binary not found, skipping live check")
		return
	}

	tmpFile, err := os.CreateTemp("", "singbox-test-*.json")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(configJSON); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}
	tmpFile.Close()

	cmd := exec.Command(singboxBin, "check", "-c", tmpFile.Name())
	out, err := cmd.CombinedOutput()
	outStr := string(out)

	if err != nil && (strings.Contains(outStr, "FATAL") || strings.Contains(outStr, "error") || strings.Contains(outStr, "panic")) {
		t.Fatalf("[%s] Sing-box syntax check failed: %v\nOutput:\n%s\nConfig:\n%s", testName, err, outStr, configJSON)
	}
}

func buildClientTestSpec(profile *ast.ServerProfile) *ast.ConfigSpec {
	engine := routing.NewEngine()
	return &ast.ConfigSpec{
		TargetCore: ast.CoreSingBox,
		LogLevel:   "warn",
		ClientInbound: &ast.ClientInboundSpec{
			Mode:          ast.InboundModeSystemProxy,
			SocksPort:     10818,
			HTTPPort:      10819,
			ListenAddress: "127.0.0.1",
		},
		ServerNode: profile,
		Routing:    engine.CompilePolicy(routing.DefaultSmartPolicy()),
		DNS: &ast.DNSSpec{
			RemoteServer: "https://1.1.1.1/dns-query",
			DirectServer: "8.8.8.8",
			Strategy:     "ipv4_only",
		},
	}
}

func createTestCertAndKey(t *testing.T) (certPath, keyPath string, cleanup func()) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Sentinel Sing-box Test"},
			CommonName:   "singbox.sentinel.internal",
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

	certFile, err := os.CreateTemp("", "singbox-cert-*.crt")
	if err != nil {
		t.Fatalf("failed to create cert file: %v", err)
	}
	if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		t.Fatalf("failed to write cert: %v", err)
	}
	certFile.Close()

	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("failed to marshal private key: %v", err)
	}
	keyFile, err := os.CreateTemp("", "singbox-key-*.key")
	if err != nil {
		t.Fatalf("failed to create key file: %v", err)
	}
	if err := pem.Encode(keyFile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}); err != nil {
		t.Fatalf("failed to write key: %v", err)
	}
	keyFile.Close()

	cleanup = func() {
		os.Remove(certFile.Name())
		os.Remove(keyFile.Name())
	}

	return certFile.Name(), keyFile.Name(), cleanup
}
