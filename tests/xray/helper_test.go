package xray_test

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

func findXrayBin() string {
	candidates := []string{
		"../../bin/xray.exe",
		"../../bin/xray",
		"../../../panel/bin/xray.exe",
		"../../../panel/bin/xray",
		"../../panel/bin/xray.exe",
		"../../panel/bin/xray",
		"../bin/xray.exe",
		"../bin/xray",
		"bin/xray.exe",
		"bin/xray",
	}
	for _, c := range candidates {
		if fi, err := os.Stat(c); err == nil && !fi.IsDir() {
			return c
		}
	}
	if lp, err := exec.LookPath("xray"); err == nil {
		return lp
	}
	return ""
}

func runXraySyntaxCheck(t *testing.T, testName, configJSON string) {
	t.Helper()
	xrayBin := findXrayBin()
	if xrayBin == "" {
		t.Skip("xray binary not found, skipping live check")
		return
	}

	tmpFile, err := os.CreateTemp("", "xray-test-*.json")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(configJSON); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}
	tmpFile.Close()

	cmd := exec.Command(xrayBin, "-test", "-config", tmpFile.Name())
	out, err := cmd.CombinedOutput()
	outStr := string(out)

	// If there are fatal loading errors, fail test. Deprecation warnings (e.g. on Shadowsocks or HTTPUpgrade) are non-fatal.
	if err != nil && (strings.Contains(outStr, "Failed to start") || strings.Contains(outStr, "failed to build") || strings.Contains(outStr, "invalid json")) {
		t.Fatalf("[%s] Xray syntax check failed: %v\nOutput:\n%s\nConfig:\n%s", testName, err, outStr, configJSON)
	}
}

func buildClientTestSpec(profile *ast.ServerProfile) *ast.ConfigSpec {
	engine := routing.NewEngine()
	return &ast.ConfigSpec{
		TargetCore: ast.CoreXray,
		LogLevel:   "warning",
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
			Organization: []string{"Sentinel Xray Test"},
			CommonName:   "xray.sentinel.internal",
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

	certFile, err := os.CreateTemp("", "xray-cert-*.crt")
	if err != nil {
		t.Fatalf("failed to create temp cert file: %v", err)
	}
	pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	certFile.Close()

	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("failed to marshal private key: %v", err)
	}
	keyFile, err := os.CreateTemp("", "xray-key-*.key")
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
