package hysteria_test

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/blackalex1/sentinel-core/pkg/ast"
	"github.com/blackalex1/sentinel-core/pkg/compiler/hysteria"
	"github.com/blackalex1/sentinel-core/pkg/parser"
)

// Test Live Syntax & Startup validation using real Hysteria 2 binary
func TestHysteria2_Client_LiveHysteriaBinaryValidation(t *testing.T) {
	hyBin := findCoreBin("hysteria")
	if hyBin == "" {
		t.Skip("hysteria binary not found, skipping live check")
		return
	}

	rawURI := "hy2://SecretKey123@node.example.org:8443?sni=node.example.org&insecure=1&obfs=salamander&obfs-password=mypassword#LiveTestNode"
	profile, err := parser.ParseURI(rawURI)
	if err != nil {
		t.Fatalf("URI parse error: %v", err)
	}

	spec := &ast.ConfigSpec{
		TargetCore: ast.CoreHysteria2,
		LogLevel:   "debug",
		ClientInbound: &ast.ClientInboundSpec{
			Mode:      ast.InboundModeSystemProxy,
			SocksPort: 20818,
			HTTPPort:  20819,
		},
		ServerNode: profile,
	}

	comp := hysteria.NewCompiler()
	cfgJSON, _, err := comp.Compile(spec)
	if err != nil {
		t.Fatalf("failed to compile Hysteria 2 client config: %v", err)
	}

	tmpFile, err := os.CreateTemp("", "hy2-client-live-*.json")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.WriteString(cfgJSON)
	tmpFile.Close()

	// Launch with 1 second timeout to verify config decodes without error
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, hyBin, "client", "-c", tmpFile.Name(), "--disable-update-check")
	out, _ := cmd.CombinedOutput()
	outStr := string(out)

	// If config was invalid, Hysteria would report "failed to load config" or "failed to parse config"
	if strings.Contains(outStr, "failed to load config") || strings.Contains(outStr, "failed to parse config") || strings.Contains(outStr, "invalid character") {
		t.Fatalf("Hysteria 2 failed to load client config:\nOutput:\n%s\nConfig:\n%s", outStr, cfgJSON)
	}

	t.Logf("✅ Real Hysteria 2 binary successfully parsed and validated client config")
}

// Test Live Server Config Syntax validation using real Hysteria 2 binary
func TestHysteria2_Server_LiveHysteriaBinaryValidation(t *testing.T) {
	hyBin := findCoreBin("hysteria")
	if hyBin == "" {
		t.Skip("hysteria binary not found, skipping live check")
		return
	}

	certPath, keyPath, cleanup := createTestCertAndKey(t)
	defer cleanup()

	inbound := ast.ServerInboundSpec{
		Protocol:      ast.ProtoHysteria2,
		Port:          38443,
		CertPath:      certPath,
		KeyPath:       keyPath,
		Clients: []ast.ServerInboundClient{
			{Email: "user1", Password: "MyPassword789!"},
		},
		ObfsType:      "salamander",
		ObfsPassword:  "SalamanderSecret123",
	}

	sc := hysteria.NewServerCompiler()
	serverJSON, err := sc.CompileServer(inbound, 0, "debug")
	if err != nil {
		t.Fatalf("failed to compile Hysteria 2 server config: %v", err)
	}

	tmpFile, err := os.CreateTemp("", "hy2-server-live-*.json")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.WriteString(serverJSON)
	tmpFile.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, hyBin, "server", "-c", tmpFile.Name(), "--disable-update-check")
	out, _ := cmd.CombinedOutput()
	outStr := string(out)

	if strings.Contains(outStr, "failed to load config") || strings.Contains(outStr, "failed to parse config") || strings.Contains(outStr, "invalid character") {
		t.Fatalf("Hysteria 2 failed to load server config:\nOutput:\n%s\nConfig:\n%s", outStr, serverJSON)
	}

	t.Logf("✅ Real Hysteria 2 binary successfully parsed and validated server config")
}
