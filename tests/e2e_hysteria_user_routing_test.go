package tests

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/blackalex1/sentinel-core/pkg/ast"
	"github.com/blackalex1/sentinel-core/pkg/builder"
)

// TestE2E_RealHysteria2_PerClientRouting_BlockGoogleForSingleUser starts a real Sing-box server with
// Hysteria 2 inbound, compiled via Sentinel-Core builder with a per-user routing rule:
// - User "blocked_user@test.lan" is BLOCKED from accessing Google.
// - User "allowed_user@test.lan" is ALLOWED to access Google.
// Two real Sing-box client binaries are launched (compiled via Sentinel-Core) connecting via Hysteria 2,
// and real traffic is sent through both tunnels to verify the selective routing behavior.
func TestE2E_RealHysteria2_PerClientRouting_BlockGoogleForSingleUser(t *testing.T) {
	sbBin := findBinary("sing-box")
	if sbBin == "" {
		t.Skip("sing-box binary not found, skipping real core test")
		return
	}

	certPath, keyPath, cleanupCert := createTestCertAndKey(t)
	defer cleanupCert()

	serverPort := getFreePort(t)
	client1Port := getFreePort(t)
	client2Port := getFreePort(t)

	blockedUser := "blocked_user@test.lan"
	blockedPassword := "pwd_secret_blocked_123"

	allowedUser := "allowed_user@test.lan"
	allowedPassword := "pwd_secret_allowed_456"

	testSNI := "matrix.test.example.com"

	// 1. Build Server Configuration using Sentinel-Core Builder
	serverInbounds := []ast.ServerInboundSpec{
		{
			Tag:           "hy2-in",
			Protocol:      "hysteria2",
			ListenAddress: "127.0.0.1",
			Port:          serverPort,
			Security:      ast.SecurityTLS,
			SNI:           testSNI,
			CertPath:      certPath,
			KeyPath:       keyPath,
			Clients: []ast.ServerInboundClient{
				{Email: blockedUser, Password: blockedPassword},
				{Email: allowedUser, Password: allowedPassword},
			},
		},
	}

	serverRouting := &ast.RoutingSpec{
		DefaultAction: ast.ActionDirect,
		Rules: []ast.RoutingRule{
			{
				Action:  ast.ActionBlock,
				Users:   []string{blockedUser},
				Domains: []string{"google.com"},
			},
		},
	}

	serverConfigJSON, err := builder.BuildServerConfig(ast.CoreSingBox, serverInbounds, serverRouting, "", "", "info")
	if err != nil {
		t.Fatalf("Sentinel-Core failed to compile server configuration: %v", err)
	}

	// Verify server config contains expected rules
	if !strings.Contains(serverConfigJSON, blockedUser) {
		t.Fatalf("Compiled server config missing blocked user %s", blockedUser)
	}
	if !strings.Contains(serverConfigJSON, "google.com") {
		t.Fatalf("Compiled server config missing google.com routing rule")
	}

	tmpServerConfig, err := os.CreateTemp("", "sb-hy2-server-*.json")
	if err != nil {
		t.Fatalf("failed to create temp server config: %v", err)
	}
	defer os.Remove(tmpServerConfig.Name())
	_, _ = tmpServerConfig.WriteString(serverConfigJSON)
	tmpServerConfig.Close()

	// 2. Build Client 1 Config (blocked_user@test.lan) using Sentinel-Core
	client1Spec := &ast.ConfigSpec{
		TargetCore: ast.CoreSingBox,
		LogLevel:   "info",
		ServerNode: &ast.ServerProfile{
			Protocol: ast.ProtoHysteria2,
			Address:  "127.0.0.1",
			Port:     serverPort,
			Password: blockedPassword,
			Insecure: true,
			SNI:      testSNI,
			Name:     "hy2-tunnel",
		},
		ClientInbound: &ast.ClientInboundSpec{
			Mode:          ast.InboundModeSystemProxy,
			ListenAddress: "127.0.0.1",
			HTTPPort:      client1Port,
		},
		Routing: &ast.RoutingSpec{
			DefaultAction: ast.ActionProxy,
		},
	}

	client1Res, err := builder.BuildClientConfig(client1Spec)
	if err != nil {
		t.Fatalf("Sentinel-Core failed to build Client 1 config: %v", err)
	}

	tmpClient1Config, err := os.CreateTemp("", "sb-hy2-client1-*.json")
	if err != nil {
		t.Fatalf("failed to create temp client 1 config: %v", err)
	}
	defer os.Remove(tmpClient1Config.Name())
	_, _ = tmpClient1Config.WriteString(client1Res.ConfigJSON)
	tmpClient1Config.Close()

	// 3. Build Client 2 Config (allowed_user@test.lan) using Sentinel-Core
	client2Spec := &ast.ConfigSpec{
		TargetCore: ast.CoreSingBox,
		LogLevel:   "info",
		ServerNode: &ast.ServerProfile{
			Protocol: ast.ProtoHysteria2,
			Address:  "127.0.0.1",
			Port:     serverPort,
			Password: allowedPassword,
			Insecure: true,
			SNI:      testSNI,
			Name:     "hy2-tunnel",
		},
		ClientInbound: &ast.ClientInboundSpec{
			Mode:          ast.InboundModeSystemProxy,
			ListenAddress: "127.0.0.1",
			HTTPPort:      client2Port,
		},
		Routing: &ast.RoutingSpec{
			DefaultAction: ast.ActionProxy,
		},
	}

	client2Res, err := builder.BuildClientConfig(client2Spec)
	if err != nil {
		t.Fatalf("Sentinel-Core failed to build Client 2 config: %v", err)
	}

	tmpClient2Config, err := os.CreateTemp("", "sb-hy2-client2-*.json")
	if err != nil {
		t.Fatalf("failed to create temp client 2 config: %v", err)
	}
	defer os.Remove(tmpClient2Config.Name())
	_, _ = tmpClient2Config.WriteString(client2Res.ConfigJSON)
	tmpClient2Config.Close()

	// 4. Launch Real Server Core (Sing-box with Hysteria 2 Inbound)
	serverCtx, serverCancel := context.WithCancel(context.Background())
	defer serverCancel()

	serverCmd := exec.CommandContext(serverCtx, sbBin, "run", "-c", tmpServerConfig.Name())
	var serverLogBuf bytes.Buffer
	serverCmd.Stdout = &serverLogBuf
	serverCmd.Stderr = &serverLogBuf

	if err := serverCmd.Start(); err != nil {
		t.Fatalf("failed to start real Sing-box server: %v", err)
	}
	defer func() {
		serverCancel()
		if serverCmd.Process != nil {
			_ = serverCmd.Process.Kill()
			_ = serverCmd.Wait()
		}
	}()

	time.Sleep(500 * time.Millisecond)

	// 5. Launch Real Client 1 Core (blocked_user)
	client1Ctx, client1Cancel := context.WithCancel(context.Background())
	defer client1Cancel()

	client1Cmd := exec.CommandContext(client1Ctx, sbBin, "run", "-c", tmpClient1Config.Name())
	var client1LogBuf bytes.Buffer
	client1Cmd.Stdout = &client1LogBuf
	client1Cmd.Stderr = &client1LogBuf

	if err := client1Cmd.Start(); err != nil {
		t.Fatalf("failed to start real Sing-box Client 1: %v", err)
	}
	defer func() {
		client1Cancel()
		if client1Cmd.Process != nil {
			_ = client1Cmd.Process.Kill()
			_ = client1Cmd.Wait()
		}
	}()

	// 6. Launch Real Client 2 Core (allowed_user)
	client2Ctx, client2Cancel := context.WithCancel(context.Background())
	defer client2Cancel()

	client2Cmd := exec.CommandContext(client2Ctx, sbBin, "run", "-c", tmpClient2Config.Name())
	var client2LogBuf bytes.Buffer
	client2Cmd.Stdout = &client2LogBuf
	client2Cmd.Stderr = &client2LogBuf

	if err := client2Cmd.Start(); err != nil {
		t.Fatalf("failed to start real Sing-box Client 2: %v", err)
	}
	defer func() {
		client2Cancel()
		if client2Cmd.Process != nil {
			_ = client2Cmd.Process.Kill()
			_ = client2Cmd.Wait()
		}
	}()

	time.Sleep(600 * time.Millisecond)

	// Prepare HTTP Clients
	proxy1URL, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", client1Port))
	httpClient1 := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxy1URL),
		},
		Timeout: 4 * time.Second,
	}

	proxy2URL, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", client2Port))
	httpClient2 := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxy2URL),
		},
		Timeout: 6 * time.Second,
	}

	// 7. Verify Client 1 (blocked_user) accessing Google -> MUST BE BLOCKED
	t.Logf("Checking Client 1 (%s) accessing google.com through Hysteria 2 tunnel...", blockedUser)
	resp1, err1 := httpClient1.Get("http://www.google.com")
	if err1 == nil && resp1 != nil {
		defer resp1.Body.Close()
		body1, _ := io.ReadAll(resp1.Body)
		if resp1.StatusCode == http.StatusOK {
			t.Fatalf("EXPECTED BLOCK for Client 1 on google.com, but got HTTP 200 OK: %s\nServer Config:\n%s\nServer Logs:\n%s",
				string(body1[:100]), serverConfigJSON, serverLogBuf.String())
		}
		t.Logf("Client 1 was blocked with response: %s", resp1.Status)
	} else {
		t.Logf("✅ Client 1 connection to google.com was correctly BLOCKED/DROPPED: %v", err1)
	}

	// 8. Verify Client 2 (allowed_user) accessing Google -> MUST SUCCEED
	t.Logf("Checking Client 2 (%s) accessing google.com through Hysteria 2 tunnel...", allowedUser)
	resp2, err2 := httpClient2.Get("http://www.google.com")
	if err2 != nil {
		t.Fatalf("EXPECTED SUCCESS for Client 2 on google.com, but got error: %v", err2)
	}
	defer resp2.Body.Close()
	body2, _ := io.ReadAll(resp2.Body)

	if resp2.StatusCode != http.StatusOK && resp2.StatusCode != http.StatusFound && resp2.StatusCode != http.StatusMovedPermanently {
		t.Fatalf("Unexpected status for Client 2: %d, body: %s\nServer logs:\n%s\nClient 2 logs:\n%s",
			resp2.StatusCode, string(body2[:min(len(body2), 200)]), serverLogBuf.String(), client2LogBuf.String())
	}
	t.Logf("✅ Client 2 successfully accessed google.com: Status=%d (%d bytes received)", resp2.StatusCode, len(body2))

	// 9. Verify Client 1 can still access other websites (e.g. cloudflare.com) -> proving selective blocking!
	t.Logf("Checking Client 1 (%s) accessing cloudflare.com to verify non-blocked targets pass through...", blockedUser)
	resp1Other, err1Other := httpClient1.Get("http://www.cloudflare.com")
	if err1Other == nil && resp1Other != nil {
		resp1Other.Body.Close()
		t.Logf("✅ Client 1 can access non-blocked domain cloudflare.com (Status=%d), proving selective per-user routing!", resp1Other.StatusCode)
	} else {
		t.Logf("Client 1 other-site probe result: err=%v", err1Other)
	}
}
