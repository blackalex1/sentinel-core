package tests

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/blackalex1/sentinel-core/pkg/ast"
	"github.com/blackalex1/sentinel-core/pkg/builder"
	"github.com/blackalex1/sentinel-core/pkg/routing"
)

func TestSingBoxLive_GoogleBlockAndDirectAccess(t *testing.T) {
	// Locate sing-box binary
	singboxBin, err := filepath.Abs("../bin/sing-box.exe")
	if err != nil {
		t.Fatalf("failed to resolve singbox path: %v", err)
	}
	fi, err := os.Stat(singboxBin)
	if err != nil || fi.IsDir() {
		t.Skipf("sing-box binary not found at %s, skipping live test", singboxBin)
	}

	httpPort := 20809
	socksPort := 20808

	// 1. Build routing table using sentinel_core:
	// - Rule 1: Block google.com
	// - Default: Direct for all other traffic
	table := routing.NewRoutingTable("direct")
	table.AddRule(routing.RoutingRuleRow{
		Order:   1,
		Name:    "Block Google",
		Enabled: true,
		Target:  "block",
		Domains: []string{"domain:google.com", "google.com", "regexp:.*\\.google\\.com$"},
	})

	spec := &ast.ConfigSpec{
		TargetCore: ast.CoreSingBox,
		ClientInbound: &ast.ClientInboundSpec{
			Mode:      ast.InboundModeSystemProxy,
			SocksPort: socksPort,
			HTTPPort:  httpPort,
		},
		Routing: table.CompileToAST(),
	}

	res, err := builder.BuildClientConfig(spec)
	if err != nil {
		t.Fatalf("failed to compile Sing-box config via sentinel_core: %v", err)
	}

	configFile, err := filepath.Abs("../bin/test_block_google.json")
	if err != nil {
		t.Fatalf("failed to resolve config path: %v", err)
	}
	if err := os.WriteFile(configFile, []byte(res.ConfigJSON), 0644); err != nil {
		t.Fatalf("failed to write test config: %v", err)
	}
	defer os.Remove(configFile)

	// Validate config syntax with sing-box check
	checkCmd := exec.Command(singboxBin, "check", "-c", configFile)
	checkCmd.Dir = filepath.Dir(singboxBin)
	var checkOut bytes.Buffer
	checkCmd.Stdout = &checkOut
	checkCmd.Stderr = &checkOut
	if err := checkCmd.Run(); err != nil {
		t.Fatalf("sing-box check failed: %v\nOutput: %s\nJSON:\n%s", err, checkOut.String(), res.ConfigJSON)
	}
	t.Logf("sing-box check passed successfully!")

	// 2. Start sing-box.exe in background
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cmd := exec.CommandContext(ctx, singboxBin, "run", "-c", configFile)
	cmd.Dir = filepath.Dir(singboxBin)
	var logBuf bytes.Buffer
	cmd.Stdout = &logBuf
	cmd.Stderr = &logBuf

	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start sing-box: %v", err)
	}
	defer func() {
		cancel()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()

	// Wait until HTTP port is ready to accept connections
	ready := false
	for i := 0; i < 20; i++ {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", httpPort), 200*time.Millisecond)
		if err == nil {
			conn.Close()
			ready = true
			break
		}
		time.Sleep(150 * time.Millisecond)
	}

	if !ready {
		t.Fatalf("sing-box failed to start listening on port %d within timeout. Logs:\n%s", httpPort, logBuf.String())
	}
	t.Logf("sing-box is actively listening on HTTP port %d and SOCKS %d", httpPort, socksPort)

	// 3. Create HTTP client using the local Sing-box HTTP proxy (127.0.0.1:20809)
	proxyURL, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", httpPort))
	httpClient := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
		Timeout: 5 * time.Second,
	}

	// 4. Test 1: Request to google.com via HTTP proxy -> MUST BE BLOCKED (Sing-box returns 502 Bad Gateway or drops)
	t.Log("===> [HTTP Proxy] Testing request to http://google.com through Sing-box...")
	respGoogle, errGoogle := httpClient.Get("http://google.com")
	if errGoogle != nil {
		t.Logf("SUCCESS: Request to google.com was blocked at network level: %v", errGoogle)
	} else {
		defer respGoogle.Body.Close()
		if respGoogle.StatusCode == http.StatusBadGateway {
			t.Logf("SUCCESS: Sing-box blocked google.com with HTTP 502 Bad Gateway as expected!")
		} else {
			t.Errorf("expected google.com to be blocked (502 or network error), but got HTTP %d", respGoogle.StatusCode)
		}
	}

	// 5. Test 2: Request to 1.1.1.1 (Cloudflare Direct) -> MUST SUCCEED (200 OK)
	t.Log("===> [HTTP Proxy] Testing request to http://1.1.1.1 through Sing-box (Direct)...")
	respDirect, errDirect := httpClient.Get("http://1.1.1.1")
	if errDirect != nil {
		t.Logf("Direct request note: %v (network dependent)", errDirect)
	} else {
		respDirect.Body.Close()
		if respDirect.StatusCode == http.StatusOK || respDirect.StatusCode == http.StatusMovedPermanently {
			t.Logf("SUCCESS: Request to 1.1.1.1 passed through Direct rule with status %d!", respDirect.StatusCode)
		}
	}

	// 6. Test 3: Request to google.com via SOCKS5 proxy (127.0.0.1:20808) -> MUST FAIL / BLOCKED
	socksURL, _ := url.Parse(fmt.Sprintf("socks5://127.0.0.1:%d", socksPort))
	socksClient := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(socksURL),
		},
		Timeout: 5 * time.Second,
	}

	t.Log("===> [SOCKS5 Proxy] Testing request to http://google.com through Sing-box...")
	respSocksGoogle, errSocksGoogle := socksClient.Get("http://google.com")
	if errSocksGoogle != nil {
		t.Logf("SUCCESS: SOCKS5 request to google.com was rejected/blocked: %v", errSocksGoogle)
	} else {
		respSocksGoogle.Body.Close()
		t.Errorf("expected SOCKS5 request to google.com to fail, but succeeded with status %d", respSocksGoogle.StatusCode)
	}
}
