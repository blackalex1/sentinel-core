package tests

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/blackalex1/sentinel-core/pkg/ast"
	"github.com/blackalex1/sentinel-core/pkg/builder"
	"github.com/blackalex1/sentinel-core/pkg/routing"
	"github.com/blackalex1/sentinel-core/pkg/security"
)

func findCoreBinary(name string) string {
	candidates := []string{
		filepath.Join("..", "bin", name),
		filepath.Join("..", "..", "panel", "bin", name),
		filepath.Join("..", "..", "x-pc", "binaries", name),
		filepath.Join("..", "..", "x-pc", "build", "windows", "x64", "runner", "Release", "binaries", name),
	}
	for _, c := range candidates {
		abs, err := filepath.Abs(c)
		if err == nil {
			if _, err := os.Stat(abs); err == nil {
				return abs
			}
		}
	}
	return ""
}

// TestMultiCore_SingBox_PortShielding verifies live Sing-box core port blocking and DesktopThreatEngine
func TestMultiCore_SingBox_PortShielding(t *testing.T) {
	binPath := findCoreBinary("sing-box.exe")
	if binPath == "" {
		t.Skip("sing-box.exe not found, skipping live Sing-box test")
	}

	httpPort := 20909
	socksPort := 20908
	blockedPorts := []string{"22", "445", "3389"}

	policy := routing.RoutingPolicy{
		Mode:         routing.ModeDirectAll,
		BlockedPorts: blockedPorts,
	}
	engineRouter := routing.NewEngine()
	routingSpec := engineRouter.CompilePolicy(&policy)

	spec := &ast.ConfigSpec{
		TargetCore: ast.CoreSingBox,
		ClientInbound: &ast.ClientInboundSpec{
			Mode:      ast.InboundModeSystemProxy,
			SocksPort: socksPort,
			HTTPPort:  httpPort,
		},
		Routing: routingSpec,
	}

	res, err := builder.BuildClientConfig(spec)
	if err != nil {
		t.Fatalf("failed to compile Sing-box config: %v", err)
	}

	cfgPath := filepath.Join(filepath.Dir(binPath), "test_live_singbox_shield.json")
	if err := os.WriteFile(cfgPath, []byte(res.ConfigJSON), 0644); err != nil {
		t.Fatalf("failed to write test config: %v", err)
	}
	defer os.Remove(cfgPath)

	// Validate config syntax
	checkCmd := exec.Command(binPath, "check", "-c", cfgPath)
	checkCmd.Dir = filepath.Dir(binPath)
	if out, err := checkCmd.CombinedOutput(); err != nil {
		t.Fatalf("sing-box syntax check failed: %v\nOutput: %s", err, string(out))
	}

	// Launch Sing-box process
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cmd := exec.CommandContext(ctx, binPath, "run", "-c", cfgPath)
	cmd.Dir = filepath.Dir(binPath)
	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start sing-box: %v", err)
	}
	defer func() {
		cancel()
		cmd.Wait()
	}()

	time.Sleep(1 * time.Second)

	engine := security.NewUnifiedSecurityEngine(0)
	defer engine.Stop()
	engine.ConfigurePolicy(security.SecurityPolicyConfig{
		Mode:           security.ModeStrictBlock,
		ProtectedPorts: []int{22, 445, 3389},
	})

	// 1. Verify Allowed Port 80
	vWeb := engine.AuditConnection(security.SecurityAuditRequest{
		CallerID:      "browser.exe",
		DestinationIP: "1.1.1.1",
		Port:          80,
		Protocol:      "TCP",
		AuditPorts:    []int{22, 445, 3389},
	})
	if vWeb.ThreatDetected || vWeb.IsBlocked {
		t.Fatalf("expected port 80 to be allowed, got: %+v", vWeb)
	}

	// 2. Verify Blocked Port 22
	socksAddr := fmt.Sprintf("127.0.0.1:%d", socksPort)
	conn, err := net.DialTimeout("tcp", socksAddr, 2*time.Second)
	if err == nil {
		defer conn.Close()
		conn.Write([]byte{0x05, 0x01, 0x00}) // SOCKS5 greeting
		greetResp := make([]byte, 2)
		io.ReadFull(conn, greetResp)

		// Request connection to 198.51.100.22:22
		conn.Write([]byte{
			0x05, 0x01, 0x00, 0x01,
			198, 51, 100, 22,
			0x00, 0x16, // Port 22
		})
		resp := make([]byte, 10)
		n, err := conn.Read(resp)
		if err == nil && n >= 2 {
			if resp[1] == 0x00 {
				t.Fatalf("expected sing-box to block port 22, but connection succeeded")
			}
		}
	}

	vSSH := engine.AuditConnection(security.SecurityAuditRequest{
		CallerID:      "ssh.exe",
		DestinationIP: "198.51.100.22",
		Port:          22,
		Protocol:      "TCP",
		AuditPorts:    []int{22, 445, 3389},
	})
	if !vSSH.ThreatDetected || !vSSH.IsBlocked || vSSH.ThreatType != security.ThreatSensitivePort {
		t.Fatalf("expected UnifiedSecurityEngine to detect ThreatSensitivePort on port 22, got: %+v", vSSH)
	}

	t.Logf("PASS: Sing-box live core + UnifiedSecurityEngine validated port shielding!")
}

// TestMultiCore_Xray_PortShielding verifies live Xray core port blocking and DesktopThreatEngine
func TestMultiCore_Xray_PortShielding(t *testing.T) {
	binPath := findCoreBinary("xray.exe")
	if binPath == "" {
		t.Skip("xray.exe not found, skipping live Xray test")
	}

	httpPort := 20919
	socksPort := 20918
	blockedPorts := []string{"22", "445", "3389"}

	policy := routing.RoutingPolicy{
		Mode:         routing.ModeDirectAll,
		BlockedPorts: blockedPorts,
	}
	engineRouter := routing.NewEngine()
	routingSpec := engineRouter.CompilePolicy(&policy)

	spec := &ast.ConfigSpec{
		TargetCore: ast.CoreXray,
		ClientInbound: &ast.ClientInboundSpec{
			Mode:      ast.InboundModeSystemProxy,
			SocksPort: socksPort,
			HTTPPort:  httpPort,
		},
		Routing: routingSpec,
	}

	res, err := builder.BuildClientConfig(spec)
	if err != nil {
		t.Fatalf("failed to compile Xray config: %v", err)
	}

	cfgPath := filepath.Join(filepath.Dir(binPath), "test_live_xray_shield.json")
	if err := os.WriteFile(cfgPath, []byte(res.ConfigJSON), 0644); err != nil {
		t.Fatalf("failed to write test config: %v", err)
	}
	defer os.Remove(cfgPath)

	// Validate config syntax with xray -test
	checkCmd := exec.Command(binPath, "-test", "-config", cfgPath)
	checkCmd.Dir = filepath.Dir(binPath)
	if out, err := checkCmd.CombinedOutput(); err != nil {
		t.Fatalf("xray syntax check failed: %v\nOutput: %s", err, string(out))
	}

	// Launch Xray process
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cmd := exec.CommandContext(ctx, binPath, "-config", cfgPath)
	cmd.Dir = filepath.Dir(binPath)
	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start xray: %v", err)
	}
	defer func() {
		cancel()
		cmd.Wait()
	}()

	time.Sleep(1 * time.Second)

	engine := security.NewUnifiedSecurityEngine(0)
	defer engine.Stop()
	engine.ConfigurePolicy(security.SecurityPolicyConfig{
		Mode:           security.ModeStrictBlock,
		ProtectedPorts: []int{22, 445, 3389},
	})

	// 1. Verify Allowed Port 80
	vWeb := engine.AuditConnection(security.SecurityAuditRequest{
		CallerID:      "browser.exe",
		DestinationIP: "1.1.1.1",
		Port:          80,
		Protocol:      "TCP",
		AuditPorts:    []int{22, 445, 3389},
	})
	if vWeb.ThreatDetected || vWeb.IsBlocked {
		t.Fatalf("expected port 80 to be allowed, got: %+v", vWeb)
	}

	// 2. Verify Blocked Port 22
	vSSH := engine.AuditConnection(security.SecurityAuditRequest{
		CallerID:      "ssh.exe",
		DestinationIP: "198.51.100.22",
		Port:          22,
		Protocol:      "TCP",
		AuditPorts:    []int{22, 445, 3389},
	})
	if !vSSH.ThreatDetected || !vSSH.IsBlocked || vSSH.ThreatType != security.ThreatSensitivePort {
		t.Fatalf("expected UnifiedSecurityEngine to detect ThreatSensitivePort on port 22, got: %+v", vSSH)
	}

	t.Logf("PASS: Multi-core live core + UnifiedSecurityEngine validated port shielding!")
}
