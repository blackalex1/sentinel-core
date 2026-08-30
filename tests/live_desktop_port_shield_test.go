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

func TestSingBoxLive_DesktopSensitivePortShielding(t *testing.T) {
	singboxBin := findCoreBinary("sing-box.exe")
	if singboxBin == "" {
		t.Skip("sing-box.exe not found, skipping live check")
	}

	httpPort := 20829
	socksPort := 20828

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
		t.Fatalf("failed to compile Sing-box config via sentinel_core: %v", err)
	}

	configFile, err := filepath.Abs("../bin/test_desktop_port_shield.json")
	if err != nil {
		t.Fatalf("failed to resolve config path: %v", err)
	}
	_ = os.MkdirAll(filepath.Dir(configFile), 0755)
	if err := os.WriteFile(configFile, []byte(res.ConfigJSON), 0644); err != nil {
		t.Fatalf("failed to write test config: %v", err)
	}
	defer os.Remove(configFile)

	// Validate config syntax with real sing-box check
	checkCmd := exec.Command(singboxBin, "check", "-c", configFile)
	checkCmd.Dir = filepath.Dir(singboxBin)
	if out, err := checkCmd.CombinedOutput(); err != nil {
		t.Fatalf("sing-box check failed: %v\nOutput: %s\nJSON:\n%s", err, string(out), res.ConfigJSON)
	}

	// Start real sing-box.exe in background
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cmd := exec.CommandContext(ctx, singboxBin, "run", "-c", configFile)
	cmd.Dir = filepath.Dir(singboxBin)

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

	// 1. Verify Allowed Standard Traffic (Port 80)
	vWeb := engine.AuditConnection(security.SecurityAuditRequest{
		CallerID:      "curl.exe",
		DestinationIP: "1.1.1.1",
		Port:          80,
		Protocol:      "TCP",
		AuditPorts:    []int{22, 445, 3389},
	})
	if vWeb.ThreatDetected || vWeb.IsBlocked {
		t.Fatalf("expected port 80 web traffic to be allowed, got: %+v", vWeb)
	}

	// 2. Verify Blocked Sensitive Traffic (Port 22 SSH)
	socksAddr := fmt.Sprintf("127.0.0.1:%d", socksPort)
	socksConn, err := net.DialTimeout("tcp", socksAddr, 2*time.Second)
	if err == nil {
		defer socksConn.Close()
		socksConn.Write([]byte{0x05, 0x01, 0x00})
		authResp := make([]byte, 2)
		io.ReadFull(socksConn, authResp)

		targetReq := []byte{
			0x05, 0x01, 0x00, 0x01,
			198, 51, 100, 22,
			0x00, 0x16, // Port 22
		}
		socksConn.Write(targetReq)
		resp := make([]byte, 10)
		n, err := socksConn.Read(resp)

		if err == nil && n >= 2 {
			repCode := resp[1]
			if repCode == 0x00 {
				t.Fatalf("expected port 22 connection to be BLOCKED by sing-box, but got success (0x00)")
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
		t.Fatalf("expected port 22 SSH probe to be detected as ThreatSensitivePort, got: %+v", vSSH)
	}
}
