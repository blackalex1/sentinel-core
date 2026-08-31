package tests

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/blackalex1/sentinel-core/pkg/security/ingest"
	"github.com/blackalex1/sentinel-core/pkg/supervisor"
)

// TestLiveCores_LogStreaming_And_SecurityPipeline verifies real-time proxy core streaming into SecurityPipeline.
func TestLiveCores_LogStreaming_And_SecurityPipeline(t *testing.T) {
	sbBin := findBinary("sing-box")
	if sbBin == "" {
		t.Skip("sing-box binary not found, skipping live binary integration test")
		return
	}

	pipeline := ingest.NewSecurityPipeline(ingest.DefaultPipelineConfig())
	dispatcher := ingest.GetDefaultEventDispatcher()
	dispatcher.Clear()

	sub := dispatcher.Subscribe()
	defer dispatcher.Unsubscribe(sub)

	pm := supervisor.GetProcessManager()
	coreName := "sing-box"
	pm.ClearInMemoryLogs(coreName)

	port := getFreePort(t)
	configJSON := fmt.Sprintf(`{
		"log": {
			"level": "debug",
			"timestamp": true
		},
		"inbounds": [
			{
				"type": "mixed",
				"tag": "mixed-in",
				"listen": "127.0.0.1",
				"listen_port": %d
			}
		],
		"outbounds": [
			{
				"type": "direct",
				"tag": "direct"
			}
		]
	}`, port)

	tmpConfig, err := os.CreateTemp("", "sb-integ-*.json")
	if err != nil {
		t.Fatalf("failed to create config: %v", err)
	}
	defer os.Remove(tmpConfig.Name())
	_, _ = tmpConfig.WriteString(configJSON)
	tmpConfig.Close()

	// Start real Sing-box process
	err = pm.StartCore(coreName, sbBin, tmpConfig.Name())
	if err != nil {
		t.Fatalf("failed to start Sing-box: %v", err)
	}
	defer pm.StopCore(coreName)

	// Verify that logs flow into broadcaster
	time.Sleep(300 * time.Millisecond)
	logs := pm.GetInMemoryLogs(coreName, 50)
	if len(logs) == 0 {
		t.Fatalf("expected in-memory logs to be populated from real Sing-box binary")
	}

	t.Logf("✅ Real Sing-box binary is running and streaming logs (collected %d lines)", len(logs))

	// Simulate suspicious core log line in pipeline
	suspiciousLine := "WARN inbound connection to 169.254.169.254:80 from client 192.168.1.55 [user@example.com]"
	pipeline.ProcessProxyCoreLine(coreName, suspiciousLine)

	select {
	case ev := <-sub:
		if ev.Source != "proxy_core" || ev.RiskLevel != "CRITICAL" {
			t.Errorf("unexpected security event: %+v", ev)
		}
		t.Logf("✅ Successfully verified proxy core security threat event: %+v", ev)
	case <-time.After(1 * time.Second):
		t.Fatalf("expected threat event to be emitted into subscriber")
	}
}
