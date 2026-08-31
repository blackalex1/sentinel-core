package ingest

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEventDispatcher_PubSub_And_History(t *testing.T) {
	d := NewEventDispatcher(10)

	sub := d.Subscribe()
	defer d.Unsubscribe(sub)

	ev1 := SecurityEvent{
		EventID:   "ev-1",
		EventType: "THREAT_DETECTED",
		RiskLevel: "CRITICAL",
		SrcIP:     "192.168.1.50",
		DstHost:   "203.0.113.1",
		DstPort:   22,
		Reason:    "Test attack",
	}

	d.Emit(ev1)

	// Verify subscriber received event
	select {
	case received := <-sub:
		if received.EventID != "ev-1" || received.SrcIP != "192.168.1.50" {
			t.Errorf("unexpected event received: %+v", received)
		}
	case <-time.After(1 * time.Second):
		t.Fatalf("timed out waiting for emitted event")
	}

	// Verify PopEventJSON
	jsonStr := d.PopEventJSON(500 * time.Millisecond)
	if jsonStr == "" || !containsSubstring(jsonStr, "192.168.1.50") {
		t.Errorf("expected pop event JSON, got %q", jsonStr)
	}

	// Verify History
	hist := d.GetHistory(5)
	if len(hist) != 1 || hist[0].EventID != "ev-1" {
		t.Errorf("expected 1 history item, got: %+v", hist)
	}
}

func TestSecurityPipeline_ProcessRouterConntrack_FastPath(t *testing.T) {
	p := NewSecurityPipeline(DefaultPipelineConfig())
	d := p.dispatcher
	d.Clear()

	sub := d.Subscribe()
	defer d.Unsubscribe(sub)

	// 1. Benign HTTPS 443 line -> Fast-Path, should NOT emit any threat event
	line443 := "[NEW] tcp 6 120 SYN_SENT src=192.168.1.100 dst=198.51.100.44 sport=50440 dport=443 [UNREPLIED]"
	ev443 := p.ProcessRouterConntrackLine(line443)
	if ev443 != nil {
		t.Errorf("expected nil event for benign 443 traffic, got: %+v", ev443)
	}

	select {
	case ev := <-sub:
		t.Fatalf("unexpected threat event emitted for 443: %+v", ev)
	case <-time.After(50 * time.Millisecond):
		// Expected: nothing emitted
	}

	// 2. Suspicious Telnet 23 line -> Should detect exploit port threat
	line23 := "[NEW] tcp 6 120 SYN_SENT src=192.168.1.100 dst=203.0.113.23 sport=50438 dport=23 [UNREPLIED]"
	ev23 := p.ProcessRouterConntrackLine(line23)
	if ev23 == nil || !containsSubstring(ev23.Reason, "23") {
		t.Errorf("expected threat event for port 23, got: %+v", ev23)
	}

	select {
	case ev := <-sub:
		if ev.DstPort != 23 || ev.SrcIP != "192.168.1.100" {
			t.Errorf("unexpected event received: %+v", ev)
		}
	case <-time.After(1 * time.Second):
		t.Fatalf("expected threat event for port 23 to be emitted")
	}
}

func TestSecurityPipeline_ProcessProxmoxIptables(t *testing.T) {
	p := NewSecurityPipeline(DefaultPipelineConfig())
	d := p.dispatcher
	d.Clear()

	sub := d.Subscribe()
	defer d.Unsubscribe(sub)

	// Attack line: Internet source hitting local Proxmox SSH port 22
	line := "HOST_CONN: IN=eth0 OUT= SRC=203.0.113.100 DST=192.168.1.120 LEN=60 PROTO=TCP SPT=45678 DPT=22"
	ev := p.ProcessProxmoxIptablesLine(line)
	if ev == nil || ev.RiskLevel != "CRITICAL" {
		t.Errorf("expected CRITICAL event for SSH attack, got: %+v", ev)
	}

	select {
	case received := <-sub:
		if received.SrcIP != "203.0.113.100" || received.DstPort != 22 {
			t.Errorf("unexpected event: %+v", received)
		}
	case <-time.After(1 * time.Second):
		t.Fatalf("expected emitted event")
	}
}

func TestLogTailer_FileStreaming(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "test.log")

	_ = os.WriteFile(logFile, []byte("initial line\n"), 0644)

	received := make(chan string, 10)
	tailer := NewFileTailer(logFile, func(line string) {
		received <- line
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := tailer.Start(ctx)
	if err != nil {
		t.Fatalf("failed to start tailer: %v", err)
	}
	defer tailer.Stop()

	// Append a new line
	time.Sleep(100 * time.Millisecond)
	f, err := os.OpenFile(logFile, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatalf("failed to open file for append: %v", err)
	}
	_, _ = f.WriteString("new alert line 1\n")
	f.Close()

	select {
	case line := <-received:
		if line != "new alert line 1" {
			t.Errorf("expected 'new alert line 1', got %q", line)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for tailed line")
	}
}

func containsSubstring(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
