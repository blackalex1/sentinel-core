package diagnostics

import (
	"net"
	"testing"
	"time"
)

func TestBatchPing(t *testing.T) {
	// Start mock TCP listener
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start mock listener: %v", err)
	}
	defer ln.Close()

	port := ln.Addr().(*net.TCPAddr).Port

	targets := []PingTarget{
		{ID: "mock-1", Address: "127.0.0.1", Port: port},
		{ID: "mock-2", Address: "127.0.0.1", Port: port},
		{ID: "mock-fail", Address: "127.0.0.1", Port: 1}, // unreachable
	}

	results := BatchPing(targets, 1*time.Second, 4)
	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}

	if !results[0].Success || results[0].LatencyMs < 0 {
		t.Errorf("expected target 0 to succeed, got %+v", results[0])
	}
	if !results[1].Success || results[1].LatencyMs < 0 {
		t.Errorf("expected target 1 to succeed, got %+v", results[1])
	}
	if results[2].Success {
		t.Errorf("expected unreachable target to fail, got %+v", results[2])
	}
}

func TestPingThroughProxyInvalidPort(t *testing.T) {
	res := PingThroughProxy(-1, "http://example.com", 500*time.Millisecond)
	if res.Success {
		t.Errorf("expected failure on invalid port, got success")
	}
}
