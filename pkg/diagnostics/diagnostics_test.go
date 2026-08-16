package diagnostics

import (
	"net"
	"strings"
	"testing"
	"time"
)

func TestPingHostPort(t *testing.T) {
	// Empty address
	resEmpty := PingHostPort("", 80, 100*time.Millisecond)
	if resEmpty.Success || !strings.Contains(resEmpty.Error, "empty") {
		t.Errorf("expected error for empty address, got: %+v", resEmpty)
	}

	// Default port <= 0 (defaults to 443)
	resDefPort := PingHostPort("127.0.0.1", -1, 50*time.Millisecond)
	// We only verify it ran without panic
	_ = resDefPort

	// Start a dummy local listener
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start local test listener: %v", err)
	}
	defer listener.Close()

	addr := listener.Addr().(*net.TCPAddr)
	res := PingHostPort("127.0.0.1", addr.Port, 1*time.Second)
	if !res.Success {
		t.Fatalf("expected ping to succeed on local listener, got error: %s", res.Error)
	}
	if res.LatencyMs < 0 {
		t.Fatalf("unexpected negative latency: %f", res.LatencyMs)
	}

	// Ping closed port
	resFail := PingHostPort("127.0.0.1", 59996, 50*time.Millisecond)
	if resFail.Success {
		t.Fatalf("expected ping to fail on unused port")
	}
}

func TestPortChecker_Availability(t *testing.T) {
	// Invalid ports
	if IsPortAvailable(0) {
		t.Errorf("expected port 0 to be unavailable")
	}
	if IsPortAvailable(-10) {
		t.Errorf("expected negative port to be unavailable")
	}
	if IsPortAvailable(70000) {
		t.Errorf("expected port > 65535 to be unavailable")
	}

	// Occupied port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer listener.Close()

	port := listener.Addr().(*net.TCPAddr).Port
	if IsPortAvailable(port) {
		t.Errorf("expected occupied port %d to not be available", port)
	}

	// CheckPorts
	results := CheckPorts([]int{port, 59995})
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	if results[0].IsFree || results[0].Error == "" {
		t.Errorf("expected port %d to be marked occupied with error", port)
	}
}

func TestCheckRemoteReachable(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer listener.Close()

	port := listener.Addr().(*net.TCPAddr).Port

	// Reachable
	ok, lat, err := CheckRemoteReachable("127.0.0.1", port, 1*time.Second)
	if !ok || err != nil || lat < 0 {
		t.Errorf("expected reachable listener, got ok=%v, lat=%v, err=%v", ok, lat, err)
	}

	// Unreachable
	ok, _, err = CheckRemoteReachable("127.0.0.1", 59994, 50*time.Millisecond)
	if ok || err == nil {
		t.Errorf("expected unreachable result for closed port")
	}
}

func TestRunHealthCheck(t *testing.T) {
	// 1. All pass with default DNS and empty secret
	report := RunHealthCheck(59992, 59993, "localhost", "")
	if !report.DNSResolving {
		t.Errorf("expected localhost DNS to resolve")
	}
	if !report.CryptoVaultOK {
		t.Errorf("expected empty secret to mark CryptoVaultOK=true")
	}

	// 2. Health check with valid master secret
	reportSecret := RunHealthCheck(59990, 59991, "localhost", "myMasterSecret123!")
	if !reportSecret.CryptoVaultOK {
		t.Errorf("expected valid secret to have CryptoVaultOK=true")
	}

	// 3. Occupied port failure
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer listener.Close()
	occupiedPort := listener.Addr().(*net.TCPAddr).Port

	reportOccupied := RunHealthCheck(occupiedPort, 59989, "localhost", "secret")
	if reportOccupied.Passed {
		t.Errorf("expected health check to fail when port is occupied")
	}
	if len(reportOccupied.Issues) == 0 {
		t.Errorf("expected issues list to be populated")
	}

	// 4. DNS failure
	reportDNSFail := RunHealthCheck(59987, 59988, "non-existent-domain-xyz-123456789.test", "secret")
	if reportDNSFail.DNSResolving || reportDNSFail.Passed {
		t.Errorf("expected health check to fail for non-existent domain")
	}
}
