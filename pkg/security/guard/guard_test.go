package guard

import (
	"os"
	"testing"
)

func TestProcessWhitelist(t *testing.T) {
	wl := NewProcessWhitelist([]string{"my_custom_daemon"}, []string{"192.168.1.50"})

	// Self PID protection
	if !wl.IsProcessProtected("random_proc", os.Getpid()) {
		t.Fatalf("expected own PID to be protected")
	}

	// Critical core process names
	if !wl.IsProcessProtected("sentinel-core", 9999) {
		t.Fatalf("expected sentinel-core to be protected")
	}
	if !wl.IsProcessProtected("sing-box", 9999) {
		t.Fatalf("expected sing-box to be protected")
	}
	if !wl.IsProcessProtected("hysteria.exe", 9999) {
		t.Fatalf("expected hysteria.exe to be protected")
	}
	if !wl.IsProcessProtected("/usr/local/bin/xray", 9999) {
		t.Fatalf("expected wrapped xray path to be protected")
	}
	if !wl.IsProcessProtected("my_custom_daemon", 9999) {
		t.Fatalf("expected custom daemon to be protected")
	}

	// Unprotected malware
	if wl.IsProcessProtected("xmrig", 9999) {
		t.Fatalf("expected xmrig to be unprotected")
	}

	// IP checks
	if !wl.IsIPProtected("127.0.0.1") {
		t.Fatalf("expected 127.0.0.1 to be protected")
	}
	if !wl.IsIPProtected("192.168.1.50") {
		t.Fatalf("expected custom IP to be protected")
	}
	if wl.IsIPProtected("198.51.100.1") {
		t.Fatalf("expected external IP to NOT be protected")
	}
}

func TestRateLimiter(t *testing.T) {
	wl := NewProcessWhitelist(nil, nil)
	// RPS = 2, Burst = 3, banThreshold = 3
	rl := NewRateLimiter(true, 2.0, 3, 3, 1, wl)
	defer rl.Stop()

	client := "203.0.113.10"

	// Initial burst of 3 should be allowed
	if !rl.Allow(client) || !rl.Allow(client) || !rl.Allow(client) {
		t.Fatalf("expected first 3 requests to be allowed under burst")
	}

	// 4th immediate request should be denied
	if rl.Allow(client) {
		t.Fatalf("expected 4th immediate request to exceed rate limit")
	}

	// Whitelisted IP should never be rate limited
	wlIP := "127.0.0.1"
	for i := 0; i < 20; i++ {
		if !rl.Allow(wlIP) {
			t.Fatalf("expected whitelisted IP to never be blocked")
		}
	}
}

func TestSensitivePortScanDetection(t *testing.T) {
	wl := NewProcessWhitelist(nil, nil)
	ports := []int{22, 3389, 8006, 5432, 3306}
	monitor := NewSensitivePortMonitor(true, ports, "block", 3, 5, true, wl)

	attacker := "198.51.100.5"

	// 1. Probe 1 (Port 22) -> Blocked (single port violation)
	blocked, isScan, _ := monitor.CheckPortAccess(attacker, 22)
	if !blocked || isScan {
		t.Fatalf("expected probe 1 to be blocked but not yet flagged as full scan")
	}

	// 2. Probe 2 (Port 3389)
	blocked, isScan, _ = monitor.CheckPortAccess(attacker, 3389)
	if !blocked || isScan {
		t.Fatalf("expected probe 2 to be blocked")
	}

	// 3. Probe 3 (Port 8006) -> Threshold of 3 reached, flagged as port scan and auto-banned
	blocked, isScan, reason := monitor.CheckPortAccess(attacker, 8006)
	if !blocked || !isScan {
		t.Fatalf("expected probe 3 to trigger port scan detection, got isScan=%v", isScan)
	}
	if reason == "" {
		t.Fatalf("expected descriptive scan reason")
	}

	// Normal benign port should now also be blocked due to auto-ban
	blocked, _, _ = monitor.CheckPortAccess(attacker, 80)
	if !blocked {
		t.Fatalf("expected attacker to be banned from all access")
	}
}

func TestGuardCoordination(t *testing.T) {
	g := New(
		true,
		[]int{22, 3389},
		"block",
		3,
		5,
		true,
		10.0,
		10,
		5,
		300,
		nil,
		nil,
	)
	defer g.Stop()

	// Safe traffic
	allowed, _ := g.CheckInbound("192.168.1.100", 8080)
	if !allowed {
		t.Fatalf("expected normal port 8080 traffic to be allowed")
	}

	// Sensitive port traffic
	allowed, reason := g.CheckInbound("192.168.1.100", 22)
	if allowed {
		t.Fatalf("expected SSH port 22 access to be denied")
	}
	if reason == "" {
		t.Fatalf("expected reason for blocking sensitive port")
	}
}
