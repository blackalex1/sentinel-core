package detector

import (
	"testing"
	"time"

	"github.com/blackalex1/sentinel-core/pkg/security/filter"
)

func TestClientRiskTracker_Compromise(t *testing.T) {
	cfg := DefaultRiskScorerConfig()
	cfg.CompromiseThreshold = 100
	cfg.SuspiciousThreshold = 40
	cfg.QuarantineDuration = 1 * time.Minute

	tracker := NewClientRiskTracker(cfg, nil)
	defer tracker.Stop()

	compromisedCount := 0
	tracker.OnCompromised(func(client *ClientRiskProfile, incident ThreatIncident) {
		compromisedCount++
	})

	client := "bad_actor@victim.com"

	// 1. Initial violation (+35) -> Clean
	p := tracker.RecordIncident(client, "SENSITIVE_PORT_PROBE", "192.168.1.1:22", "SSH probe", 35)
	if p.Status != StatusClean || p.RiskScore != 35 {
		t.Fatalf("expected score 35, clean status, got: %v (%d)", p.Status, p.RiskScore)
	}

	// 2. Second violation (+35 = 70) -> Suspicious
	p = tracker.RecordIncident(client, "SENSITIVE_PORT_PROBE", "192.168.1.1:3389", "RDP probe", 35)
	if p.Status != StatusSuspicious || p.RiskScore != 70 {
		t.Fatalf("expected score 70, suspicious status, got: %v (%d)", p.Status, p.RiskScore)
	}

	// 3. Third violation (+50 = 120) -> Compromised!
	p = tracker.RecordIncident(client, "MALWARE_C2", "c2-panel.su", "C2 contact", 50)
	if p.Status != StatusCompromised || p.RiskScore != 120 {
		t.Fatalf("expected score 120, compromised status, got: %v (%d)", p.Status, p.RiskScore)
	}

	if compromisedCount != 1 {
		t.Fatalf("expected 1 compromise callback, got %d", compromisedCount)
	}

	if !tracker.IsCompromisedOrQuarantined(client) {
		t.Fatalf("expected client to be quarantined")
	}
}

func TestLogAuditor_MultiCore(t *testing.T) {
	cfg := DefaultRiskScorerConfig()
	tracker := NewClientRiskTracker(cfg, nil)
	defer tracker.Stop()

	registry := NewClientRegistry()
	// Link email to Xray/Singbox UUID and Hysteria user
	registry.RegisterClient("user@example.com", "b9f3857a-ce20-4e1e-b5e0-6f3d141fa2b2", "alice_hy2", "203.0.113.10")

	auditor := NewLogAuditor(tracker, registry, []int{22, 3389, 8006})

	// 1. Sing-box log line: matches via user email
	logSingbox := "2026/08/16 01:00:00 [INFO] inbound/vless[vless-in]: inbound connection to 192.168.1.1:22 from user user@example.com (203.0.113.10:5678)"
	auditor.AuditLogLine("sing-box", logSingbox)

	p, exists := tracker.GetProfile("user@example.com")
	if !exists || p.RiskScore != 35 {
		t.Fatalf("expected user@example.com to have 35 risk points, got %v", p)
	}

	// 2. Xray log line: matches via email field
	logXray := "[Info] [123456] proxy/vless/inbound: from tcp:203.0.113.10:5678 accepted tcp:192.168.1.1:3389 [vless-in -> direct] email: user@example.com"
	auditor.AuditLogLine("xray", logXray)

	p, _ = tracker.GetProfile("user@example.com")
	if p.RiskScore != 70 {
		t.Fatalf("expected risk score 70 after Xray RDP probe, got %d", p.RiskScore)
	}

	// 3. Hysteria 2 log line: matches via alias "alice_hy2" -> resolves to user@example.com!
	logHysteria := "[TCP] 203.0.113.10:5678 -> 192.168.1.1:8006 (user: alice_hy2)"
	auditor.AuditLogLine("hysteria2", logHysteria)

	p, _ = tracker.GetProfile("user@example.com")
	if p.RiskScore != 105 || p.Status != StatusCompromised {
		t.Fatalf("expected user@example.com to be COMPROMISED (105 points) via Hysteria alias, got score=%d status=%v", p.RiskScore, p.Status)
	}
}

func TestConnectionAuditor(t *testing.T) {
	cfg := DefaultRiskScorerConfig()
	tracker := NewClientRiskTracker(cfg, nil)
	defer tracker.Stop()

	registry := NewClientRegistry()
	thr := filter.NewThreatEngine(true, true, true, true, false, nil, nil, nil)
	ca := NewConnectionAuditor(tracker, registry, thr, []int{22, 3389, 8006}, 10)

	conns := []ActiveConnection{
		{ID: "c1", User: "victim_bot@compromised.net", DestHost: "192.168.1.1", DestPort: 22},
		{ID: "c2", User: "victim_bot@compromised.net", DestHost: "192.168.1.1", DestPort: 3389},
		{ID: "c3", User: "victim_bot@compromised.net", DestHost: "192.168.1.1", DestPort: 8006},
		{ID: "c4", User: "victim_bot@compromised.net", DestHost: "c2-panel.su", DestPort: 443},
	}

	report := ca.AuditConnections(conns)
	if report.ViolationsFound == 0 {
		t.Fatalf("expected multiple violations in audit report")
	}

	if len(report.CompromisedClients) == 0 {
		t.Fatalf("expected victim_bot@compromised.net to be flagged as compromised")
	}
}

func TestSingboxParser_ProcessRecognition(t *testing.T) {
	parser := NewSingboxParser()

	tests := []struct {
		name         string
		logLine      string
		expectedID   string
		expectedHost string
		expectedPort int
	}{
		{
			name:         "Windows process with simple name",
			logLine:      "INFO [12345678] inbound/tun[tun-in]: inbound connection to 198.51.100.22:22 from process powershell.exe",
			expectedID:   "powershell.exe",
			expectedHost: "198.51.100.22",
			expectedPort: 22,
		},
		{
			name:         "Windows process with full absolute path",
			logLine:      `INFO [12345678] inbound/tun[tun-in]: inbound connection to 198.51.100.22:22 from process C:\Windows\System32\OpenSSH\ssh.exe`,
			expectedID:   "ssh.exe",
			expectedHost: "198.51.100.22",
			expectedPort: 22,
		},
		{
			name:         "Process with by process syntax",
			logLine:      "INFO router: match[0] action=block for 198.51.100.22:3389 by process putty.exe",
			expectedID:   "putty.exe",
			expectedHost: "198.51.100.22",
			expectedPort: 3389,
		},
		{
			name:         "Android package user",
			logLine:      "INFO inbound connection to 198.51.100.22:445 from user com.termux",
			expectedID:   "com.termux",
			expectedHost: "198.51.100.22",
			expectedPort: 445,
		},
		{
			name:         "IP client fallback when no process is present",
			logLine:      "INFO inbound connection to 198.51.100.22:80 from 192.168.1.50:52341",
			expectedID:   "192.168.1.50",
			expectedHost: "198.51.100.22",
			expectedPort: 80,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ev, ok := parser.ParseLogLine(tc.logLine)
			if !ok {
				t.Fatalf("failed to parse log line: %s", tc.logLine)
			}
			if ev.ClientRawID != tc.expectedID {
				t.Errorf("expected ClientRawID '%s', got '%s'", tc.expectedID, ev.ClientRawID)
			}
			if ev.TargetHost != tc.expectedHost {
				t.Errorf("expected TargetHost '%s', got '%s'", tc.expectedHost, ev.TargetHost)
			}
			if ev.TargetPort != tc.expectedPort {
				t.Errorf("expected TargetPort %d, got %d", tc.expectedPort, ev.TargetPort)
			}
		})
	}
}

func TestXrayParser_ProcessRecognition(t *testing.T) {
	parser := NewXrayParser()

	tests := []struct {
		name         string
		logLine      string
		expectedID   string
		expectedHost string
		expectedPort int
	}{
		{
			name:         "Xray inbound with email tag",
			logLine:      "[Info] [12345678] proxy/vless/inbound: from tcp:203.0.113.10:5678 accepted tcp:198.51.100.22:3389 [vless-in -> direct] email: user@example.com",
			expectedID:   "user@example.com",
			expectedHost: "198.51.100.22",
			expectedPort: 3389,
		},
		{
			name:         "Xray SOCKS inbound with process name",
			logLine:      "2026/08/22 21:00:00 [Info] [12345678] proxy/socks: from tcp:127.0.0.1:52341 accepted tcp:198.51.100.22:22 (process: powershell.exe)",
			expectedID:   "powershell.exe",
			expectedHost: "198.51.100.22",
			expectedPort: 22,
		},
		{
			name:         "Xray SOCKS inbound with full Windows path",
			logLine:      `2026/08/22 21:00:00 [Info] [12345678] proxy/socks: from tcp:127.0.0.1:52341 accepted tcp:198.51.100.22:22 from process C:\Windows\System32\OpenSSH\ssh.exe`,
			expectedID:   "ssh.exe",
			expectedHost: "198.51.100.22",
			expectedPort: 22,
		},
		{
			name:         "Xray generic connection without email (falls back to IP)",
			logLine:      "2026/08/22 21:00:00 [Info] [12345678] proxy/socks: from tcp:192.168.1.100:52341 accepted tcp:198.51.100.22:80 [socks-in -> proxy]",
			expectedID:   "192.168.1.100",
			expectedHost: "198.51.100.22",
			expectedPort: 80,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ev, ok := parser.ParseLogLine(tc.logLine)
			if !ok {
				t.Fatalf("failed to parse log line: %s", tc.logLine)
			}
			if ev.ClientRawID != tc.expectedID {
				t.Errorf("expected ClientRawID '%s', got '%s'", tc.expectedID, ev.ClientRawID)
			}
			if ev.TargetHost != tc.expectedHost {
				t.Errorf("expected TargetHost '%s', got '%s'", tc.expectedHost, ev.TargetHost)
			}
			if ev.TargetPort != tc.expectedPort {
				t.Errorf("expected TargetPort %d, got %d", tc.expectedPort, ev.TargetPort)
			}
		})
	}
}
