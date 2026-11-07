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
		{
			name:         "Sing-box server inbound with username tag and cached from IP",
			logLine:      "+0000 2026-08-31 11:33:20 INFO [3342564101 42ms] inbound/vless[inbound-8]: [test_client] inbound connection to api4.my-ip.io:443",
			expectedID:   "test_client",
			expectedHost: "api4.my-ip.io",
			expectedPort: 443,
		},
	}

	// Pre-feed the "from" line for connID 3342564101 so parser has cached source IP
	fromLine := "+0000 2026-08-31 11:33:20 INFO [3342564101 0ms]  inbound/vless[inbound-8]: inbound connection from 192.168.1.1:46980"
	evFrom, okFrom := parser.ParseLogLine(fromLine)
	if okFrom || evFrom != nil {
		t.Errorf("expected from-line to return (nil, false), got (%v, %v)", evFrom, okFrom)
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
			if tc.name == "Sing-box server inbound with username tag and cached from IP" {
				if ev.ClientIP != "192.168.1.1" {
					t.Errorf("expected ClientIP '192.168.1.1', got '%s'", ev.ClientIP)
				}
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

func TestClientRiskTracker_IncidentListBounded(t *testing.T) {
	cfg := DefaultRiskScorerConfig()
	tracker := NewClientRiskTracker(cfg, nil)
	defer tracker.Stop()

	client := "flooder@test.local"
	for i := 0; i < 150; i++ {
		tracker.RecordIncident(client, "PROBE", "1.2.3.4:80", "scan", 1)
	}

	p, exists := tracker.GetProfile(client)
	if !exists {
		t.Fatalf("expected profile to exist")
	}
	if len(p.Incidents) != 100 {
		t.Fatalf("expected incidents list to be capped at 100, got %d", len(p.Incidents))
	}
}

func TestIPv6_LogDetection_AllCores(t *testing.T) {
	// 1. Xray Parser with IPv6 client and IPv6 target (RFC 3849)
	xrayParser := NewXrayParser()
	xrayLog := "2026/11/08 00:00:00 [Info] [4102910] proxy/vless/inbound: from tcp:[2001:db8:cafe::42]:54321 accepted tcp:[2001:db8:1000::1]:443 [vless-in -> direct] email: alice_v6@example.com"
	evXray, ok := xrayParser.ParseLogLine(xrayLog)
	if !ok || evXray == nil {
		t.Fatalf("failed to parse IPv6 Xray log line")
	}
	if evXray.ClientRawID != "alice_v6@example.com" {
		t.Errorf("expected ClientRawID 'alice_v6@example.com', got '%s'", evXray.ClientRawID)
	}
	if evXray.ClientIP != "2001:db8:cafe::42" {
		t.Errorf("expected ClientIP '2001:db8:cafe::42', got '%s'", evXray.ClientIP)
	}
	if evXray.TargetHost != "2001:db8:1000::1" {
		t.Errorf("expected TargetHost '2001:db8:1000::1', got '%s'", evXray.TargetHost)
	}
	if evXray.TargetPort != 443 {
		t.Errorf("expected TargetPort 443, got %d", evXray.TargetPort)
	}

	// Xray reject with IPv6 target
	xrayReject := "2026/11/08 00:00:00 [Warning] [4102911] app/dispatcher: default: block connection to tcp:[2001:db8:1000::1]:22"
	evXrayReject, ok := xrayParser.ParseLogLine(xrayReject)
	if !ok || evXrayReject == nil {
		t.Fatalf("failed to parse IPv6 Xray reject log line")
	}
	if evXrayReject.TargetHost != "2001:db8:1000::1" {
		t.Errorf("expected TargetHost '2001:db8:1000::1', got '%s'", evXrayReject.TargetHost)
	}
	if evXrayReject.TargetPort != 22 {
		t.Errorf("expected TargetPort 22, got %d", evXrayReject.TargetPort)
	}

	// 2. Sing-box Parser with 2-stage IPv6 correlation
	sbParser := NewSingboxParser()
	sbStage1 := "[12345678 0ms] vless-in: inbound connection from [2001:db8:cafe::42]:54321"
	ev1, ok1 := sbParser.ParseLogLine(sbStage1)
	if ok1 || ev1 != nil {
		t.Errorf("Stage 1 'from' line should not yield security event directly")
	}

	sbStage2 := "[12345678 5ms] [user_sb_v6@example.com] inbound connection to [2001:db8:1000::1]:443"
	ev2, ok2 := sbParser.ParseLogLine(sbStage2)
	if !ok2 || ev2 == nil {
		t.Fatalf("failed to parse Stage 2 IPv6 Sing-box log line")
	}
	if ev2.ClientRawID != "user_sb_v6@example.com" {
		t.Errorf("expected ClientRawID 'user_sb_v6@example.com', got '%s'", ev2.ClientRawID)
	}
	if ev2.ClientIP != "2001:db8:cafe::42" {
		t.Errorf("expected ClientIP '2001:db8:cafe::42' correlated from cache, got '%s'", ev2.ClientIP)
	}
	if ev2.TargetHost != "2001:db8:1000::1" {
		t.Errorf("expected TargetHost '2001:db8:1000::1', got '%s'", ev2.TargetHost)
	}
	if ev2.TargetPort != 443 {
		t.Errorf("expected TargetPort 443, got %d", ev2.TargetPort)
	}

	// Sing-box reject with IPv6 target
	sbReject := "router: match[0] to [2001:db8:1000::1]:22 rejected"
	evSbReject, ok := sbParser.ParseLogLine(sbReject)
	if !ok || evSbReject == nil {
		t.Fatalf("failed to parse IPv6 Sing-box reject log line")
	}
	if evSbReject.TargetHost != "2001:db8:1000::1" {
		t.Errorf("expected TargetHost '2001:db8:1000::1', got '%s'", evSbReject.TargetHost)
	}
	if evSbReject.TargetPort != 22 {
		t.Errorf("expected TargetPort 22, got %d", evSbReject.TargetPort)
	}

	// 3. Hysteria 2 Parser with IPv6 client and target
	hyParser := NewHysteriaParser()
	hyTextLog := "[TCP] [2001:db8:cafe::42]:54321 -> [2001:db8:1000::1]:22 (user: alice_hy_v6)"
	evHy, ok := hyParser.ParseLogLine(hyTextLog)
	if !ok || evHy == nil {
		t.Fatalf("failed to parse IPv6 Hysteria text log line")
	}
	if evHy.ClientRawID != "alice_hy_v6" {
		t.Errorf("expected ClientRawID 'alice_hy_v6', got '%s'", evHy.ClientRawID)
	}
	if evHy.ClientIP != "2001:db8:cafe::42" {
		t.Errorf("expected ClientIP '2001:db8:cafe::42', got '%s'", evHy.ClientIP)
	}
	if evHy.TargetHost != "2001:db8:1000::1" {
		t.Errorf("expected TargetHost '2001:db8:1000::1', got '%s'", evHy.TargetHost)
	}
	if evHy.TargetPort != 22 {
		t.Errorf("expected TargetPort 22, got %d", evHy.TargetPort)
	}

	// Hysteria 2 JSON log line
	hyJsonLog := `{"time":"2026-11-08T00:00:00Z","level":"info","msg":"tcp request","id":"alice_hy_json","reqAddr":"[2001:db8:1000::1]:22","client_ip":"[2001:db8:cafe::42]:54321"}`
	evHyJson, ok := hyParser.ParseLogLine(hyJsonLog)
	if !ok || evHyJson == nil {
		t.Fatalf("failed to parse IPv6 Hysteria JSON log line")
	}
	if evHyJson.ClientRawID != "alice_hy_json" {
		t.Errorf("expected ClientRawID 'alice_hy_json', got '%s'", evHyJson.ClientRawID)
	}
	if evHyJson.ClientIP != "2001:db8:cafe::42" {
		t.Errorf("expected ClientIP '2001:db8:cafe::42', got '%s'", evHyJson.ClientIP)
	}
	if evHyJson.TargetHost != "2001:db8:1000::1" {
		t.Errorf("expected TargetHost '2001:db8:1000::1', got '%s'", evHyJson.TargetHost)
	}
	if evHyJson.TargetPort != 22 {
		t.Errorf("expected TargetPort 22, got %d", evHyJson.TargetPort)
	}

	// 4. LogAuditor multi-core with IPv6 audit trail
	tracker := NewClientRiskTracker(DefaultRiskScorerConfig(), nil)
	defer tracker.Stop()
	reg := NewClientRegistry()
	auditor := NewLogAuditor(tracker, reg, []int{22, 443})

	auditor.AuditLogLine("xray", xrayLog)
	auditor.AuditLogLine("sing-box", sbStage1)
	auditor.AuditLogLine("sing-box", sbStage2)
	auditor.AuditLogLine("hysteria2", hyTextLog)

	pXray, exists := tracker.GetProfile("alice_v6@example.com")
	if !exists || pXray.RiskScore != 35 {
		t.Errorf("expected profile for alice_v6@example.com with score 35, got exists=%v profile=%+v", exists, pXray)
	}

	pHy, exists := tracker.GetProfile("alice_hy_v6")
	if !exists || pHy.RiskScore != 35 {
		t.Errorf("expected profile for alice_hy_v6 with score 35, got exists=%v profile=%+v", exists, pHy)
	}
}
