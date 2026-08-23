package security

import (
	"os"
	"testing"
)

func TestUnifiedSecurityEngine_ThresholdBlockMode(t *testing.T) {
	engine := NewUnifiedSecurityEngine(0)
	defer engine.Stop()

	// Configure Threshold Block Policy with 3 attempts limit
	engine.ConfigurePolicy(SecurityPolicyConfig{
		Mode:           ModeThresholdBlock,
		BlockThreshold: 3,
		ProtectedPorts: []int{22, 445, 3389},
	})

	req := SecurityAuditRequest{
		CallerID:      "test-agent",
		DestinationIP: "198.51.100.22",
		Port:          22,
		Protocol:      "TCP",
		Platform:      "windows",
	}

	// Attempt 1: Threat detected, but NOT blocked yet (alert only)
	v1 := engine.AuditConnection(req)
	if !v1.ThreatDetected || v1.IsBlocked || v1.Action != "ALERT" || v1.AttemptCount != 1 {
		t.Fatalf("expected attempt 1 to ALERT without block, got: %+v", v1)
	}

	// Attempt 2: Threat detected, still ALERT
	v2 := engine.AuditConnection(req)
	if !v2.ThreatDetected || v2.IsBlocked || v2.Action != "ALERT" || v2.AttemptCount != 2 {
		t.Fatalf("expected attempt 2 to ALERT without block, got: %+v", v2)
	}

	// Attempt 3: Threshold reached -> MUST BLOCK!
	v3 := engine.AuditConnection(req)
	if !v3.ThreatDetected || !v3.IsBlocked || v3.Action != "BLOCK" || v3.AttemptCount != 3 {
		t.Fatalf("expected attempt 3 to BLOCK, got: %+v", v3)
	}
}

func TestUnifiedSecurityEngine_StrictBlockMode(t *testing.T) {
	engine := NewUnifiedSecurityEngine(0)
	defer engine.Stop()

	engine.ConfigurePolicy(SecurityPolicyConfig{
		Mode:           ModeStrictBlock,
		ProtectedPorts: []int{22, 445},
	})

	req := SecurityAuditRequest{
		CallerID:      "test-agent",
		DestinationIP: "198.51.100.22",
		Port:          22,
		Protocol:      "TCP",
		Platform:      "windows",
	}

	// Strict mode: MUST BLOCK immediately on 1st attempt
	v := engine.AuditConnection(req)
	if !v.ThreatDetected || !v.IsBlocked || v.Action != "BLOCK" {
		t.Fatalf("expected strict mode to block on 1st attempt, got: %+v", v)
	}
}

func TestUnifiedSecurityEngine_AlertOnlyMode(t *testing.T) {
	engine := NewUnifiedSecurityEngine(0)
	defer engine.Stop()

	engine.ConfigurePolicy(SecurityPolicyConfig{
		Mode:           ModeAlertOnly,
		ProtectedPorts: []int{22, 445},
	})

	req := SecurityAuditRequest{
		CallerID:      "test-agent",
		DestinationIP: "198.51.100.22",
		Port:          22,
		Protocol:      "TCP",
		Platform:      "windows",
	}

	for i := 1; i <= 5; i++ {
		v := engine.AuditConnection(req)
		if !v.ThreatDetected || v.IsBlocked || v.Action != "ALERT" {
			t.Fatalf("expected alert_only mode to never block, attempt %d got: %+v", i, v)
		}
	}
}

func TestUnifiedSecurityEngine_SSRFProtection(t *testing.T) {
	engine := NewUnifiedSecurityEngine(0)
	defer engine.Stop()

	v := engine.AuditConnection(SecurityAuditRequest{
		CallerID:        "malicious-app",
		DestinationIP:   "169.254.169.254",
		DestinationHost: "metadata.google.internal",
		Port:            80,
		Protocol:        "TCP",
	})
	if !v.ThreatDetected || !v.IsBlocked || v.ThreatType != ThreatSSRFProbe {
		t.Fatalf("expected SSRF probe to be blocked, got: %+v", v)
	}
}

func TestUnifiedSecurityEngine_SafeTrafficWhitelist(t *testing.T) {
	engine := NewUnifiedSecurityEngine(0)
	defer engine.Stop()

	// Port 53 DNS
	vDNS := engine.AuditConnection(SecurityAuditRequest{
		CallerID:      "system-resolver",
		DestinationIP: "8.8.8.8",
		Port:          53,
		Protocol:      "UDP",
		AuditPorts:    []int{22, 445, 3389},
	})
	if vDNS.ThreatDetected || vDNS.IsBlocked {
		t.Fatalf("expected safe DNS traffic to pass without threat alert, got: %+v", vDNS)
	}

	// Port 443 HTTPS
	vWeb := engine.AuditConnection(SecurityAuditRequest{
		CallerID:      "chrome",
		DestinationIP: "142.250.190.46",
		Port:          443,
		Protocol:      "TCP",
		AuditPorts:    []int{22, 445, 3389},
	})
	if vWeb.ThreatDetected || vWeb.IsBlocked {
		t.Fatalf("expected safe HTTPS traffic to pass without threat alert, got: %+v", vWeb)
	}
}

func TestUnifiedSecurityEngine_PortScanDetection(t *testing.T) {
	engine := NewUnifiedSecurityEngine(0)
	defer engine.Stop()

	ports := []int{21, 25, 110, 143, 993, 995}
	var lastV SecurityAuditVerdict
	for _, p := range ports {
		lastV = engine.AuditConnection(SecurityAuditRequest{
			CallerID:      "nmap-scanner",
			DestinationIP: "192.0.2.10",
			Port:          p,
			Protocol:      "TCP",
		})
	}

	if !lastV.ThreatDetected || lastV.ThreatType != ThreatPortScan {
		t.Fatalf("expected port scan to be detected after 5+ distinct ports, got: %+v", lastV)
	}
}

func TestGetPortShieldCatalog(t *testing.T) {
	catalogRU := GetPortShieldCatalog("ru")
	if len(catalogRU) == 0 {
		t.Fatalf("expected non-empty RU port catalog")
	}

	foundSSH := false
	for _, item := range catalogRU {
		if item.Port == 22 {
			foundSSH = true
			if item.Name == "" || item.ThreatRisk == "" {
				t.Errorf("expected localized name and risk for SSH port 22")
			}
		}
	}
	if !foundSSH {
		t.Fatalf("expected SSH port 22 in catalog")
	}

	catalogEN := GetPortShieldCatalog("en")
	if catalogEN == nil || len(catalogEN) != len(catalogRU) {
		t.Errorf("expected same length for EN and RU catalog")
	}
}

func TestUnifiedSecurityEngine_QuarantineAndUnblock(t *testing.T) {
	engine := NewUnifiedSecurityEngine(0)
	defer engine.Stop()

	engine.ConfigurePolicy(SecurityPolicyConfig{
		Mode:           ModeThresholdBlock,
		BlockThreshold: 2,
		ProtectedPorts: []int{22, 445},
	})

	req := SecurityAuditRequest{
		CallerID:      "bad_process.exe",
		DestinationIP: "198.51.100.22",
		Port:          22,
		Protocol:      "TCP",
		Platform:      "windows",
	}

	// Attempt 1: Alert
	v1 := engine.AuditConnection(req)
	if v1.IsBlocked || engine.IsEntityBlocked("bad_process.exe") {
		t.Fatalf("attempt 1 should not block or quarantine")
	}

	// Attempt 2: Block & Quarantine
	v2 := engine.AuditConnection(req)
	if !v2.IsBlocked || !engine.IsEntityBlocked("bad_process.exe") {
		t.Fatalf("attempt 2 should block and quarantine bad_process.exe")
	}

	blocked := engine.GetBlockedEntities()
	if len(blocked) != 1 || blocked[0].CallerID != "bad_process.exe" {
		t.Fatalf("expected 1 quarantined entity, got: %+v", blocked)
	}

	// Attempt 3 on safe web port 80: must still be blocked due to Zero Trust isolation!
	v3 := engine.AuditConnection(SecurityAuditRequest{
		CallerID:      "bad_process.exe",
		DestinationIP: "93.184.216.34",
		Port:          80,
		Protocol:      "TCP",
	})
	if !v3.IsBlocked || v3.ThreatType != ThreatCoreBlocked {
		t.Fatalf("quarantined process should be blocked even on web ports, got: %+v", v3)
	}

	// Unblock entity
	engine.UnblockEntity("bad_process.exe")
	if engine.IsEntityBlocked("bad_process.exe") {
		t.Fatalf("expected entity to be unblocked")
	}
	if len(engine.GetBlockedEntities()) != 0 {
		t.Fatalf("expected 0 blocked entities after unblock")
	}
}

func TestUnifiedSecurityEngine_PcapSessionAndIngest(t *testing.T) {
	engine := NewUnifiedSecurityEngine(0)
	defer engine.Stop()

	engine.ConfigurePolicy(SecurityPolicyConfig{
		Mode:            ModeThresholdBlock,
		BlockThreshold:  1,
		AutoPcapCapture: true,
		PcapDirectory:   t.TempDir(),
		ProtectedPorts:  []int{445},
	})

	// 1. Process discovery log line
	line1 := "INFO [112233 0ms] router: found process path: C:\\Tools\\smb_scanner.exe"
	_ = engine.IngestCoreLog(line1)

	// 2. Inbound connection on shielded port 445
	line2 := "INFO [112233 0ms] inbound/tun[tun-in]: inbound connection to 192.168.1.50:445"
	v := engine.IngestCoreLog(line2)

	if v == nil {
		t.Fatalf("expected verdict from IngestCoreLog")
	}
	if !v.ThreatDetected || !v.IsBlocked || !v.PcapCaptured {
		t.Fatalf("expected threat blocked and PCAP captured, got: %+v", v)
	}

	// 3. Verify active PCAP session
	status := engine.GetPcapStatus()
	if !status.IsActive || status.FilePath == "" {
		t.Fatalf("expected active PCAP session status, got: %+v", status)
	}

	engine.StopPcapSession()
	statusAfter := engine.GetPcapStatus()
	if statusAfter.IsActive {
		t.Fatalf("expected PCAP session to be inactive after stop")
	}
}

func TestUnifiedSecurityEngine_SinglePcapFileForContinuousSession(t *testing.T) {
	tempDir := t.TempDir()
	engine := NewUnifiedSecurityEngine(0)
	defer engine.Stop()

	engine.ConfigurePolicy(SecurityPolicyConfig{
		Mode:            ModeStrictBlock,
		BlockThreshold:  1,
		AutoPcapCapture: true,
		PcapDirectory:   tempDir,
		ProtectedPorts:  []int{22, 445, 3389},
	})

	// Fire 10 blocked attempts rapidly
	for i := 0; i < 10; i++ {
		v := engine.AuditConnection(SecurityAuditRequest{
			CallerID:      "ssh_client.exe",
			DestinationIP: "198.51.100.14",
			Port:          22,
			Protocol:      "TCP",
			Platform:      "windows",
		})
		if !v.IsBlocked || !v.PcapCaptured {
			t.Fatalf("attempt %d should be blocked with PCAP captured", i+1)
		}
	}

	// Verify that ONLY ONE file was created in tempDir
	entries, err := os.ReadDir(tempDir)
	if err != nil {
		t.Fatalf("failed to read temp dir: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected exactly 1 PCAP file for continuous session, found %d: %+v", len(entries), entries)
	}

	info, err := entries[0].Info()
	if err != nil {
		t.Fatalf("failed to get entry info: %v", err)
	}
	// File should contain header (24 bytes) + 10 packets (~100-200 bytes each)
	if info.Size() < 24+10*50 {
		t.Fatalf("PCAP file size is too small (%d bytes), expected >500 bytes for 10 packets", info.Size())
	}
}

func TestUnifiedSecurityEngine_MasqueradingDetection(t *testing.T) {
	engine := NewUnifiedSecurityEngine(0)
	defer engine.Stop()

	engine.ConfigurePolicy(SecurityPolicyConfig{
		Mode:            ModeThresholdBlock,
		BlockThreshold:  3,
		AutoPcapCapture: true,
		PcapDirectory:   t.TempDir(),
		ProtectedPorts:  []int{22, 445},
	})

	// 1. Legitimate Windows svchost.exe in System32
	legitVerdict := engine.AuditConnection(SecurityAuditRequest{
		CallerID:       "svchost.exe",
		ExecutablePath: "C:\\Windows\\System32\\svchost.exe",
		DestinationIP:  "4.207.247.137",
		Port:           443,
		Protocol:       "TCP",
		Platform:       "windows",
	})
	if legitVerdict.IsBlocked || legitVerdict.ThreatDetected {
		t.Fatalf("legitimate System32 svchost.exe should not be blocked: %+v", legitVerdict)
	}

	// 2. Fake svchost.exe in Temp folder (MITRE T1036 Masquerading)
	fakeVerdict := engine.AuditConnection(SecurityAuditRequest{
		CallerID:       "svchost.exe",
		ExecutablePath: "C:\\Users\\tester\\AppData\\Local\\Temp\\svchost.exe",
		DestinationIP:  "198.51.100.50",
		Port:           443,
		Protocol:       "TCP",
		Platform:       "windows",
	})
	if !fakeVerdict.IsBlocked || !fakeVerdict.ThreatDetected || fakeVerdict.ThreatType != ThreatMasquerade {
		t.Fatalf("fake svchost in Temp should be blocked immediately as MASQUERADED_PROCESS: %+v", fakeVerdict)
	}

	// 3. Verify that the fake process is quarantined
	if !engine.IsEntityBlocked("svchost.exe") {
		t.Fatalf("fake svchost.exe should be in quarantine registry")
	}
}
