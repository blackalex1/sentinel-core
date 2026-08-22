package security

import (
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
	if len(catalogEN) != len(catalogRU) {
		t.Errorf("expected same length for EN and RU catalog")
	}
}
