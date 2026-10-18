package killswitch

import (
	"net"
	"testing"
)

func TestKillSwitchStates(t *testing.T) {
	ks := New(true, true, true, true, []string{"192.168.1.0/24", "10.0.0.0/8"})

	if ks.GetState() != StateBlocking {
		t.Fatalf("expected initial state to be BLOCKING, got %v", ks.GetState())
	}

	stateChanges := 0
	ks.OnStateChange(func(oldState, newState State) {
		stateChanges++
	})

	// Activate VPN
	ks.SetVPNActive(true)
	if ks.GetState() != StateActive {
		t.Fatalf("expected state ACTIVE, got %v", ks.GetState())
	}
	if !ks.IsVPNActive() {
		t.Fatalf("expected VPN to be active")
	}

	// Deactivate VPN -> should drop back to blocking
	ks.SetVPNActive(false)
	if ks.GetState() != StateBlocking {
		t.Fatalf("expected state BLOCKING after VPN drop, got %v", ks.GetState())
	}

	if stateChanges != 2 {
		t.Fatalf("expected 2 state transitions, got %d", stateChanges)
	}
}

func TestKillSwitchPacketEvaluation(t *testing.T) {
	ks := New(true, true, true, true, []string{"192.168.0.0/16", "10.0.0.0/8"})

	// 1. VPN is down: Public traffic must be DROPPED
	publicIP := net.ParseIP("1.1.1.1")
	decision := ks.EvaluatePacket(publicIP, 443, false, false)
	if decision != DecisionDrop {
		t.Fatalf("expected DecisionDrop for public IP when VPN down, got %v", decision)
	}

	// 2. VPN is down: LAN traffic must be ALLOWED
	lanIP := net.ParseIP("192.168.1.1")
	decision = ks.EvaluatePacket(lanIP, 80, false, false)
	if decision != DecisionAllow {
		t.Fatalf("expected DecisionAllow for LAN IP when VPN down, got %v", decision)
	}

	// 3. VPN is down: Plaintext DNS (port 53) to public DNS must be DROPPED
	decision = ks.EvaluatePacket(publicIP, 53, false, true)
	if decision != DecisionDrop {
		t.Fatalf("expected DecisionDrop for plaintext DNS leak, got %v", decision)
	}

	// 4. VPN is active: Public traffic must be ALLOWED
	ks.SetVPNActive(true)
	decision = ks.EvaluatePacket(publicIP, 443, false, false)
	if decision != DecisionAllow {
		t.Fatalf("expected DecisionAllow when VPN active, got %v", decision)
	}

	// 5. IPv6 leak check
	ipv6Public := net.ParseIP("2001:4860:4860::8888")
	decision = ks.EvaluatePacket(ipv6Public, 443, true, false)
	if decision != DecisionDrop {
		t.Fatalf("expected DecisionDrop for IPv6 public IP, got %v", decision)
	}

	// IPv6 loopback should be allowed
	ipv6Loopback := net.ParseIP("::1")
	decision = ks.EvaluatePacket(ipv6Loopback, 8080, true, false)
	if decision != DecisionAllow {
		t.Fatalf("expected DecisionAllow for IPv6 loopback, got %v", decision)
	}
}

func TestDNSLeakGuard_StrictRules(t *testing.T) {
	guard := NewDNSLeakGuard(true)

	dnsServer := net.ParseIP("1.1.1.1")
	loopback := net.ParseIP("127.0.0.1")
	untrustedDNS := net.ParseIP("198.51.100.99")

	// 1. VPN DOWN:
	// Port 53 plaintext to public resolver MUST BE BLOCKED
	if guard.AllowDNSQuery(dnsServer, 53, false) {
		t.Fatalf("vulnerability: allowed plaintext DNS query to public IP when VPN is down!")
	}

	// Port 853 DoT to public resolver MUST BE BLOCKED when VPN down
	if guard.AllowDNSQuery(dnsServer, 853, false) {
		t.Fatalf("vulnerability: allowed DoT query to public IP when VPN is down!")
	}

	// Port 443 DoH to public resolver MUST BE BLOCKED when VPN down
	if guard.AllowDNSQuery(dnsServer, 443, false) {
		t.Fatalf("vulnerability: allowed DoH query to public IP when VPN is down!")
	}

	// Loopback internal resolver query allowed even when VPN is down
	if !guard.AllowDNSQuery(loopback, 53, false) {
		t.Fatalf("expected loopback DNS query to be allowed when VPN is down")
	}

	// 2. VPN UP:
	// Allowed DNS IPs on port 53 / 853 / 443 should pass
	if !guard.AllowDNSQuery(dnsServer, 53, true) {
		t.Fatalf("expected allowed DNS IP on port 53 to pass when VPN is active")
	}
	if !guard.AllowDNSQuery(dnsServer, 853, true) {
		t.Fatalf("expected DoT on port 853 to pass when VPN is active")
	}
	if !guard.AllowDNSQuery(dnsServer, 443, true) {
		t.Fatalf("expected DoH on port 443 to pass when VPN is active")
	}

	// Untrusted DNS IP on port 53 should NOT pass even if VPN is active
	if guard.AllowDNSQuery(untrustedDNS, 53, true) {
		t.Fatalf("expected untrusted external DNS IP to be blocked on port 53")
	}
}

