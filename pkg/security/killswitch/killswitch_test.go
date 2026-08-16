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
