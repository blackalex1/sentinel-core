package security

import (
	"testing"
	"time"
)

func TestDecay_LifecycleAndDecayStep(t *testing.T) {
	engine := NewUnifiedSecurityEngine(100 * time.Millisecond)
	defer engine.Stop()

	now := time.Now()

	// 1. Setup banned entities
	engine.BanEntity("client-ttl-expired", ThreatCoreBlocked, "test ban expired")
	engine.BanEntity("client-ttl-active", ThreatCoreBlocked, "test ban active")

	engine.mu.Lock()
	// Set blocked at in the past for client-ttl-expired (>15m)
	engine.bannedEntities["client-ttl-expired"].BlockedAt = now.Add(-20 * time.Minute)
	engine.bannedEntities["client-ttl-active"].BlockedAt = now.Add(-5 * time.Minute)

	// Setup profiles: one stale (>10m), one active (>0 score), one with 0 score
	engine.profiles["stale-profile"] = &entitySecurityProfile{
		CallerID:    "stale-profile",
		RiskScore:   50,
		ThreatCount: 2,
		LastSeen:    now.Add(-15 * time.Minute),
	}
	engine.profiles["active-profile"] = &entitySecurityProfile{
		CallerID:    "active-profile",
		RiskScore:   30,
		ThreatCount: 3,
		LastSeen:    now.Add(-2 * time.Minute),
	}
	engine.profiles["floor-profile"] = &entitySecurityProfile{
		CallerID:    "floor-profile",
		RiskScore:   10,
		ThreatCount: 1,
		LastSeen:    now.Add(-1 * time.Minute),
	}
	engine.mu.Unlock()

	// Execute decay step
	engine.runDecayStep(now)

	// Verify TTL unblock
	if engine.IsEntityBlocked("client-ttl-expired") {
		t.Errorf("expected client-ttl-expired to be unblocked by TTL")
	}
	if !engine.IsEntityBlocked("client-ttl-active") {
		t.Errorf("expected client-ttl-active to remain blocked")
	}

	// Verify profile decay
	engine.mu.RLock()
	defer engine.mu.RUnlock()

	if _, ok := engine.profiles["stale-profile"]; ok {
		t.Errorf("expected stale-profile to be evicted")
	}

	active, ok := engine.profiles["active-profile"]
	if !ok || active.RiskScore != 10 || active.ThreatCount != 2 {
		t.Errorf("expected active-profile RiskScore=10 ThreatCount=2, got: %+v", active)
	}

	floor, ok := engine.profiles["floor-profile"]
	if !ok || floor.RiskScore != 0 || floor.ThreatCount != 0 {
		t.Errorf("expected floor-profile RiskScore=0 ThreatCount=0, got: %+v", floor)
	}
}
