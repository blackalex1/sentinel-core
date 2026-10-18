package security

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/blackalex1/sentinel-core/pkg/ast"
	"github.com/blackalex1/sentinel-core/pkg/security/detector"
)

func TestSecurityManager_CompromisedClientAndCompiler(t *testing.T) {
	cfg := DefaultSecurityConfig()
	cfg.KillSwitch.Enabled = true
	cfg.Filter.Enabled = true
	cfg.PortGuard.Enabled = true
	cfg.Integrity.BlockCloudMetadata = true

	sm, err := NewSecurityManager(cfg)
	if err != nil {
		t.Fatalf("failed to create SecurityManager: %v", err)
	}
	defer sm.Stop()

	// 1. Test Compiler: Injects high priority security rules into AST
	baseRouting := &ast.RoutingSpec{
		DefaultAction: ast.ActionProxy,
		Rules: []ast.RoutingRule{
			{Action: ast.ActionDirect, Domains: []string{"domain:yandex.ru"}},
		},
	}

	compiledRouting := sm.CompileSecurityRouting(baseRouting)
	if len(compiledRouting.Rules) <= len(baseRouting.Rules) {
		t.Fatalf("expected injected security rules in routing table, got %d rules", len(compiledRouting.Rules))
	}

	// 2. Test Real-time Log Auditor: Compromise escalation
	badUser := "infected_workstation@corp.local"
	sm.AuditLogLine("sing-box", "inbound connection to 192.168.1.10:22 from user "+badUser)
	sm.AuditLogLine("sing-box", "inbound connection to 192.168.1.10:3389 from user "+badUser)
	sm.AuditLogLine("sing-box", "client user "+badUser+" requested 169.254.169.254")

	profile, exists := sm.GetClientProfile(badUser)
	if !exists || profile.Status != detector.StatusCompromised {
		t.Fatalf("expected client %s to be flagged as COMPROMISED, got exists=%v status=%v score=%v", badUser, exists, profile.Status, profile.RiskScore)
	}

	quarantined := sm.GetQuarantinedClients()
	if len(quarantined) == 0 || quarantined[0] != badUser {
		t.Fatalf("expected quarantined client list to contain %s, got: %v", badUser, quarantined)
	}

	// 3. Recompiling routing table now injects a specific block rule for the compromised user
	recompiled := sm.CompileSecurityRouting(baseRouting)
	userBlocked := false
	for _, rule := range recompiled.Rules {
		if rule.Action == ast.ActionBlock {
			for _, u := range rule.Users {
				if u == badUser {
					userBlocked = true
					break
				}
			}
		}
	}
	if !userBlocked {
		t.Fatalf("expected compiled routing to include block rule for quarantined user %s", badUser)
	}

	// 4. Test Connection Auditor
	conns := []detector.ActiveConnection{
		{ID: "c1", User: "scammer@evil.org", DestHost: "192.168.1.1", DestPort: 22},
		{ID: "c2", User: "scammer@evil.org", DestHost: "192.168.1.1", DestPort: 3389},
		{ID: "c3", User: "scammer@evil.org", DestHost: "192.168.1.1", DestPort: 8006},
	}
	auditReport := sm.AuditActiveConnections(conns)
	if auditReport.ViolationsFound == 0 {
		t.Fatalf("expected violations to be recorded during connection audit")
	}

	// 5. Test stats
	stats := sm.GetStats()
	if stats.TotalCompromisedKicks == 0 {
		t.Fatalf("expected compromised kicks counter to increment, got: %+v", stats)
	}
}

func TestDynamicSchemaGeneration(t *testing.T) {
	schemaRU := GenerateSecuritySchema("ru")
	if len(schemaRU) < 10 {
		t.Fatalf("expected at least 10 UI schema fields for Russian, got %d", len(schemaRU))
	}

	schemaEN := GenerateSecuritySchema("en")
	if len(schemaEN) < 10 {
		t.Fatalf("expected at least 10 UI schema fields for English, got %d", len(schemaEN))
	}
}

func TestConfigSerialization(t *testing.T) {
	cfg := DefaultSecurityConfig()
	jsonStr, err := cfg.ToJSON()
	if err != nil {
		t.Fatalf("failed to serialize to JSON: %v", err)
	}

	parsed, err := FromJSON(jsonStr)
	if err != nil {
		t.Fatalf("failed to deserialize from JSON: %v", err)
	}

	if parsed.RateLimiter.RequestsPerSecond != cfg.RateLimiter.RequestsPerSecond {
		t.Fatalf("config value mismatch after deserialization")
	}
}

func TestSecurityManager_Operations(t *testing.T) {
	cfg := DefaultSecurityConfig()
	sm, err := NewSecurityManager(cfg)
	if err != nil {
		t.Fatalf("NewSecurityManager failed: %v", err)
	}
	defer sm.Stop()

	// 1. GetConfig
	if sm.GetConfig().RateLimiter.RequestsPerSecond != cfg.RateLimiter.RequestsPerSecond {
		t.Errorf("GetConfig mismatch")
	}

	// 2. RegisterClient & Aliases
	sm.RegisterClient("client-101", "uuid-1", "user-hy2", "192.168.1.50")
	aliases := sm.GetQuarantinedAliases()
	if len(aliases) != 0 {
		t.Errorf("expected 0 quarantined aliases initially")
	}

	// 3. QuarantineClient & UnquarantineClient
	var reloadTriggered atomic.Bool
	sm.SetOnQuarantineReload(func(clientID string) {
		reloadTriggered.Store(true)
	})

	sm.QuarantineClient("client-101", "Manual isolation")
	quarantined := sm.GetQuarantinedClients()
	if len(quarantined) != 1 || quarantined[0] != "client-101" {
		t.Errorf("expected client-101 in quarantine list, got: %v", quarantined)
	}
	aliases = sm.GetQuarantinedAliases()
	if len(aliases) < 1 {
		t.Errorf("expected quarantined aliases, got: %v", aliases)
	}

	// Unquarantine
	sm.UnquarantineClient("client-101")
	time.Sleep(50 * time.Millisecond) // wait for async hook
	if !reloadTriggered.Load() {
		t.Errorf("expected onQuarantineReload callback to be called on unquarantine")
	}
	if len(sm.GetQuarantinedClients()) != 0 {
		t.Errorf("expected 0 quarantined clients after unquarantine")
	}

	// 4. Threat Journal integration
	tj, err := NewThreatJournal("", "node-sm")
	if err != nil {
		t.Fatalf("NewThreatJournal failed: %v", err)
	}
	sm.SetThreatJournal(tj)
	if sm.GetThreatJournal() != tj {
		t.Errorf("GetThreatJournal mismatch")
	}

	// 5. Node summary
	summary := sm.GetNodeSecuritySummary("node-sm")
	if summary.NodeID != "node-sm" {
		t.Errorf("unexpected security summary: %+v", summary)
	}

	// 6. RiskTracker, SSHMonitor, VPNActive
	if sm.RiskTracker() == nil {
		t.Errorf("expected non-nil RiskTracker")
	}
	_ = sm.SSHMonitor()
	sm.SetVPNActive(true)

	// 7. Security verification methods
	if err := sm.AuditConfig([]byte(`{"outbounds":[]}`)); err != nil {
		t.Errorf("AuditConfig failed: %v", err)
	}
	if err := sm.AuditURI("vless://b9f3857a-ce20-4e1e-b5e0-6f3d141fa2b2@1.1.1.1:443?type=tcp#test"); err != nil {
		t.Errorf("AuditURI failed: %v", err)
	}
	sm.ZeroizeMemory([]byte("secret key"))
}

