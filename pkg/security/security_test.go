package security

import (
	"testing"

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
