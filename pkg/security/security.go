package security

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/blackalex1/sentinel-core/pkg/ast"
	"github.com/blackalex1/sentinel-core/pkg/events"
	"github.com/blackalex1/sentinel-core/pkg/security/detector"
	"github.com/blackalex1/sentinel-core/pkg/security/filter"
	"github.com/blackalex1/sentinel-core/pkg/security/guard"
	"github.com/blackalex1/sentinel-core/pkg/security/integrity"
	"github.com/blackalex1/sentinel-core/pkg/security/killswitch"
	"github.com/blackalex1/sentinel-core/pkg/security/ssh"
	"github.com/blackalex1/sentinel-core/pkg/supervisor"
)

// SecurityStats contains real-time counters of security operations.
type SecurityStats struct {
	TotalInspectedOutbound uint64 `json:"total_inspected_outbound"`
	TotalInspectedInbound  uint64 `json:"total_inspected_inbound"`
	TotalThreatsBlocked    uint64 `json:"total_threats_blocked"`
	TotalPortBlocks        uint64 `json:"total_port_blocks"`
	TotalRateLimitDrops    uint64 `json:"total_rate_limit_drops"`
	TotalKillSwitchDrops   uint64 `json:"total_kill_switch_drops"`
	TotalCompromisedKicks  uint64 `json:"total_compromised_kicks"`
}

// SecurityManager is the top-level orchestrator for threat detection and proxy security.
type SecurityManager struct {
	mu           sync.RWMutex
	cfg          SecurityConfig
	killSwitch   *killswitch.KillSwitch
	guard        *guard.Guard
	sanitizer    *integrity.Sanitizer
	threatEngine *filter.ThreatEngine
	riskTracker  *detector.ClientRiskTracker
	logAuditor   *detector.LogAuditor
	connAuditor  *detector.ConnectionAuditor
	sshMonitor   *ssh.SSHMonitor
	eventBus     *events.EventBus

	// Atomic stats counters
	statOutbound     uint64
	statInbound      uint64
	statThreats      uint64
	statPortBlocks   uint64
	statRateDrops    uint64
	statKSDrops      uint64
	statCompromised  uint64

	journal            *ThreatJournal
	onQuarantineReload func(clientID string)
}

// NewSecurityManager initializes all security sub-modules using the provided config.
func NewSecurityManager(cfg SecurityConfig) (*SecurityManager, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid security config: %w", err)
	}

	ks := killswitch.New(
		cfg.KillSwitch.Enabled,
		cfg.KillSwitch.BlockIPv6,
		cfg.KillSwitch.AllowLocalLAN,
		cfg.KillSwitch.StrictDNS,
		cfg.KillSwitch.AllowedSubnets,
	)

	g := guard.New(
		cfg.PortGuard.Enabled,
		cfg.PortGuard.SensitivePorts,
		string(cfg.PortGuard.Action),
		cfg.PortGuard.ScanThreshold,
		cfg.PortGuard.ScanWindowSeconds,
		cfg.PortGuard.AutoBanScanner,
		cfg.RateLimiter.RequestsPerSecond,
		cfg.RateLimiter.Burst,
		cfg.RateLimiter.BanThresholdViolations,
		cfg.RateLimiter.BanDurationSeconds,
		cfg.Whitelist.Processes,
		cfg.Whitelist.IPs,
	)

	san := integrity.NewSanitizer(cfg.Integrity.BlockCloudMetadata)

	thr := filter.NewThreatEngine(
		cfg.Filter.Enabled,
		cfg.Filter.BlockMalware,
		cfg.Filter.BlockPhishing,
		cfg.Filter.BlockMiners,
		cfg.Filter.BlockAds,
		cfg.Filter.CustomBlockedDomains,
		cfg.Filter.CustomAllowedDomains,
		cfg.Filter.CustomBlockedIPs,
	)

	riskCfg := detector.DefaultRiskScorerConfig()
	riskCfg.QuarantineDuration = time.Duration(cfg.RateLimiter.BanDurationSeconds) * time.Second
	riskTracker := detector.NewClientRiskTracker(riskCfg, append(cfg.Whitelist.Processes, cfg.Whitelist.IPs...))

	registry := detector.NewClientRegistry()
	logAuditor := detector.NewLogAuditor(riskTracker, registry, cfg.PortGuard.SensitivePorts)
	connAuditor := detector.NewConnectionAuditor(riskTracker, registry, thr, cfg.PortGuard.SensitivePorts, 200)
	sshMon := ssh.NewSSHMonitor(nil)

	sm := &SecurityManager{
		cfg:          cfg,
		killSwitch:   ks,
		guard:        g,
		sanitizer:    san,
		threatEngine: thr,
		riskTracker:  riskTracker,
		logAuditor:   logAuditor,
		connAuditor:  connAuditor,
		sshMonitor:   sshMon,
		eventBus:     events.GetGlobalBus(),
	}

	// Auto-kick handler when client is detected as compromised
	riskTracker.OnCompromised(func(client *detector.ClientRiskProfile, incident detector.ThreatIncident) {
		atomic.AddUint64(&sm.statCompromised, 1)
		sm.handleAutoKick(client.ClientID)
	})

	return sm, nil
}

// SSHMonitor returns the SSH/Host authentication monitor.
func (sm *SecurityManager) SSHMonitor() *ssh.SSHMonitor {
	return sm.sshMonitor
}

// ProcessAuthLogLine parses an auth/secure log line and tracks SSH logins/logouts.
func (sm *SecurityManager) ProcessAuthLogLine(line string) (*ssh.SSHEvent, bool) {
	if sm.sshMonitor != nil {
		return sm.sshMonitor.ProcessLogLine(line)
	}
	return nil, false
}

// CompileSecurityRouting applies security blocking rules into an AST RoutingSpec for Sing-box / Xray / Hysteria configs.
func (sm *SecurityManager) CompileSecurityRouting(baseRouting *ast.RoutingSpec) *ast.RoutingSpec {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	quarantined := sm.riskTracker.GetQuarantinedClients()
	return InjectSecurityRules(baseRouting, sm.cfg, quarantined)
}

// AuditLogLine processes a single log line from any core and flags potential attacks.
func (sm *SecurityManager) AuditLogLine(coreName, line string) {
	if sm.logAuditor != nil {
		sm.logAuditor.AuditLogLine(coreName, line)
	}
}

// AuditActiveConnections analyzes active proxy connections and flags compromised clients.
func (sm *SecurityManager) AuditActiveConnections(conns []detector.ActiveConnection) detector.ConnectionAuditReport {
	if sm.connAuditor != nil {
		return sm.connAuditor.AuditConnections(conns)
	}
	return detector.ConnectionAuditReport{}
}

// GetQuarantinedClients returns all currently isolated user IDs.
func (sm *SecurityManager) GetQuarantinedClients() []string {
	if sm.riskTracker != nil {
		return sm.riskTracker.GetQuarantinedClients()
	}
	return nil
}

// RegisterClient registers cross-core aliases for a subscriber (UUID for Sing-box/Xray, Username for Hysteria 2).
func (sm *SecurityManager) RegisterClient(primaryID, uuid, hysteriaUser, sourceIP string) {
	if sm.logAuditor != nil && sm.logAuditor.Registry() != nil {
		sm.logAuditor.Registry().RegisterClient(primaryID, uuid, hysteriaUser, sourceIP)
	}
}

// GetQuarantinedAliases returns all known UUIDs, emails, and Hysteria usernames for quarantined clients.
func (sm *SecurityManager) GetQuarantinedAliases() []string {
	if sm.riskTracker == nil {
		return nil
	}
	quarantined := sm.riskTracker.GetQuarantinedClients()
	if sm.logAuditor == nil || sm.logAuditor.Registry() == nil {
		return quarantined
	}
	reg := sm.logAuditor.Registry()
	var all []string
	for _, q := range quarantined {
		all = append(all, reg.GetAllAliases(q)...)
	}
	return all
}

// GetClientProfile retrieves the risk scoring profile of a client.
func (sm *SecurityManager) GetClientProfile(clientID string) (*detector.ClientRiskProfile, bool) {
	if sm.riskTracker != nil {
		return sm.riskTracker.GetProfile(clientID)
	}
	return nil, false
}

// RiskTracker returns the underlying ClientRiskTracker.
func (sm *SecurityManager) RiskTracker() *detector.ClientRiskTracker {
	return sm.riskTracker
}

// SetVPNActive informs the KillSwitch about the tunnel state.
func (sm *SecurityManager) SetVPNActive(active bool) {
	sm.killSwitch.SetVPNActive(active)
}

// InspectOutbound evaluates if an outbound connection to targetHost:targetPort is safe and permitted.
func (sm *SecurityManager) InspectOutbound(targetHost string, targetPort int, isIPv6 bool, isDNS bool) (bool, string) {
	atomic.AddUint64(&sm.statOutbound, 1)

	sm.mu.RLock()
	defer sm.mu.RUnlock()

	if !sm.cfg.Enabled {
		return true, ""
	}

	// 1. SSRF & Endpoint validity check
	if err := sm.sanitizer.AuditEndpoint(targetHost, targetPort); err != nil {
		atomic.AddUint64(&sm.statThreats, 1)
		sm.emitThreatBlocked("SSRF_VIOLATION", targetHost, err.Error())
		return false, err.Error()
	}

	// 2. Threat Intelligence / Content Filtering
	match := sm.threatEngine.CheckHost(targetHost)
	if match.Blocked {
		atomic.AddUint64(&sm.statThreats, 1)
		sm.emitThreatBlocked(string(match.Category), targetHost, match.Reason)
		return false, match.Reason
	}

	// 3. KillSwitch & Leak Protection
	parsedIP := net.ParseIP(targetHost)
	decision := sm.killSwitch.EvaluatePacket(parsedIP, targetPort, isIPv6, isDNS)
	if decision == killswitch.DecisionDrop {
		atomic.AddUint64(&sm.statKSDrops, 1)
		reason := "Blocked by Kill-Switch (VPN disconnected or leak prevented)"
		sm.emitThreatBlocked("KILL_SWITCH_DROP", targetHost, reason)
		return false, reason
	}

	return true, ""
}

// InspectInbound evaluates if an inbound connection from remoteIP to targetPort is permitted.
func (sm *SecurityManager) InspectInbound(remoteIP string, targetPort int) (bool, string) {
	atomic.AddUint64(&sm.statInbound, 1)

	sm.mu.RLock()
	defer sm.mu.RUnlock()

	if !sm.cfg.Enabled {
		return true, ""
	}

	allowed, reason := sm.guard.CheckInbound(remoteIP, targetPort)
	if !allowed {
		if sm.guard.PortMonitor().IsSensitivePort(targetPort) {
			atomic.AddUint64(&sm.statPortBlocks, 1)
		} else {
			atomic.AddUint64(&sm.statRateDrops, 1)
		}
		sm.emitThreatBlocked("INBOUND_GUARD_BLOCKED", remoteIP, reason)
		return false, reason
	}

	return true, ""
}

// AuditConfig checks and sanitizes a proxy configuration JSON payload.
func (sm *SecurityManager) AuditConfig(jsonBytes []byte) error {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	if !sm.cfg.Integrity.SanitizeConfigs {
		return nil
	}
	return sm.sanitizer.SanitizeJSONConfig(jsonBytes)
}

// AuditURI checks and sanitizes a raw proxy connection string (e.g. vless://, hy2://).
func (sm *SecurityManager) AuditURI(rawURI string) error {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	if !sm.cfg.Integrity.SanitizeConfigs {
		return nil
	}
	return sm.sanitizer.AuditURI(rawURI)
}

// VerifySignature validates an Ed25519 signature on configuration or preset data.
func (sm *SecurityManager) VerifySignature(payload []byte, sigB64 string, pubKeyB64 string) error {
	return integrity.VerifyPayloadEd25519(payload, sigB64, pubKeyB64)
}

// ZeroizeMemory wipes sensitive crypto bytes from RAM.
func (sm *SecurityManager) ZeroizeMemory(secret []byte) {
	if sm.cfg.Integrity.ZeroizeOnDrop {
		integrity.ZeroizeBytes(secret)
	}
}

// GetStats returns snapshot of security statistics.
func (sm *SecurityManager) GetStats() SecurityStats {
	return SecurityStats{
		TotalInspectedOutbound: atomic.LoadUint64(&sm.statOutbound),
		TotalInspectedInbound:  atomic.LoadUint64(&sm.statInbound),
		TotalThreatsBlocked:    atomic.LoadUint64(&sm.statThreats),
		TotalPortBlocks:        atomic.LoadUint64(&sm.statPortBlocks),
		TotalRateLimitDrops:    atomic.LoadUint64(&sm.statRateDrops),
		TotalKillSwitchDrops:   atomic.LoadUint64(&sm.statKSDrops),
		TotalCompromisedKicks:  atomic.LoadUint64(&sm.statCompromised),
	}
}

// GetConfig returns the current configuration.
func (sm *SecurityManager) GetConfig() SecurityConfig {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.cfg
}

// Stop cleanly terminates all running routines.
func (sm *SecurityManager) Stop() {
	if sm.guard != nil {
		sm.guard.Stop()
	}
	if sm.riskTracker != nil {
		sm.riskTracker.Stop()
	}
}

// SetOnQuarantineReload registers a callback to rebuild configs and gracefully reload/restart cores on client compromise.
// SetThreatJournal configures the structured threat-only journal.
func (sm *SecurityManager) SetThreatJournal(j *ThreatJournal) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.journal = j
}

// GetThreatJournal returns the configured ThreatJournal.
func (sm *SecurityManager) GetThreatJournal() *ThreatJournal {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.journal
}

// QuarantineClient forcibly quarantines a client across all cores and records it in the journal.
func (sm *SecurityManager) QuarantineClient(clientID, reason string) {
	sm.riskTracker.RecordIncident(
		clientID,
		"MANUAL_QUARANTINE",
		"ADMIN_ACTION",
		reason,
		100, // Forces compromise and quarantine
	)
}

// UnquarantineClient resets a client's risk score and unblocks them.
func (sm *SecurityManager) UnquarantineClient(clientID string) {
	if sm.riskTracker != nil {
		sm.riskTracker.ResetClientScore(clientID)
	}

	sm.mu.RLock()
	j := sm.journal
	sm.mu.RUnlock()

	if j != nil {
		_ = j.LogIncident("UNQUARANTINED", "ADMIN_ACTION", clientID, nil, 0, detector.StatusClean, "", "Client manually unquarantined", "UNBLOCKED")
	}

	// Trigger config reload to remove block rule
	sm.mu.RLock()
	hook := sm.onQuarantineReload
	sm.mu.RUnlock()
	if hook != nil {
		go hook(clientID)
	}
}

// GetNodeSecuritySummary generates a structured status report for remote master queries.
func (sm *SecurityManager) GetNodeSecuritySummary(nodeID string) NodeSecuritySummary {
	quarantined := sm.GetQuarantinedClients()
	profiles := sm.riskTracker.GetAllProfiles()

	var suspicious []SuspiciousClientEntry
	for _, p := range profiles {
		if p.Status == detector.StatusSuspicious || p.Status == detector.StatusCompromised {
			suspicious = append(suspicious, SuspiciousClientEntry{
				ClientID:  p.ClientID,
				RiskScore: p.RiskScore,
				Status:    string(p.Status),
			})
		}
	}

	return NodeSecuritySummary{
		NodeID:             nodeID,
		QuarantinedClients: quarantined,
		SuspiciousClients:  suspicious,
		Stats:              sm.GetStats(),
		Timestamp:          time.Now().Unix(),
	}
}

// SetOnQuarantineReload registers a callback to rebuild configs and gracefully reload/restart cores on client compromise.
func (sm *SecurityManager) SetOnQuarantineReload(hook func(clientID string)) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.onQuarantineReload = hook
}

func (sm *SecurityManager) handleAutoKick(clientID string) {
	// 1. Instant in-memory session drop across active cores (Sing-box, Hysteria 2, Xray) in background
	go func(id string) {
		ctrl := supervisor.GetController()
		_ = ctrl.KickClient(id)
	}(clientID)

	// 2. Log incident to structured threat journal (if enabled)
	sm.mu.RLock()
	j := sm.journal
	aliases := sm.GetQuarantinedAliases()
	sm.mu.RUnlock()

	if j != nil {
		_ = j.LogIncident(
			"COMPROMISED",
			"CLIENT_COMPROMISE",
			clientID,
			aliases,
			100,
			detector.StatusCompromised,
			"",
			"Client risk score exceeded threshold, auto-kick executed",
			"KICKED_AND_ISOLATED",
		)
	}

	// 3. Trigger registered core config rebuild and reload/restart hook
	sm.mu.RLock()
	hook := sm.onQuarantineReload
	sm.mu.RUnlock()
	if hook != nil {
		go hook(clientID)
	}
}

func (sm *SecurityManager) emitThreatBlocked(threatType, target, reason string) {
	if sm.eventBus == nil {
		return
	}
	sm.eventBus.Publish(events.SentinelEvent{
		Category:       events.CategoryThreatBlocked,
		Severity:       events.SeverityWarn,
		Code:           events.CodeThreatAppIsolated,
		Message:        fmt.Sprintf("[%s] Blocked: %s (Reason: %s)", threatType, target, reason),
		Timestamp:      time.Now().Unix(),
		SuggestedAction: events.ActionNone,
	})
}
