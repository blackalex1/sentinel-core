package security

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/blackalex1/sentinel-core/pkg/security/detector"
)

// UnifiedSecurityEngine provides cross-platform threat detection and port shielding.
type UnifiedSecurityEngine struct {
	mu               sync.RWMutex
	profiles         map[string]*entitySecurityProfile
	bannedEntities   map[string]*BannedEntity
	pcapActiveUntil  time.Time
	pcapActiveReason string
	pcapActiveFile   string
	singboxParser    *detector.SingboxParser
	decayTicker      *time.Ticker
	stopChan         chan struct{}
	policy           SecurityPolicyConfig
}

var (
	defaultUnifiedEngine *UnifiedSecurityEngine
	unifiedEngineOnce    sync.Once
	safeFilenameRegex    = regexp.MustCompile(`[^a-zA-Z0-9_\.-]`)
)

func sanitizeFilename(s string) string {
	clean := safeFilenameRegex.ReplaceAllString(s, "_")
	if clean == "" {
		return "entity"
	}
	return clean
}

// GetDefaultSecurityEngine returns the global singleton unified security engine.
func GetDefaultSecurityEngine() *UnifiedSecurityEngine {
	unifiedEngineOnce.Do(func() {
		defaultUnifiedEngine = NewUnifiedSecurityEngine(3 * time.Minute)
	})
	return defaultUnifiedEngine
}

// NewUnifiedSecurityEngine creates a new cross-platform threat engine.
func NewUnifiedSecurityEngine(decayInterval time.Duration) *UnifiedSecurityEngine {
	if decayInterval <= 0 {
		decayInterval = 3 * time.Minute
	}

	engine := &UnifiedSecurityEngine{
		profiles:       make(map[string]*entitySecurityProfile),
		bannedEntities: make(map[string]*BannedEntity),
		singboxParser:  detector.NewSingboxParser(),
		decayTicker:    time.NewTicker(decayInterval),
		stopChan:       make(chan struct{}),
		policy:         DefaultSecurityPolicy(),
	}

	go engine.decayWorker()
	return engine
}

// ConfigurePolicy dynamically updates the engine's security and shielding policy.
func (e *UnifiedSecurityEngine) ConfigurePolicy(cfg SecurityPolicyConfig) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if cfg.Mode == "" {
		cfg.Mode = ModeThresholdBlock
	}
	if cfg.BlockThreshold <= 0 {
		cfg.BlockThreshold = 3
	}
	if cfg.PcapThreshold <= 0 {
		cfg.PcapThreshold = 3
	}
	if cfg.PortScanThreshold <= 0 {
		cfg.PortScanThreshold = 5
	}
	if cfg.WindowSeconds <= 0 {
		cfg.WindowSeconds = 30
	}
	if cfg.PcapDirectory == "" {
		cfg.PcapDirectory = "data/pcaps"
	}
	if len(cfg.ProtectedPorts) == 0 {
		cfg.ProtectedPorts = []int{445, 135, 139, 3389, 22, 23, 5353}
	}
	e.policy = cfg
}

// GetPolicy returns the current active security policy.
func (e *UnifiedSecurityEngine) GetPolicy() SecurityPolicyConfig {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.policy
}

// SetPcapConfig configures automated PCAP packet recording.
func (e *UnifiedSecurityEngine) SetPcapConfig(dir string, threshold int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.policy.PcapDirectory = dir
	if threshold > 0 {
		e.policy.PcapThreshold = threshold
	}
	e.policy.AutoPcapCapture = true
}

// AuditConnection executes comprehensive threat auditing on any incoming socket or log event.
func (e *UnifiedSecurityEngine) AuditConnection(req SecurityAuditRequest) SecurityAuditVerdict {
	now := time.Now()
	nowMs := now.UnixMilli()

	caller := strings.TrimSpace(req.CallerID)
	if caller == "" {
		caller = strings.TrimSpace(req.PackageName)
	}
	if caller == "" {
		caller = "DefaultEntity"
	}
	isSystem := isProtectedSystemEntity(caller, req.ExecutablePath)

	// Determine active policy (global with per-request override)
	e.mu.RLock()
	policy := e.policy
	e.mu.RUnlock()
	if req.PolicyOverride != nil {
		policy = *req.PolicyOverride
	}

	windowDuration := time.Duration(policy.WindowSeconds) * time.Second
	if windowDuration <= 0 {
		windowDuration = 30 * time.Second
	}

	// 0. Check if entity is already quarantined in Zero Trust registry
	if e.IsEntityBlocked(caller) {
		v := SecurityAuditVerdict{
			IsBlocked:       true,
			ShouldBlock:     false,
			IsSystemFlagged: false,
			ThreatDetected:  true,
			ThreatType:      ThreatCoreBlocked,
			Description:     fmt.Sprintf("Process '%s' is in Zero Trust isolation", caller),
			Action:          "BLOCK",
			RiskScore:       100,
			AttemptCount:    1,
			AttemptsCount:   1,
			Timestamp:       nowMs,
		}
		e.handlePcapAndProfile(caller, &v, req, policy, now, nowMs)
		return v
	}

	// 0.1 Check for Masquerading / Fake System Process (MITRE ATT&CK T1036)
	if isMasq, masqReason := IsMasqueradedSystemProcess(caller, req.ExecutablePath); isMasq {
		v := SecurityAuditVerdict{
			IsBlocked:      true,
			ShouldBlock:    true,
			ThreatDetected: true,
			ThreatType:     ThreatMasquerade,
			Description:    masqReason,
			Action:         "BLOCK",
			RiskScore:      100,
			Timestamp:      nowMs,
		}
		e.handlePcapAndProfile(caller, &v, req, policy, now, nowMs)
		return v
	}

	// 1. SSRF / Cloud Metadata endpoint probe (Always zero-tolerance block)
	if IsCloudMetadataEndpoint(req.DestinationIP, req.DestinationHost) {
		v := SecurityAuditVerdict{
			IsBlocked:      true,
			ShouldBlock:    true,
			ThreatDetected: true,
			ThreatType:     ThreatSSRFProbe,
			Description:    "Blocked unauthorized cloud metadata / SSRF access attempt (169.254.169.254)",
			Action:         "BLOCK",
			RiskScore:      100,
			Timestamp:      nowMs,
		}
		e.handlePcapAndProfile(caller, &v, req, policy, now, nowMs)
		return v
	}

	// Check if port is in protected ports list
	isSensitive := false
	auditPorts := req.AuditPorts
	if len(auditPorts) == 0 {
		auditPorts = policy.ProtectedPorts
	}
	for _, p := range auditPorts {
		if p == req.Port && p > 0 {
			isSensitive = true
			break
		}
	}

	// 2. Explicit Core Block Rule triggered for non-shielded port (e.g. AdBlock, QUIC drop, BitTorrent rule)
	if req.IsExplicitBlock && !isSensitive {
		v := SecurityAuditVerdict{
			IsBlocked:      true,
			ShouldBlock:    false,
			ThreatDetected: false,
			ThreatType:     ThreatNone,
			Description:    fmt.Sprintf("Filtered connection to %s:%d dropped by routing rule", req.DestinationIP, req.Port),
			Action:         "DROP",
			RiskScore:      0,
			Timestamp:      nowMs,
		}
		return v
	}

	// 3. Safe Web/DNS/LAN traffic whitelist (only for unshielded ports)
	if !isSensitive && IsSafeSystemTraffic(req.DestinationIP, req.DestinationHost, req.Port) {
		v := SecurityAuditVerdict{
			IsBlocked:      false,
			ShouldBlock:    false,
			ThreatDetected: false,
			ThreatType:     ThreatNone,
			Description:    "Standard safe network traffic",
			Action:         "ALLOW",
			RiskScore:      0,
			Timestamp:      nowMs,
		}
		// If continuous 5-minute PCAP session is running, record safe traffic as well
		e.mu.RLock()
		activePcap := now.Before(e.pcapActiveUntil)
		pcapFile := e.pcapActiveFile
		e.mu.RUnlock()
		if activePcap && pcapFile != "" {
			srcIP := "127.0.0.1"
			if req.Platform == "android" {
				srcIP = "10.0.0.2"
			}
			_ = SynthesizeAndRecordThreatPcap(pcapFile, req.Protocol, srcIP, 54321, req.DestinationIP, req.Port, "TRAFFIC", nowMs)
			v.PcapCaptured = true
			v.PcapFilePath = pcapFile
		}
		return v
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	profile, exists := e.profiles[caller]
	if !exists {
		if len(e.profiles) >= 10000 {
			// Evict profiles unseen for >1 minute to protect against OOM
			for k, p := range e.profiles {
				if now.Sub(p.LastSeen) > 1*time.Minute {
					delete(e.profiles, k)
				}
			}
			if len(e.profiles) >= 10000 {
				caller = "DefaultEntity"
				profile = e.profiles[caller]
			}
		}
		if profile == nil {
			profile = &entitySecurityProfile{
				CallerID:       caller,
				RiskScore:      0,
				ThreatCount:    0,
				LastSeen:       now,
				ProbedPorts:    make(map[int]time.Time),
				RecentAttempts: make([]entityConnEntry, 0, 10),
			}
			e.profiles[caller] = profile
		}
	}

	profile.LastSeen = now
	if req.Port > 0 && !IsSafeSystemTraffic("", "", req.Port) {
		profile.ProbedPorts[req.Port] = now
	}

	// Prune attempts older than window
	var recent []entityConnEntry
	for _, a := range profile.RecentAttempts {
		if now.Sub(a.Timestamp) < 1*time.Minute {
			recent = append(recent, a)
		}
	}
	recent = append(recent, entityConnEntry{
		Timestamp:     now,
		DestinationIP: req.DestinationIP,
		Port:          req.Port,
	})
	if len(recent) > 100 {
		recent = recent[len(recent)-100:]
	}
	profile.RecentAttempts = recent

	// Prune probed ports older than windowDuration
	for p, t := range profile.ProbedPorts {
		if now.Sub(t) > windowDuration {
			delete(profile.ProbedPorts, p)
		}
	}

	var verdict SecurityAuditVerdict

	if isSensitive {
		profile.ThreatCount++
		profile.RiskScore += 25
		if profile.RiskScore > 100 {
			profile.RiskScore = 100
		}

		attemptCount := profile.ThreatCount
		blockLimit := policy.BlockThreshold
		if req.MaxThreshold > 0 {
			blockLimit = req.MaxThreshold
		}
		if blockLimit <= 0 {
			blockLimit = 3
		}

		isExceeded := (req.MaxThreshold > 0 && attemptCount > blockLimit) || (req.MaxThreshold <= 0 && attemptCount >= blockLimit)
		if policy.Mode == ModeStrictBlock {
			isExceeded = true
		} else if policy.Mode == ModeAlertOnly {
			isExceeded = false
		}

		shouldBlock := isExceeded && !isSystem
		isSystemFlagged := isSystem && isExceeded
		action := "ALERT"
		if shouldBlock {
			action = "BLOCK"
		} else if isSystemFlagged {
			action = "FLAG_SYSTEM"
		}

		var desc string
		if shouldBlock {
			desc = fmt.Sprintf("Shielded sensitive port %d blocked (policy %s: attempt %d/%d)", req.Port, policy.Mode, attemptCount, blockLimit)
		} else if isSystemFlagged {
			desc = fmt.Sprintf("System entity '%s' probed sensitive port %d (flagged)", caller, req.Port)
		} else {
			desc = fmt.Sprintf("Shielded sensitive port %d probe detected (attempt %d/%d)", req.Port, attemptCount, blockLimit)
		}

		threatType := ThreatSensitivePort
		if isSystemFlagged {
			threatType = ThreatHighFrequency
		}

		verdict = SecurityAuditVerdict{
			IsBlocked:       shouldBlock,
			ShouldBlock:     shouldBlock,
			IsSystemFlagged: isSystemFlagged,
			ThreatDetected:  true,
			ThreatType:      threatType,
			Description:     desc,
			Action:          action,
			RiskScore:       profile.RiskScore,
			AttemptCount:    attemptCount,
			AttemptsCount:   attemptCount,
			Threshold:       blockLimit,
			Timestamp:       nowMs,
		}
	} else if len(profile.ProbedPorts) >= policy.PortScanThreshold && policy.PortScanThreshold > 0 {
		// Port scan threshold reached
		profile.ThreatCount++
		profile.RiskScore += 40
		if profile.RiskScore > 100 {
			profile.RiskScore = 100
		}

		shouldScanBlock := policy.Mode == ModeStrictBlock && !isSystem
		verdict = SecurityAuditVerdict{
			IsBlocked:      shouldScanBlock,
			ShouldBlock:    shouldScanBlock,
			ThreatDetected: true,
			ThreatType:     ThreatPortScan,
			Description:    fmt.Sprintf("Entity '%s' performed port scan across %d distinct ports", caller, len(profile.ProbedPorts)),
			Action:         "ALERT",
			RiskScore:      profile.RiskScore,
			AttemptCount:   len(profile.ProbedPorts),
			Threshold:      policy.PortScanThreshold,
			Timestamp:      nowMs,
		}
	} else {
		verdict = SecurityAuditVerdict{
			IsBlocked:      false,
			ShouldBlock:    false,
			ThreatDetected: false,
			ThreatType:     ThreatNone,
			Description:    "Normal network connection",
			Action:         "ALLOW",
			RiskScore:      profile.RiskScore,
			Timestamp:      nowMs,
		}
	}

	// If engine decided to block -> quarantine entity in Zero Trust registry (never quarantine OS components)
	if verdict.ShouldBlock && !isSystem {
		e.bannedEntities[caller] = &BannedEntity{
			CallerID:  caller,
			BlockedAt: now,
			Reason:    verdict.Description,
			RiskScore: verdict.RiskScore,
		}
	}

	// Trigger PCAP session ONLY when block threshold is reached or on zero-tolerance threats (SSRF, PortScan)
	if verdict.ThreatDetected && policy.AutoPcapCapture {
		if verdict.ShouldBlock || verdict.IsBlocked || verdict.ThreatType == ThreatPortScan || verdict.ThreatType == ThreatSSRFProbe {
			e.EnsureActivePcapSession(verdict.Description, policy, now)
		}
	}

	// Trigger continuous 5-minute PCAP recording into the ONE active session file
	if now.Before(e.pcapActiveUntil) && e.pcapActiveFile != "" {
		srcIP := "127.0.0.1"
		if req.Platform == "android" {
			srcIP = "10.0.0.2"
		}
		_ = os.MkdirAll(filepath.Dir(e.pcapActiveFile), 0755)
		err := SynthesizeAndRecordThreatPcap(e.pcapActiveFile, req.Protocol, srcIP, 54321, req.DestinationIP, req.Port, string(verdict.ThreatType), nowMs)
		if err == nil {
			verdict.PcapCaptured = true
			verdict.PcapFilePath = e.pcapActiveFile
			profile.PcapCaptured = true
			profile.PcapFilePath = e.pcapActiveFile
		}
	}

	return verdict
}

func (e *UnifiedSecurityEngine) handlePcapAndProfile(caller string, v *SecurityAuditVerdict, req SecurityAuditRequest, policy SecurityPolicyConfig, now time.Time, nowMs int64) {
	e.mu.Lock()
	defer e.mu.Unlock()

	profile, exists := e.profiles[caller]
	if !exists {
		profile = &entitySecurityProfile{
			CallerID: caller,
			LastSeen: now,
		}
		e.profiles[caller] = profile
	}
	profile.ThreatCount++
	profile.RiskScore = 100

	if v.ShouldBlock && !isProtectedSystemEntity(caller, req.ExecutablePath) {
		e.bannedEntities[caller] = &BannedEntity{
			CallerID:  caller,
			BlockedAt: now,
			Reason:    v.Description,
			RiskScore: 100,
		}
		e.EnsureActivePcapSession(v.Description, policy, now)
	}

	if now.Before(e.pcapActiveUntil) && e.pcapActiveFile != "" {
		srcIP := "127.0.0.1"
		if req.Platform == "android" {
			srcIP = "10.0.0.2"
		}
		_ = os.MkdirAll(filepath.Dir(e.pcapActiveFile), 0755)
		err := SynthesizeAndRecordThreatPcap(e.pcapActiveFile, req.Protocol, srcIP, 54321, req.DestinationIP, req.Port, string(v.ThreatType), nowMs)
		if err == nil {
			v.PcapCaptured = true
			v.PcapFilePath = e.pcapActiveFile
			profile.PcapCaptured = true
			profile.PcapFilePath = e.pcapActiveFile
		}
	}
}
