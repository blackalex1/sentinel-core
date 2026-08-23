package security

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/blackalex1/sentinel-core/pkg/security/detector"
)

// ThreatClassification defines the unified taxonomy of security threats.
type ThreatClassification string

const (
	ThreatNone          ThreatClassification = "NONE"
	ThreatSensitivePort ThreatClassification = "SENSITIVE_PORT_PROBE"
	ThreatPortScan      ThreatClassification = "PORT_SCAN"
	ThreatSSRFProbe     ThreatClassification = "SSRF_PROBE"
	ThreatHighFrequency ThreatClassification = "HIGH_FREQUENCY_BURST"
	ThreatCoreBlocked   ThreatClassification = "THREAT_BLOCKED"
	ThreatMalwareC2     ThreatClassification = "MALWARE_C2_SUSPECT"
	ThreatMasquerade    ThreatClassification = "MASQUERADED_PROCESS"
)

// BannedEntity represents a process, user or package currently in zero-trust isolation.
type BannedEntity struct {
	CallerID  string    `json:"caller_id"`
	BlockedAt time.Time `json:"blocked_at"`
	Reason    string    `json:"reason"`
	RiskScore int       `json:"risk_score"`
}

// PcapCaptureStatus represents live continuous forensic capture telemetry.
type PcapCaptureStatus struct {
	IsActive         bool   `json:"is_active"`
	Reason           string `json:"reason"`
	FilePath         string `json:"file_path"`
	RemainingSeconds int    `json:"remaining_seconds"`
}

// PortShieldMode defines how aggressively sensitive ports and suspicious behaviors are defended.
type PortShieldMode string

const (
	// ModeAlertOnly registers alerts in logs/threat journal but does not block connections.
	ModeAlertOnly PortShieldMode = "alert_only"

	// ModeThresholdBlock allows initial warnings (1..N-1) and only blocks once BlockThreshold is exceeded.
	ModeThresholdBlock PortShieldMode = "threshold_block"

	// ModeStrictBlock immediately drops connections on the 1st prohibited attempt.
	ModeStrictBlock PortShieldMode = "strict_block"
)

// SecurityPolicyConfig allows applications (Android & Desktop) to configure dynamic defense rules.
type SecurityPolicyConfig struct {
	Mode               PortShieldMode `json:"mode"`                 // "threshold_block", "strict_block", "alert_only"
	BlockThreshold     int            `json:"block_threshold"`     // Number of suspicious attempts before BLOCK (default: 3)
	PcapThreshold      int            `json:"pcap_threshold"`      // Number of suspicious attempts before PCAP capture (default: 3)
	PortScanThreshold  int            `json:"port_scan_threshold"` // Distinct ports in window before PORT_SCAN alert (default: 5)
	WindowSeconds      int            `json:"window_seconds"`      // Sliding window in seconds (default: 30)
	AutoPcapCapture    bool           `json:"auto_pcap_capture"`   // Enable/disable PCAP capture
	PcapDirectory      string         `json:"pcap_directory"`      // Destination folder for .pcap files
	AutoUnblockMinutes int            `json:"auto_unblock_minutes"`// 0 = never, 5, 15, 60, 1440
	ProtectedPorts     []int          `json:"protected_ports,omitempty"`
}

// DefaultSecurityPolicy returns balanced default protection settings.
func DefaultSecurityPolicy() SecurityPolicyConfig {
	return SecurityPolicyConfig{
		Mode:               ModeThresholdBlock,
		BlockThreshold:     3,
		PcapThreshold:      3,
		PortScanThreshold:  5,
		WindowSeconds:      30,
		AutoPcapCapture:    true,
		PcapDirectory:      "data/pcaps",
		AutoUnblockMinutes: 15,
		ProtectedPorts:     []int{445, 135, 139, 3389, 22, 23, 5353},
	}
}

// SecurityAuditRequest represents a unified connection audit payload for both Android and PC.
type SecurityAuditRequest struct {
	CallerID        string                `json:"caller_id"`        // Android: package/UID, PC: process_name/user
	ExecutablePath  string                `json:"executable_path,omitempty"` // Absolute disk path of binary (e.g. C:\Windows\System32\svchost.exe)
	DestinationIP   string                `json:"destination_ip"`
	DestinationHost string                `json:"destination_host,omitempty"`
	Port            int                   `json:"port"`
	Protocol        string                `json:"protocol"`         // "TCP", "UDP", "ICMP"
	AuditPorts      []int                 `json:"audit_ports,omitempty"`
	IsExplicitBlock bool                  `json:"is_explicit_block,omitempty"`
	Platform        string                `json:"platform,omitempty"` // "windows", "android", "linux"
	PolicyOverride  *SecurityPolicyConfig `json:"policy_override,omitempty"`
}

// SecurityAuditVerdict contains the unified security verdict.
type SecurityAuditVerdict struct {
	IsBlocked      bool                 `json:"is_blocked"`
	ShouldBlock    bool                 `json:"should_block"`
	ThreatDetected bool                 `json:"threat_detected"`
	ThreatType     ThreatClassification `json:"threat_type"`
	Description    string               `json:"description"`
	Action         string               `json:"action"` // "BLOCK", "ALLOW", "ALERT"
	RiskScore      int                  `json:"risk_score"`
	AttemptCount   int                  `json:"attempt_count"`
	Threshold      int                  `json:"threshold"`
	Timestamp      int64                `json:"timestamp"`
	PcapCaptured   bool                 `json:"pcap_captured,omitempty"`
	PcapFilePath   string               `json:"pcap_file_path,omitempty"`
}

type entityConnEntry struct {
	Timestamp     time.Time
	DestinationIP string
	Port          int
}

type entitySecurityProfile struct {
	CallerID       string
	RiskScore      int
	ThreatCount    int
	LastSeen       time.Time
	ProbedPorts    map[int]time.Time
	RecentAttempts []entityConnEntry
	PcapCaptured   bool
	PcapFilePath   string
}

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

// GetBlockedEntities returns all currently quarantined processes/packages.
func (e *UnifiedSecurityEngine) GetBlockedEntities() []*BannedEntity {
	e.mu.RLock()
	defer e.mu.RUnlock()
	list := make([]*BannedEntity, 0, len(e.bannedEntities))
	for _, b := range e.bannedEntities {
		list = append(list, b)
	}
	return list
}

// UnblockEntity removes a quarantined entity by caller ID.
func (e *UnifiedSecurityEngine) UnblockEntity(callerID string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.bannedEntities, callerID)
	if p, ok := e.profiles[callerID]; ok {
		p.ThreatCount = 0
		p.RiskScore = 0
	}
}

// UnblockAllEntities clears all quarantines.
func (e *UnifiedSecurityEngine) UnblockAllEntities() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.bannedEntities = make(map[string]*BannedEntity)
	for _, p := range e.profiles {
		p.ThreatCount = 0
		p.RiskScore = 0
	}
}

// IsEntityBlocked checks if an entity is currently quarantined.
func (e *UnifiedSecurityEngine) IsEntityBlocked(callerID string) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	_, exists := e.bannedEntities[callerID]
	return exists
}

// EnsureActivePcapSession starts a 5-minute forensic session if none is active, returning the active PCAP file path.
func (e *UnifiedSecurityEngine) EnsureActivePcapSession(reason string, policy SecurityPolicyConfig, now time.Time) string {
	if !policy.AutoPcapCapture {
		return ""
	}
	if now.Before(e.pcapActiveUntil) && e.pcapActiveFile != "" {
		return e.pcapActiveFile
	}

	pcapDir := policy.PcapDirectory
	if pcapDir == "" {
		pcapDir = "data/pcaps"
	}
	_ = os.MkdirAll(pcapDir, 0755)

	e.pcapActiveUntil = now.Add(5 * time.Minute)
	e.pcapActiveReason = reason
	e.pcapActiveFile = filepath.Join(pcapDir, fmt.Sprintf("threat_capture_%s.pcap", now.Format("20060102_150405")))

	f, err := os.OpenFile(e.pcapActiveFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err == nil {
		_ = WritePcapGlobalHeader(f, PCAPLinkTypeRawIP)
		f.Close()
	}

	return e.pcapActiveFile
}

// StartPcapSession starts an active continuous forensic capture session.
func (e *UnifiedSecurityEngine) StartPcapSession(reason string, duration time.Duration) {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := time.Now()
	e.EnsureActivePcapSession(reason, e.policy, now)
	if duration > 0 {
		e.pcapActiveUntil = now.Add(duration)
	}
}

// StopPcapSession stops any active forensic capture session.
func (e *UnifiedSecurityEngine) StopPcapSession() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.pcapActiveUntil = time.Time{}
}

// GetPcapStatus returns the live status of the PCAP capture session.
func (e *UnifiedSecurityEngine) GetPcapStatus() PcapCaptureStatus {
	e.mu.RLock()
	defer e.mu.RUnlock()
	now := time.Now()
	active := now.Before(e.pcapActiveUntil)
	remSec := 0
	if active {
		remSec = int(e.pcapActiveUntil.Sub(now).Seconds())
	}
	return PcapCaptureStatus{
		IsActive:         active,
		Reason:           e.pcapActiveReason,
		FilePath:         e.pcapActiveFile,
		RemainingSeconds: remSec,
	}
}

// IngestCoreLog parses raw core logs, extracts endpoints/PID, audits threat, and records forensics.
func (e *UnifiedSecurityEngine) IngestCoreLog(logLine string) *SecurityAuditVerdict {
	clean := strings.TrimSpace(logLine)
	if clean == "" {
		return nil
	}

	ev, ok := e.singboxParser.ParseLogLine(clean)
	if !ok || ev == nil {
		ev, ok = detector.ParseCoreLogLine("", clean)
	}
	if !ok || ev == nil {
		return nil
	}

	lower := strings.ToLower(clean)
	isBlock := strings.Contains(lower, "outbound/block") || strings.Contains(lower, "action=block") || strings.Contains(lower, "match[block]") || strings.Contains(lower, "ssrf_probe")

	req := SecurityAuditRequest{
		CallerID:        ev.ClientRawID,
		ExecutablePath:  ev.ExecutablePath,
		DestinationIP:   ev.TargetHost,
		DestinationHost: ev.TargetHost,
		Port:            ev.TargetPort,
		Protocol:        "TCP",
		IsExplicitBlock: isBlock,
		Platform:        "windows",
	}

	v := e.AuditConnection(req)
	return &v
}

// Stop halts background tasks.
func (e *UnifiedSecurityEngine) Stop() {
	if e.decayTicker != nil {
		e.decayTicker.Stop()
	}
	close(e.stopChan)
}

func (e *UnifiedSecurityEngine) decayWorker() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			e.mu.Lock()
			now := time.Now()

			// 1. Auto-unblock TTL check for quarantined entities
			if e.policy.AutoUnblockMinutes > 0 {
				ttl := time.Duration(e.policy.AutoUnblockMinutes) * time.Minute
				for id, b := range e.bannedEntities {
					if now.Sub(b.BlockedAt) > ttl {
						delete(e.bannedEntities, id)
					}
				}
			}

			// 2. Risk profile decay
			for id, p := range e.profiles {
				if now.Sub(p.LastSeen) > 10*time.Minute {
					delete(e.profiles, id)
					continue
				}
				if p.RiskScore > 0 {
					p.RiskScore -= 20
					if p.RiskScore < 0 {
						p.RiskScore = 0
					}
				}
				if p.ThreatCount > 0 {
					p.ThreatCount--
				}
			}
			e.mu.Unlock()
		case <-e.stopChan:
			return
		}
	}
}

// IsSafeSystemTraffic checks if a destination is standard web/DNS/LAN infrastructure.
func IsSafeSystemTraffic(destIP, destHost string, port int) bool {
	if port == 53 || port == 80 || port == 443 || port == 853 {
		return true
	}
	if destIP == "127.0.0.1" || destIP == "::1" || destIP == "localhost" || destHost == "localhost" {
		return true
	}
	ip := net.ParseIP(destIP)
	if ip != nil && (ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()) {
		return true
	}
	return false
}

// IsCloudMetadataEndpoint checks for SSRF targets.
func IsCloudMetadataEndpoint(destIP, destHost string) bool {
	if destIP == "169.254.169.254" || destIP == "100.100.100.200" {
		return true
	}
	if strings.Contains(destHost, "metadata.google.internal") || strings.Contains(destHost, "169.254.169.254") {
		return true
	}
	return false
}

// IsMasqueradedSystemProcess detects MITRE ATT&CK T1036 (Masquerading / Fake System Executables).
func IsMasqueradedSystemProcess(callerID, fullPath string) (bool, string) {
	name := strings.ToLower(filepath.Base(callerID))
	path := strings.ToLower(filepath.ToSlash(fullPath))

	systemBinaries := map[string]string{
		"svchost.exe":   "system32",
		"csrss.exe":     "system32",
		"lsass.exe":     "system32",
		"services.exe":  "system32",
		"smss.exe":      "system32",
		"taskhostw.exe": "system32",
		"dwm.exe":       "system32",
		"conhost.exe":   "system32",
		"explorer.exe":  "windows",
	}

	expectedSubdir, isSysBin := systemBinaries[name]
	if !isSysBin || path == "" {
		return false, ""
	}

	// Genuine system paths must be within C:/windows or C:/windows/system32
	if expectedSubdir == "system32" {
		if strings.Contains(path, "/windows/system32/") || strings.Contains(path, "/windows/syswow64/") {
			return false, ""
		}
	} else if expectedSubdir == "windows" {
		if strings.Contains(path, "/windows/") && !strings.Contains(path, "/users/") && !strings.Contains(path, "/temp/") && !strings.Contains(path, "/appdata/") {
			return false, ""
		}
	}

	return true, fmt.Sprintf("MITRE T1036: Маскировка процесса! Вредоносный бинарник '%s' запущен вне системной директории Windows (%s)", name, fullPath)
}

// isProtectedSystemEntity ensures ONLY genuinely verified OS components are immune to broad quarantine.
func isProtectedSystemEntity(caller, execPath string) bool {
	clean := strings.ToLower(strings.TrimSpace(caller))
	switch clean {
	case "", "defaultentity", "unknown", "pending", "127.0.0.1", "::1":
		return true
	case "system", "system.exe", "kernel", "ntoskrnl.exe":
		return execPath == "" || !strings.Contains(strings.ToLower(execPath), "/users/")
	case "svchost.exe", "csrss.exe", "lsass.exe", "services.exe", "smss.exe", "taskhostw.exe", "dwm.exe", "conhost.exe":
		p := strings.ToLower(filepath.ToSlash(execPath))
		return p == "" || strings.Contains(p, "/windows/system32/") || strings.Contains(p, "/windows/syswow64/")
	case "explorer.exe":
		p := strings.ToLower(filepath.ToSlash(execPath))
		return p == "" || (strings.Contains(p, "/windows/") && !strings.Contains(p, "/users/") && !strings.Contains(p, "/temp/") && !strings.Contains(p, "/appdata/"))
	default:
		return false
	}
}

// AuditConnection executes comprehensive threat auditing on any incoming socket or log event.
func (e *UnifiedSecurityEngine) AuditConnection(req SecurityAuditRequest) SecurityAuditVerdict {
	now := time.Now()
	nowMs := now.UnixMilli()

	caller := strings.TrimSpace(req.CallerID)
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
			IsBlocked:      true,
			ShouldBlock:    true,
			ThreatDetected: true,
			ThreatType:     ThreatCoreBlocked,
			Description:    fmt.Sprintf("Process '%s' is in Zero Trust isolation", caller),
			Action:         "BLOCK",
			RiskScore:      100,
			Timestamp:      nowMs,
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

	// 2. Explicit Core Block Rule triggered for non-shielded port (Outbound Block / Reject from Core)
	if req.IsExplicitBlock && !isSensitive {
		v := SecurityAuditVerdict{
			IsBlocked:      true,
			ShouldBlock:    true,
			ThreatDetected: true,
			ThreatType:     ThreatCoreBlocked,
			Description:    fmt.Sprintf("Explicit Zero Trust security rule dropped connection to %s:%d", req.DestinationIP, req.Port),
			Action:         "BLOCK",
			RiskScore:      90,
			Timestamp:      nowMs,
		}
		e.handlePcapAndProfile(caller, &v, req, policy, now, nowMs)
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
		if blockLimit <= 0 {
			blockLimit = 3
		}

		shouldBlock := false
		action := "ALERT"

		switch policy.Mode {
		case ModeStrictBlock:
			shouldBlock = true
			action = "BLOCK"
		case ModeAlertOnly:
			shouldBlock = false
			action = "ALERT"
		case ModeThresholdBlock:
			fallthrough
		default:
			if attemptCount >= blockLimit {
				shouldBlock = true
				action = "BLOCK"
			} else {
				shouldBlock = false
				action = "ALERT"
			}
		}

		if isSystem {
			shouldBlock = false
			action = "ALERT"
		}

		var desc string
		if shouldBlock {
			desc = fmt.Sprintf("Shielded sensitive port %d blocked (policy %s: attempt %d/%d)", req.Port, policy.Mode, attemptCount, blockLimit)
		} else {
			desc = fmt.Sprintf("Shielded sensitive port %d probe detected (attempt %d/%d)", req.Port, attemptCount, blockLimit)
		}

		verdict = SecurityAuditVerdict{
			IsBlocked:      shouldBlock,
			ShouldBlock:    shouldBlock,
			ThreatDetected: true,
			ThreatType:     ThreatSensitivePort,
			Description:    desc,
			Action:         action,
			RiskScore:      profile.RiskScore,
			AttemptCount:   attemptCount,
			Threshold:      blockLimit,
			Timestamp:      nowMs,
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

// Helper to deserialize policy
func ParseSecurityPolicy(jsonStr string) (SecurityPolicyConfig, error) {
	var cfg SecurityPolicyConfig
	err := json.Unmarshal([]byte(jsonStr), &cfg)
	return cfg, err
}
