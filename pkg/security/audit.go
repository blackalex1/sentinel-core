package security

import (
	"encoding/json"
	"fmt"
	"net"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
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
)

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
	Mode              PortShieldMode `json:"mode"`                // "threshold_block", "strict_block", "alert_only"
	BlockThreshold    int            `json:"block_threshold"`    // Number of suspicious attempts before BLOCK (default: 3)
	PcapThreshold     int            `json:"pcap_threshold"`     // Number of suspicious attempts before PCAP capture (default: 3)
	PortScanThreshold int            `json:"port_scan_threshold"`// Distinct ports in window before PORT_SCAN alert (default: 5)
	WindowSeconds     int            `json:"window_seconds"`     // Sliding window in seconds (default: 30)
	AutoPcapCapture   bool           `json:"auto_pcap_capture"`  // Enable/disable PCAP capture
	PcapDirectory     string         `json:"pcap_directory"`     // Destination folder for .pcap files
	ProtectedPorts    []int          `json:"protected_ports,omitempty"`
}

// DefaultSecurityPolicy returns balanced default protection settings.
func DefaultSecurityPolicy() SecurityPolicyConfig {
	return SecurityPolicyConfig{
		Mode:              ModeThresholdBlock,
		BlockThreshold:    3,
		PcapThreshold:     3,
		PortScanThreshold: 5,
		WindowSeconds:     30,
		AutoPcapCapture:   true,
		PcapDirectory:     "",
		ProtectedPorts:    []int{445, 135, 139, 3389, 22, 23, 5353},
	}
}

// SecurityAuditRequest represents a unified connection audit payload for both Android and PC.
type SecurityAuditRequest struct {
	CallerID        string                `json:"caller_id"`        // Android: package/UID, PC: process_name/user
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
	mu          sync.RWMutex
	profiles    map[string]*entitySecurityProfile
	decayTicker *time.Ticker
	stopChan    chan struct{}
	policy      SecurityPolicyConfig
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
		profiles:    make(map[string]*entitySecurityProfile),
		decayTicker: time.NewTicker(decayInterval),
		stopChan:    make(chan struct{}),
		policy:      DefaultSecurityPolicy(),
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

// Stop halts background tasks.
func (e *UnifiedSecurityEngine) Stop() {
	if e.decayTicker != nil {
		e.decayTicker.Stop()
	}
	close(e.stopChan)
}

func (e *UnifiedSecurityEngine) decayWorker() {
	for {
		select {
		case <-e.decayTicker.C:
			e.mu.Lock()
			now := time.Now()
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

// AuditConnection executes comprehensive threat auditing on any incoming socket or log event.
func (e *UnifiedSecurityEngine) AuditConnection(req SecurityAuditRequest) SecurityAuditVerdict {
	now := time.Now()
	nowMs := now.UnixMilli()

	caller := strings.TrimSpace(req.CallerID)
	if caller == "" {
		caller = "DefaultEntity"
	}

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

	// 2. Explicit Core Block Rule triggered (Outbound Block / Reject from Core)
	if req.IsExplicitBlock {
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

	// 3. Safe Web/DNS/LAN traffic whitelist (prevent false positives)
	if IsSafeSystemTraffic(req.DestinationIP, req.DestinationHost, req.Port) {
		return SecurityAuditVerdict{
			IsBlocked:      false,
			ShouldBlock:    false,
			ThreatDetected: false,
			ThreatType:     ThreatNone,
			Description:    "Standard safe network traffic",
			Action:         "ALLOW",
			RiskScore:      0,
			Timestamp:      nowMs,
		}
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
	if req.Port > 0 {
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

		verdict = SecurityAuditVerdict{
			IsBlocked:      policy.Mode == ModeStrictBlock,
			ShouldBlock:    policy.Mode == ModeStrictBlock,
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
		return SecurityAuditVerdict{
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

	// Trigger automated PCAP recording if configured
	if verdict.ThreatDetected && policy.AutoPcapCapture && policy.PcapDirectory != "" {
		if profile.ThreatCount >= policy.PcapThreshold || verdict.ThreatType == ThreatPortScan || verdict.ThreatType == ThreatSSRFProbe {
			cleanCaller := sanitizeFilename(caller)
			pcapFileName := fmt.Sprintf("threat_%s_%d.pcap", cleanCaller, now.Unix())
			pcapPath := filepath.Join(policy.PcapDirectory, pcapFileName)
			srcIP := "10.0.0.2"
			if req.Platform == "windows" {
				srcIP = "127.0.0.1"
			}
			err := SynthesizeAndRecordThreatPcap(pcapPath, req.Protocol, srcIP, 54321, req.DestinationIP, req.Port, string(verdict.ThreatType), nowMs)
			if err == nil {
				verdict.PcapCaptured = true
				verdict.PcapFilePath = pcapPath
				profile.PcapCaptured = true
				profile.PcapFilePath = pcapPath
			}
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

	if policy.AutoPcapCapture && policy.PcapDirectory != "" {
		cleanCaller := sanitizeFilename(caller)
		pcapFileName := fmt.Sprintf("threat_%s_%d.pcap", cleanCaller, now.Unix())
		pcapPath := filepath.Join(policy.PcapDirectory, pcapFileName)
		srcIP := "10.0.0.2"
		if req.Platform == "windows" {
			srcIP = "127.0.0.1"
		}
		err := SynthesizeAndRecordThreatPcap(pcapPath, req.Protocol, srcIP, 54321, req.DestinationIP, req.Port, string(v.ThreatType), nowMs)
		if err == nil {
			v.PcapCaptured = true
			v.PcapFilePath = pcapPath
			profile.PcapCaptured = true
			profile.PcapFilePath = pcapPath
		}
	}
}

// Helper to deserialize policy
func ParseSecurityPolicy(jsonStr string) (SecurityPolicyConfig, error) {
	var cfg SecurityPolicyConfig
	err := json.Unmarshal([]byte(jsonStr), &cfg)
	return cfg, err
}
