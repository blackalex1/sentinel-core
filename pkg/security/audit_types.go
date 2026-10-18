package security

import (
	"encoding/json"
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

// ParseSecurityPolicy deserializes a JSON policy string into SecurityPolicyConfig.
func ParseSecurityPolicy(jsonStr string) (SecurityPolicyConfig, error) {
	var cfg SecurityPolicyConfig
	err := json.Unmarshal([]byte(jsonStr), &cfg)
	return cfg, err
}

// SecurityAuditRequest represents a unified connection audit payload for both Android and PC.
type SecurityAuditRequest struct {
	CallerID        string                `json:"caller_id"`        // Android: package/UID, PC: process_name/user
	PackageName     string                `json:"package_name,omitempty"` // Android alias for CallerID
	AppName         string                `json:"app_name,omitempty"`
	ExecutablePath  string                `json:"executable_path,omitempty"` // Absolute disk path of binary (e.g. C:\Windows\System32\svchost.exe)
	DestinationIP   string                `json:"destination_ip"`
	DestinationHost string                `json:"destination_host,omitempty"`
	Port            int                   `json:"port"`
	Protocol        string                `json:"protocol"`         // "TCP", "UDP", "ICMP"
	AuditPorts      []int                 `json:"audit_ports,omitempty"`
	MaxThreshold    int                   `json:"max_threshold,omitempty"`
	IsExplicitBlock bool                  `json:"is_explicit_block,omitempty"`
	Platform        string                `json:"platform,omitempty"` // "windows", "android", "linux"
	PolicyOverride  *SecurityPolicyConfig `json:"policy_override,omitempty"`
}

// SecurityAuditVerdict contains the unified security verdict.
type SecurityAuditVerdict struct {
	IsBlocked       bool                 `json:"is_blocked"`
	ShouldBlock     bool                 `json:"should_block"`
	IsSystemFlagged bool                 `json:"is_system_flagged"`
	ThreatDetected  bool                 `json:"threat_detected"`
	ThreatType      ThreatClassification `json:"threat_type"`
	Description     string               `json:"description"`
	Action          string               `json:"action"` // "BLOCK", "ALLOW", "ALERT", "FLAG_SYSTEM"
	RiskScore       int                  `json:"risk_score"`
	AttemptCount    int                  `json:"attempt_count"`
	AttemptsCount   int                  `json:"attempts_count"`
	Threshold       int                  `json:"threshold"`
	Timestamp       int64                `json:"timestamp"`
	PcapCaptured    bool                 `json:"pcap_captured,omitempty"`
	PcapFilePath    string               `json:"pcap_file_path,omitempty"`
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
