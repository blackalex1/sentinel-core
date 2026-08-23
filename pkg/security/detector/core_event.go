package detector

// ParsedLogEvent represents a normalized threat event extracted from any core's logs.
type ParsedLogEvent struct {
	CoreName     string `json:"core_name"`     // sing-box, xray, hysteria2
	ClientRawID    string `json:"client_raw_id"` // email, uuid, username, or client IP
	ClientIP       string `json:"client_ip"`
	ExecutablePath string `json:"executable_path,omitempty"`
	TargetHost     string `json:"target_host"`
	TargetPort   int    `json:"target_port"`
	EventType    string `json:"event_type"` // SENSITIVE_PORT_PROBE, AUTH_FAIL, SSRF_PROBE, MALWARE_HIT
	RawLine      string `json:"raw_line"`
}

// CoreLogParser defines the contract for core-specific log analyzers.
type CoreLogParser interface {
	CoreName() string
	ParseLogLine(line string) (*ParsedLogEvent, bool)
}
