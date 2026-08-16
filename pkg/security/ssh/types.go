package ssh

import "time"

// SSHEventType defines the type of SSH / Host authentication event.
type SSHEventType string

const (
	EventSSHLogin      SSHEventType = "SSH_LOGIN"
	EventSSHLogout     SSHEventType = "SSH_LOGOUT"
	EventSSHFailedAuth SSHEventType = "SSH_FAILED_AUTH"
	EventSudoExec      SSHEventType = "SUDO_EXEC"
	EventPVEWebLogin   SSHEventType = "PVE_WEB_LOGIN"
	EventPVEWebFail    SSHEventType = "PVE_WEB_FAIL"
)

// SSHEvent represents a parsed and normalized authentication event from the system.
type SSHEvent struct {
	Timestamp      time.Time    `json:"timestamp"`
	Type           SSHEventType `json:"type"`
	User           string       `json:"user"`
	RunAs          string       `json:"run_as,omitempty"` // For sudo events
	SourceIP       string       `json:"source_ip"`
	Port           int          `json:"port,omitempty"`
	PID            int          `json:"pid,omitempty"`
	AuthMethod     string       `json:"auth_method,omitempty"` // password, publickey
	KeyFingerprint string       `json:"key_fingerprint,omitempty"`
	Command        string       `json:"command,omitempty"`     // For sudo commands
	Duration       string       `json:"duration,omitempty"`    // Formatted session duration for logout
	DurationSec    int64        `json:"duration_sec,omitempty"`
	Reason         string       `json:"reason,omitempty"`
	RawLine        string       `json:"raw_line,omitempty"`
}

// SSHSession represents an active, currently connected SSH login session.
type SSHSession struct {
	PID            int       `json:"pid"`
	User           string    `json:"user"`
	SourceIP       string    `json:"source_ip"`
	Port           int       `json:"port"`
	AuthMethod     string    `json:"auth_method"`
	KeyFingerprint string    `json:"key_fingerprint,omitempty"`
	LoginTime      time.Time `json:"login_time"`
}
