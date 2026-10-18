package security

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// NodeSecuritySummary represents high-level security state reported by a remote node.
type NodeSecuritySummary struct {
	NodeID              string                  `json:"node_id"`
	QuarantinedClients  []string                `json:"quarantined_clients"`
	SuspiciousClients   []SuspiciousClientEntry `json:"suspicious_clients"`
	Stats               SecurityStats           `json:"stats"`
	Timestamp           int64                   `json:"timestamp"`
}

// SuspiciousClientEntry describes a client with elevated risk score.
type SuspiciousClientEntry struct {
	ClientID  string `json:"client_id"`
	RiskScore int    `json:"risk_score"`
	Status    string `json:"status"`
}

// RemoteNodeClient connects from the Master server to remote edge nodes via SSH.
type RemoteNodeClient struct {
	Host     string
	Port     int
	User     string
	SSHKey   string
	Password string
}

// NewRemoteNodeClient creates a remote node SSH controller.
func NewRemoteNodeClient(host string, port int, user string, sshKey string) *RemoteNodeClient {
	if port <= 0 {
		port = 22
	}
	if user == "" {
		user = "root"
	}
	return &RemoteNodeClient{
		Host:   host,
		Port:   port,
		User:   user,
		SSHKey: sshKey,
	}
}

// ValidateRemoteClientID verifies that a clientID consists only of safe identifier characters
// and cannot be abused for command or flag injection.
func ValidateRemoteClientID(clientID string) error {
	if clientID == "" {
		return fmt.Errorf("clientID cannot be empty")
	}
	if len(clientID) > 256 {
		return fmt.Errorf("clientID exceeds maximum length of 256")
	}
	if strings.HasPrefix(clientID, "-") {
		return fmt.Errorf("clientID cannot start with hyphen: %q", clientID)
	}
	for _, r := range clientID {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' || r == '@' || r == ':') {
			return fmt.Errorf("invalid character %q in clientID: %q", r, clientID)
		}
	}
	return nil
}

// ShellEscape escapes a string for safe inclusion in a POSIX shell command argument.
func ShellEscape(s string) string {
	s = strings.ReplaceAll(s, "\x00", "")
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// BuildRemoteNodeSSHArgs validates connection parameters and generates OpenSSH arguments safely,
// defending against OpenSSH flag/option injection (CWE-88) and command injection.
func BuildRemoteNodeSSHArgs(host string, port int, user string, sshKey string, remoteCmd string) ([]string, error) {
	if host == "" {
		return nil, fmt.Errorf("empty ssh host")
	}
	if strings.HasPrefix(host, "-") || strings.ContainsAny(host, " \t\r\n'\"`;&|$(){}") {
		return nil, fmt.Errorf("invalid or insecure ssh host: %q", host)
	}

	if user == "" {
		user = "root"
	}
	if strings.HasPrefix(user, "-") || strings.ContainsAny(user, " \t\r\n'\"`;&|$(){}") {
		return nil, fmt.Errorf("invalid or insecure ssh user: %q", user)
	}

	if port <= 0 {
		port = 22
	}

	args := []string{
		"-p", strconv.Itoa(port),
		"-o", "BatchMode=yes",
		"-o", "StrictHostKeyChecking=accept-new",
		"-o", "ConnectTimeout=5",
	}

	if sshKey != "" {
		if strings.HasPrefix(sshKey, "-") || strings.ContainsAny(sshKey, "\r\n'\"`;&|$(){}") {
			return nil, fmt.Errorf("invalid or insecure ssh key path: %q", sshKey)
		}
		args = append(args, "-i", sshKey)
	}

	target := fmt.Sprintf("%s@%s", user, host)
	// Use -- delimiter to prevent target from being parsed as an OpenSSH option
	args = append(args, "--", target, remoteCmd)
	return args, nil
}

// QuarantineClient instructs the remote node to isolate and kick a compromised client.
func (c *RemoteNodeClient) QuarantineClient(clientID, reason string) error {
	if err := ValidateRemoteClientID(clientID); err != nil {
		return fmt.Errorf("invalid clientID: %w", err)
	}
	escapedReason := ShellEscape(reason)
	cmdStr := fmt.Sprintf("sentinel-core security quarantine --client=%s --reason=%s", clientID, escapedReason)
	_, err := c.runSSHCommand(cmdStr)
	return err
}

// UnquarantineClient instructs the remote node to release a client from quarantine.
func (c *RemoteNodeClient) UnquarantineClient(clientID string) error {
	if err := ValidateRemoteClientID(clientID); err != nil {
		return fmt.Errorf("invalid clientID: %w", err)
	}
	cmdStr := fmt.Sprintf("sentinel-core security unquarantine --client=%s", clientID)
	_, err := c.runSSHCommand(cmdStr)
	return err
}

// GetSecurityStatus retrieves structured threat summary from the remote node.
func (c *RemoteNodeClient) GetSecurityStatus() (*NodeSecuritySummary, error) {
	out, err := c.runSSHCommand("sentinel-core security status")
	if err != nil {
		return nil, err
	}

	var summary NodeSecuritySummary
	if err := json.Unmarshal([]byte(out), &summary); err != nil {
		return nil, fmt.Errorf("failed to parse node status JSON: %w (output: %s)", err, out)
	}

	return &summary, nil
}

// FetchThreatJournal pulls the last N threat records from the remote node's journal.
func (c *RemoteNodeClient) FetchThreatJournal(lines int) ([]ThreatRecord, error) {
	if lines <= 0 {
		lines = 50
	}
	if lines > 10000 {
		lines = 10000
	}
	cmdStr := fmt.Sprintf("sentinel-core security journal --lines=%d", lines)
	out, err := c.runSSHCommand(cmdStr)
	if err != nil {
		return nil, err
	}

	var records []ThreatRecord
	rawLines := strings.Split(out, "\n")
	for _, l := range rawLines {
		clean := strings.TrimSpace(l)
		if clean == "" {
			continue
		}
		var rec ThreatRecord
		if err := json.Unmarshal([]byte(clean), &rec); err == nil {
			records = append(records, rec)
		}
	}

	return records, nil
}

// ReloadNodeCores commands the remote node to reload/restart its proxy engines.
func (c *RemoteNodeClient) ReloadNodeCores() error {
	_, err := c.runSSHCommand("sentinel-core supervisor reload")
	return err
}

func (c *RemoteNodeClient) runSSHCommand(remoteCmd string) (string, error) {
	args, err := BuildRemoteNodeSSHArgs(c.Host, c.Port, c.User, c.SSHKey, remoteCmd)
	if err != nil {
		return "", err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "ssh", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return "", fmt.Errorf("ssh command timed out")
		}
		return "", fmt.Errorf("ssh command failed: %w (stderr: %s)", err, strings.TrimSpace(stderr.String()))
	}
	return strings.TrimSpace(stdout.String()), nil
}
