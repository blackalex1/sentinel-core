package security

import (
	"bytes"
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

// QuarantineClient instructs the remote node to isolate and kick a compromised client.
func (c *RemoteNodeClient) QuarantineClient(clientID, reason string) error {
	cmdStr := fmt.Sprintf("sentinel-core security quarantine --client=%s --reason=%q", clientID, reason)
	_, err := c.runSSHCommand(cmdStr)
	return err
}

// UnquarantineClient instructs the remote node to release a client from quarantine.
func (c *RemoteNodeClient) UnquarantineClient(clientID string) error {
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
	args := []string{
		"-p", strconv.Itoa(c.Port),
		"-o", "BatchMode=yes",
		"-o", "StrictHostKeyChecking=no",
		"-o", "ConnectTimeout=5",
	}

	if c.SSHKey != "" {
		args = append(args, "-i", c.SSHKey)
	}

	target := fmt.Sprintf("%s@%s", c.User, c.Host)
	args = append(args, target, remoteCmd)

	cmd := exec.Command("ssh", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	done := make(chan error, 1)
	go func() {
		done <- cmd.Run()
	}()

	select {
	case err := <-done:
		if err != nil {
			return "", fmt.Errorf("ssh command failed: %w (stderr: %s)", err, strings.TrimSpace(stderr.String()))
		}
		return strings.TrimSpace(stdout.String()), nil
	case <-time.After(10 * time.Second):
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		return "", fmt.Errorf("ssh command timed out")
	}
}
