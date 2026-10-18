package security

import (
	"strings"
	"testing"
)

func TestValidateRemoteClientID(t *testing.T) {
	validIDs := []string{
		"alice",
		"client-1",
		"user_123",
		"dev.user",
		"user@example.com",
		"user:100",
		"12345",
	}

	for _, id := range validIDs {
		if err := ValidateRemoteClientID(id); err != nil {
			t.Errorf("expected %q to be valid, got: %v", id, err)
		}
	}

	invalidIDs := []string{
		"",                                   // empty
		"-maliciousFlag",                     // leading hyphen
		"--client=evil",                      // flag injection
		"user; rm -rf /",                     // command separator
		"user && reboot",                     // command chaining
		"user || false",                      // logic operator
		"user | ls",                          // pipe
		"user`whoami`",                       // backtick execution
		"user$(id)",                          // command substitution
		"user$VAR",                           // variable expansion
		"user name",                          // space
		"user\nname",                         // newline
		"user\tname",                         // tab
		"user'name",                          // quote
		"user\"name",                         // double quote
		strings.Repeat("a", 257),             // exceeds 256 bytes
	}

	for _, id := range invalidIDs {
		if err := ValidateRemoteClientID(id); err == nil {
			t.Errorf("expected %q to be rejected, but it was accepted", id)
		}
	}
}

func TestShellEscape(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"simple", "'simple'"},
		{"can't stop", "'can'\\''t stop'"},
		{"$USER $(whoami) `id`", "'$USER $(whoami) `id`'"},
		{"with\x00null", "'withnull'"},
		{"", "''"},
	}

	for _, tc := range tests {
		actual := ShellEscape(tc.input)
		if actual != tc.expected {
			t.Errorf("ShellEscape(%q) = %q; want %q", tc.input, actual, tc.expected)
		}
	}
}

func TestBuildRemoteNodeSSHArgs(t *testing.T) {
	// 1. Valid invocation
	args, err := BuildRemoteNodeSSHArgs("192.168.1.10", 2222, "admin", "/home/user/.ssh/id_ed25519", "sentinel-core status")
	if err != nil {
		t.Fatalf("unexpected error for valid args: %v", err)
	}

	// Verify security hardening flags
	hasAcceptNew := false
	hasBatchMode := false
	delimiterIdx := -1
	targetIdx := -1
	cmdIdx := -1

	for i, a := range args {
		if a == "StrictHostKeyChecking=accept-new" {
			hasAcceptNew = true
		}
		if a == "BatchMode=yes" {
			hasBatchMode = true
		}
		if a == "--" {
			delimiterIdx = i
		}
		if a == "admin@192.168.1.10" {
			targetIdx = i
		}
		if a == "sentinel-core status" {
			cmdIdx = i
		}
	}

	if !hasAcceptNew {
		t.Errorf("missing StrictHostKeyChecking=accept-new flag")
	}
	if !hasBatchMode {
		t.Errorf("missing BatchMode=yes flag")
	}
	if delimiterIdx == -1 {
		t.Fatalf("missing '--' option delimiter")
	}
	if targetIdx != delimiterIdx+1 {
		t.Errorf("target must immediately follow '--', got delimiter at %d and target at %d", delimiterIdx, targetIdx)
	}
	if cmdIdx != delimiterIdx+2 {
		t.Errorf("command must follow target, got command at %d", cmdIdx)
	}

	// 2. Reject option injection in Host
	invalidHosts := []string{"-oProxyCommand=calc", "--proxy", "host; reboot", "host name"}
	for _, h := range invalidHosts {
		if _, err := BuildRemoteNodeSSHArgs(h, 22, "root", "", "ls"); err == nil {
			t.Errorf("expected host %q to be rejected, got nil error", h)
		}
	}

	// 3. Reject option injection in User
	invalidUsers := []string{"-oStrictHostKeyChecking=no", "root; echo evil", "user name"}
	for _, u := range invalidUsers {
		if _, err := BuildRemoteNodeSSHArgs("1.2.3.4", 22, u, "", "ls"); err == nil {
			t.Errorf("expected user %q to be rejected, got nil error", u)
		}
	}

	// 4. Reject option injection in SSHKey
	invalidKeys := []string{"-oProxyCommand=calc", "/path/to/key; rm -rf /", "/path\nto\nkey"}
	for _, k := range invalidKeys {
		if _, err := BuildRemoteNodeSSHArgs("1.2.3.4", 22, "root", k, "ls"); err == nil {
			t.Errorf("expected ssh key %q to be rejected, got nil error", k)
		}
	}
}

func TestRemoteNodeClient_QuarantineClient_Validation(t *testing.T) {
	client := NewRemoteNodeClient("127.0.0.1", 22, "root", "")

	// Malicious client ID should fail immediately before SSH execution
	err := client.QuarantineClient("client; rm -rf /", "suspicious activity")
	if err == nil {
		t.Errorf("expected error for malicious clientID, got nil")
	}
	if !strings.Contains(err.Error(), "invalid clientID") {
		t.Errorf("unexpected error message: %v", err)
	}

	err = client.UnquarantineClient("-flag")
	if err == nil {
		t.Errorf("expected error for hyphenated clientID, got nil")
	}
	if !strings.Contains(err.Error(), "invalid clientID") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestRemoteNodeClient_Methods_ValidationAndExecution(t *testing.T) {
	client := NewRemoteNodeClient("invalid-unreachable-node", 9999, "root", "")

	if err := client.ReloadNodeCores(); err == nil {
		t.Errorf("expected error for ReloadNodeCores on unreachable host")
	}

	if _, err := client.GetSecurityStatus(); err == nil {
		t.Errorf("expected error for GetSecurityStatus on unreachable host")
	}

	if _, err := client.FetchThreatJournal(0); err == nil {
		t.Errorf("expected error for FetchThreatJournal on unreachable host")
	}

	if _, err := client.FetchThreatJournal(20000); err == nil {
		t.Errorf("expected error for FetchThreatJournal with >10000 lines")
	}
}

