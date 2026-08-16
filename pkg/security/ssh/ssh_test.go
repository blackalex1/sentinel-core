package ssh

import (
	"testing"
	"time"
)

type mockJournal struct {
	loggedEvents []string
}

func (m *mockJournal) LogIncident(
	eventType string,
	category string,
	clientID string,
	aliases []string,
	score int,
	status string,
	target string,
	reason string,
	actionTaken string,
) error {
	m.loggedEvents = append(m.loggedEvents, eventType+":"+clientID+":"+actionTaken)
	return nil
}

func TestSSHMonitor_Lifecycle(t *testing.T) {
	journal := &mockJournal{}
	monitor := NewSSHMonitor(journal)

	// 1. Test Login
	loginLine := "Aug 16 01:30:00 server sshd[12345]: Accepted publickey for root from 198.51.100.42 port 54321 ssh2: RSA SHA256:abcd1234efgh"
	ev, ok := monitor.ProcessLogLine(loginLine)
	if !ok || ev == nil {
		t.Fatalf("expected login event to be parsed")
	}

	if ev.Type != EventSSHLogin || ev.User != "root" || ev.SourceIP != "198.51.100.42" || ev.PID != 12345 {
		t.Fatalf("unexpected login event fields: %+v", ev)
	}

	if ev.KeyFingerprint != "SHA256:abcd1234efgh" {
		t.Fatalf("expected key fingerprint SHA256:abcd1234efgh, got: %s", ev.KeyFingerprint)
	}

	sessions := monitor.GetActiveSessions()
	if len(sessions) != 1 || sessions[0].PID != 12345 {
		t.Fatalf("expected 1 active session with PID 12345, got: %+v", sessions)
	}

	// 2. Test Logout (Connection Closed)
	time.Sleep(10 * time.Millisecond)
	closeLine := "Aug 16 01:30:05 server sshd[12345]: Connection closed by user root 198.51.100.42 port 54321"
	evClose, okClose := monitor.ProcessLogLine(closeLine)
	if !okClose || evClose == nil {
		t.Fatalf("expected close event to be parsed")
	}

	if evClose.Type != EventSSHLogout || evClose.User != "root" {
		t.Fatalf("unexpected logout event: %+v", evClose)
	}

	sessionsAfter := monitor.GetActiveSessions()
	if len(sessionsAfter) != 0 {
		t.Fatalf("expected 0 active sessions after logout, got %d", len(sessionsAfter))
	}

	// 3. Test Deduplication
	dupLine := "Aug 16 01:30:05 server sshd[12345]: pam_unix(sshd:session): session closed for user root"
	_, okDup := monitor.ProcessLogLine(dupLine)
	if okDup {
		t.Fatalf("expected duplicate close within 3s to be suppressed")
	}
}

func TestSSHParser_FailedAuthAndSudo(t *testing.T) {
	// 1. Failed password
	failLine := "Aug 16 01:31:00 server sshd[9999]: Failed password for invalid user admin from 203.0.113.10 port 44444 ssh2"
	evFail, okFail := ParseAuthLine(failLine)
	if !okFail || evFail.Type != EventSSHFailedAuth || evFail.User != "admin" || evFail.SourceIP != "203.0.113.10" {
		t.Fatalf("expected failed auth for admin, got: %+v", evFail)
	}

	// 2. Sudo execution
	sudoLine := "Aug 16 01:32:00 server sudo:   ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/bin/systemctl restart sing-box"
	evSudo, okSudo := ParseAuthLine(sudoLine)
	if !okSudo || evSudo.Type != EventSudoExec || evSudo.User != "ubuntu" || evSudo.RunAs != "root" {
		t.Fatalf("expected sudo event, got: %+v", evSudo)
	}
}
