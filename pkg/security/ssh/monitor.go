package ssh

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"sync"
	"time"

	"github.com/blackalex1/sentinel-core/pkg/events"
)

// JournalLogger defines the interface for recording SSH events into the threat journal.
type JournalLogger interface {
	LogIncident(
		eventType string,
		category string,
		clientID string,
		aliases []string,
		score int,
		status string,
		target string,
		reason string,
		actionTaken string,
	) error
}

// SSHMonitor manages real-time tracking of SSH logins, logouts, and brute-force attempts.
type SSHMonitor struct {
	mu             sync.RWMutex
	activeSessions map[int]*SSHSession // Keyed by SSHD PID
	recentCloses   map[string]time.Time // Deduplication cache: "pid:user" -> timestamp
	failedAttempts map[string]int      // IP -> failed attempts count
	eventBus       *events.EventBus
	journal        JournalLogger
	onEventHooks   []func(event SSHEvent)
}

// NewSSHMonitor creates a new SSH activity monitor.
func NewSSHMonitor(journal JournalLogger) *SSHMonitor {
	return &SSHMonitor{
		activeSessions: make(map[int]*SSHSession),
		recentCloses:   make(map[string]time.Time),
		failedAttempts: make(map[string]int),
		eventBus:       events.GetGlobalBus(),
		journal:        journal,
		onEventHooks:   make([]func(event SSHEvent), 0),
	}
}

// OnEvent registers a listener for SSH events.
func (m *SSHMonitor) OnEvent(fn func(event SSHEvent)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onEventHooks = append(m.onEventHooks, fn)
}

// ProcessLogLine processes a single log line from auth.log / secure / journalctl.
func (m *SSHMonitor) ProcessLogLine(line string) (*SSHEvent, bool) {
	event, ok := ParseAuthLine(line)
	if !ok || event == nil {
		return nil, false
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()

	switch event.Type {
	case EventSSHLogin:
		// Register active session
		sess := &SSHSession{
			PID:            event.PID,
			User:           event.User,
			SourceIP:       event.SourceIP,
			Port:           event.Port,
			AuthMethod:     event.AuthMethod,
			KeyFingerprint: event.KeyFingerprint,
			LoginTime:      now,
		}
		if event.PID > 0 {
			m.activeSessions[event.PID] = sess
		}
		// Reset failed attempts for this IP on success
		delete(m.failedAttempts, event.SourceIP)

		// Record in journal
		if m.journal != nil {
			_ = m.journal.LogIncident(
				"SSH_LOGIN",
				"AUTH_AUDIT",
				event.User,
				[]string{event.SourceIP, event.KeyFingerprint},
				0,
				"CLEAN",
				fmt.Sprintf("sshd[%d]", event.PID),
				fmt.Sprintf("SSH login via %s from %s:%d", event.AuthMethod, event.SourceIP, event.Port),
				"AUTHORIZED",
			)
		}

	case EventSSHLogout:
		// Check for close deduplication (within 3 seconds)
		dedupKey := fmt.Sprintf("%d:%s", event.PID, event.User)
		if lastClose, exists := m.recentCloses[dedupKey]; exists && now.Sub(lastClose) < 3*time.Second {
			return nil, false
		}
		m.recentCloses[dedupKey] = now

		// Calculate session duration if session was tracked
		if sess, exists := m.activeSessions[event.PID]; exists {
			dur := now.Sub(sess.LoginTime)
			event.DurationSec = int64(dur.Seconds())
			event.Duration = formatDuration(dur)
			if event.SourceIP == "" {
				event.SourceIP = sess.SourceIP
			}
			if event.User == "" {
				event.User = sess.User
			}
			delete(m.activeSessions, event.PID)
		}

		// Record in journal
		if m.journal != nil {
			_ = m.journal.LogIncident(
				"SSH_LOGOUT",
				"AUTH_AUDIT",
				event.User,
				[]string{event.SourceIP},
				0,
				"CLEAN",
				fmt.Sprintf("sshd[%d]", event.PID),
				fmt.Sprintf("SSH session closed (duration: %s)", event.Duration),
				"CLOSED",
			)
		}

	case EventSSHFailedAuth:
		m.failedAttempts[event.SourceIP]++
		count := m.failedAttempts[event.SourceIP]

		// Escalation: If >= 5 failed attempts, mark as brute force
		if count >= 5 && m.journal != nil {
			_ = m.journal.LogIncident(
				"SSH_BRUTE_FORCE",
				"AUTH_ATTACK",
				event.User,
				[]string{event.SourceIP},
				50,
				"SUSPICIOUS",
				fmt.Sprintf("sshd port %d", event.Port),
				fmt.Sprintf("Repeated SSH auth failures (%d attempts) from %s", count, event.SourceIP),
				"FLAGGED",
			)
		}
	}

	// Trigger registered event callbacks
	for _, fn := range m.onEventHooks {
		fn(*event)
	}

	return event, true
}

// GetActiveSessions returns snapshots of all currently open SSH sessions.
func (m *SSHMonitor) GetActiveSessions() []SSHSession {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var sessions []SSHSession
	for _, s := range m.activeSessions {
		sessions = append(sessions, *s)
	}
	return sessions
}

// KillSSHSession forcibly terminates a specific SSH session by PID.
func (m *SSHMonitor) KillSSHSession(pid int) error {
	m.mu.Lock()
	delete(m.activeSessions, pid)
	m.mu.Unlock()

	if runtime.GOOS == "windows" {
		return exec.Command("taskkill", "/F", "/PID", strconv.Itoa(pid)).Run()
	}
	return exec.Command("kill", "-9", strconv.Itoa(pid)).Run()
}

// DetectAuthLogPath returns standard auth log location on Linux.
func DetectAuthLogPath() string {
	candidates := []string{
		"/var/log/auth.log",
		"/var/log/secure",
		"/var/log/messages",
	}
	for _, c := range candidates {
		if fi, err := os.Stat(c); err == nil && !fi.IsDir() {
			return c
		}
	}
	return ""
}

func formatDuration(d time.Duration) string {
	d = d.Round(time.Second)
	h := d / time.Hour
	d -= h * time.Hour
	m := d / time.Minute
	d -= m * time.Minute
	s := d / time.Second

	if h > 0 {
		return fmt.Sprintf("%dh %dm %ds", h, m, s)
	}
	if m > 0 {
		return fmt.Sprintf("%dm %ds", m, s)
	}
	return fmt.Sprintf("%ds", s)
}
