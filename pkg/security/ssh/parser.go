package ssh

import (
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	// 1. SSH Accepted login
	// sshd[12345]: Accepted publickey for root from 1.2.3.4 port 54321 ssh2: RSA SHA256:abc...
	// sshd-session[12345]: Accepted password for ubuntu from 1.2.3.4 port 54321 ssh2
	sshAcceptedRegex = regexp.MustCompile(`sshd(?:-session)?\[(\d+)\]:\s+Accepted\s+(password|publickey)\s+for\s+(\S+)\s+from\s+(\S+)\s+port\s+(\d+)(?:\s+ssh2:\s+\S+\s+(\S+))?`)

	// 2. SSH Failed password / publickey
	// sshd[12345]: Failed password for invalid user admin from 1.2.3.4 port 54321 ssh2
	// sshd[12345]: Failed publickey for root from 1.2.3.4 port 54321 ssh2
	sshFailedRegex = regexp.MustCompile(`sshd(?:-session)?\[(?:\d+)?\]:\s+Failed\s+(password|publickey)\s+for\s+(?:invalid user\s+)?(\S+)\s+from\s+(\S+)\s+port\s+(\d+)`)

	// 3. SSH Connection closed by user / authenticating user
	// sshd[12345]: Connection closed by user root 1.2.3.4 port 54321
	// sshd[12345]: Connection closed by authenticating user root 1.2.3.4 port 54321 [preauth]
	sshConnClosedRegex = regexp.MustCompile(`sshd(?:-session)?\[(\d+)\]:\s+Connection closed by (?:user|authenticating user)\s+(\S+)\s+(\S+)\s+port\s+(\d+)`)

	// 4. SSH pam_unix session closed
	// sshd[12345]: pam_unix(sshd:session): session closed for user root
	sshPamClosedRegex = regexp.MustCompile(`sshd(?:-session)?\[(\d+)\]:\s+pam_unix\(sshd:session\):\s+session closed for user\s+(\S+)`)

	// 5. SSH Disconnected from user
	// sshd[12345]: Disconnected from user root 1.2.3.4 port 54321
	sshDisconnectedRegex = regexp.MustCompile(`sshd(?:-session)?\[(\d+)\]:\s+Disconnected from (?:user\s+)?(\S+)\s+(\S+)\s+port\s+(\d+)`)

	// 6. Sudo execution
	// sudo:   ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/bin/systemctl restart sing-box
	sudoRegex = regexp.MustCompile(`sudo:\s+(\S+)\s+:.*?USER=(\S+)\s+;.*?COMMAND=(.*)`)

	// 7. Proxmox VE Web GUI auth
	// pvedaemon[1234]: <root@pam> successful auth for user 'root@pam'
	pveWebOkRegex = regexp.MustCompile(`pvedaemon\[\d+\]:\s+<(\S+)> successful auth for user '(\S+)'`)
	// pvedaemon[1234]: authentication failure; rhost=1.2.3.4 user=root@pam msg=...
	pveWebFailRegex = regexp.MustCompile(`pvedaemon\[\d+\]:\s+authentication failure;\s+rhost=(?:::ffff:)?(\S+)\s+user=(\S+)\s+msg=(.*)`)
)

// ParseAuthLine parses a single auth log line and returns an SSHEvent if recognized.
func ParseAuthLine(line string) (*SSHEvent, bool) {
	clean := strings.TrimSpace(line)
	if clean == "" {
		return nil, false
	}

	now := time.Now()

	// 1. Check SSH Login (Accepted)
	if matches := sshAcceptedRegex.FindStringSubmatch(clean); len(matches) >= 6 {
		pid, _ := strconv.Atoi(matches[1])
		method := matches[2]
		user := matches[3]
		ip := matches[4]
		port, _ := strconv.Atoi(matches[5])
		fingerprint := matches[6]

		return &SSHEvent{
			Timestamp:      now,
			Type:           EventSSHLogin,
			User:           user,
			SourceIP:       ip,
			Port:           port,
			PID:            pid,
			AuthMethod:     method,
			KeyFingerprint: fingerprint,
			RawLine:        clean,
		}, true
	}

	// 2. Check SSH Failed login
	if matches := sshFailedRegex.FindStringSubmatch(clean); len(matches) >= 5 {
		method := matches[1]
		user := matches[2]
		ip := matches[3]
		port, _ := strconv.Atoi(matches[4])

		return &SSHEvent{
			Timestamp:  now,
			Type:       EventSSHFailedAuth,
			User:       user,
			SourceIP:   ip,
			Port:       port,
			AuthMethod: method,
			Reason:     "Failed " + method + " for user " + user,
			RawLine:    clean,
		}, true
	}

	// 3. Check SSH Connection Closed
	if matches := sshConnClosedRegex.FindStringSubmatch(clean); len(matches) >= 5 {
		pid, _ := strconv.Atoi(matches[1])
		user := matches[2]
		ip := matches[3]
		port, _ := strconv.Atoi(matches[4])

		return &SSHEvent{
			Timestamp: now,
			Type:      EventSSHLogout,
			User:      user,
			SourceIP:  ip,
			Port:      port,
			PID:       pid,
			RawLine:   clean,
		}, true
	}

	// 4. Check SSH pam session closed
	if matches := sshPamClosedRegex.FindStringSubmatch(clean); len(matches) >= 3 {
		pid, _ := strconv.Atoi(matches[1])
		user := matches[2]

		return &SSHEvent{
			Timestamp: now,
			Type:      EventSSHLogout,
			User:      user,
			PID:       pid,
			RawLine:   clean,
		}, true
	}

	// 5. Check SSH Disconnected
	if matches := sshDisconnectedRegex.FindStringSubmatch(clean); len(matches) >= 5 {
		pid, _ := strconv.Atoi(matches[1])
		user := matches[2]
		ip := matches[3]
		port, _ := strconv.Atoi(matches[4])

		return &SSHEvent{
			Timestamp: now,
			Type:      EventSSHLogout,
			User:      user,
			SourceIP:  ip,
			Port:      port,
			PID:       pid,
			RawLine:   clean,
		}, true
	}

	// 6. Check Sudo execution
	if matches := sudoRegex.FindStringSubmatch(clean); len(matches) >= 4 {
		user := matches[1]
		runAs := matches[2]
		cmd := strings.TrimSpace(matches[3])

		return &SSHEvent{
			Timestamp: now,
			Type:      EventSudoExec,
			User:      user,
			RunAs:     runAs,
			SourceIP:  "LOCAL",
			Command:   cmd,
			RawLine:   clean,
		}, true
	}

	// 7. Check Proxmox Web GUI
	if matches := pveWebOkRegex.FindStringSubmatch(clean); len(matches) >= 3 {
		user := matches[2]
		return &SSHEvent{
			Timestamp:  now,
			Type:       EventPVEWebLogin,
			User:       user,
			SourceIP:   "WEB_GUI",
			AuthMethod: "cookie/token",
			RawLine:    clean,
		}, true
	}

	if matches := pveWebFailRegex.FindStringSubmatch(clean); len(matches) >= 4 {
		ip := matches[1]
		user := matches[2]
		reason := matches[3]

		return &SSHEvent{
			Timestamp: now,
			Type:      EventPVEWebFail,
			User:      user,
			SourceIP:  ip,
			Reason:    reason,
			RawLine:   clean,
		}, true
	}

	return nil, false
}
