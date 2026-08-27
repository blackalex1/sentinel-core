package supervisor

import (
	"encoding/json"
	"log"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/blackalex1/sentinel-core/pkg/i18n"
)

// SessionInfo represents an active client connection tracked by sentinel-core.
type SessionInfo struct {
	Email       string `json:"email"`
	IP          string `json:"ip"`
	InboundTag  string `json:"inbound_tag,omitempty"`
	Core        string `json:"core"`
	StartedAt   int64  `json:"started_at"`
	LastSeenAt  int64  `json:"last_seen_at"`
	ConnectedAt string `json:"connected_at"`
}

// SessionEvent represents a connect or disconnect event.
type SessionEvent struct {
	ID        string `json:"id"`
	Action    string `json:"action"` // "connect" or "disconnect"
	Core      string `json:"core"`
	Email     string `json:"email"`
	IP        string `json:"ip"`
	Timestamp int64  `json:"timestamp"`
	TimeStr   string `json:"time_str"`
	Duration  string `json:"duration,omitempty"`
}

// SessionTracker coordinates session tracking and log parsing across all VPN cores.
type SessionTracker struct {
	mu           sync.RWMutex
	sessions     map[string]*SessionInfo // key: "core:email:ip"
	singboxConns map[string]string       // connID -> srcIP
	events       []*SessionEvent
	maxEvents    int
}

var (
	defaultTracker     *SessionTracker
	defaultTrackerOnce sync.Once

	singboxConnIDPattern = regexp.MustCompile(`\[([0-9a-zA-Z_-]+)(?:\s+[^\]]+)?\]`)
	singboxFromPattern   = regexp.MustCompile(`(?:from|client)\s+(?:tcp:|udp:)?\[?([0-9a-fA-F.:]+)\]?(?::\d+)?`)
	singboxUserPattern   = regexp.MustCompile(`(?:\[([^\s,\]]+)\]\s+(?:inbound connection|accepted|router)|(?:user|email)[:=]\s*([^\s,\]]+))`)
	xrayAcceptedPattern  = regexp.MustCompile(`(?:from\s+)?(?:tcp:|udp:)?\[?([0-9a-fA-F.:]+)\]?(?::\d+)?\s+accepted`)
	xrayEmailPattern     = regexp.MustCompile(`email:\s+([^\s,\]]+)`)
	hyTCPRegex           = regexp.MustCompile(`\[(?:TCP|UDP)\]\s+([^\s:]+):\d+\s+->\s+\S+\s+\(user:\s*([^\s\)]+)\)`)
	hyAuthAsRegex        = regexp.MustCompile(`(?:client\s+)?authenticated as\s+([^\s(]+)(?:\s+\(?([^\s:)]+)(?::\d+)?\)?)?`)
	ipCandidatePattern   = regexp.MustCompile(`\b([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})(?::\d+)?\b`)
)

// GetSessionTracker returns the global session tracker singleton.
func GetSessionTracker() *SessionTracker {
	defaultTrackerOnce.Do(func() {
		defaultTracker = &SessionTracker{
			sessions:     make(map[string]*SessionInfo),
			singboxConns: make(map[string]string),
			events:       make([]*SessionEvent, 0, 1000),
			maxEvents:    1000,
		}
		go defaultTracker.inactivityCleanerLoop()
	})
	return defaultTracker
}

func extractAnyNonLoopbackIP(line string) string {
	matches := ipCandidatePattern.FindAllStringSubmatch(line, -1)
	for _, m := range matches {
		if len(m) > 1 {
			ipStr := m[1]
			ip := net.ParseIP(ipStr)
			if ip != nil && !ip.IsLoopback() && !ip.IsUnspecified() {
				return ipStr
			}
		}
	}
	return ""
}

func parseCleanIP(raw string) string {
	raw = strings.TrimSpace(raw)
	raw = strings.Trim(raw, "[]'\"()")
	if host, _, err := net.SplitHostPort(raw); err == nil {
		return strings.Trim(host, "[]")
	}
	return raw
}

// ProcessLogLine parses a raw log line from a core and updates session tracking.
func (st *SessionTracker) ProcessLogLine(coreName, line string) {
	normCore := normalizeCoreName(coreName)
	now := time.Now().Unix()
	nowStr := time.Now().Format("2006-01-02 15:04:05")

	switch normCore {
	case "sing-box", "singbox":
		st.processSingBoxLine(line, now, nowStr)
	case "xray":
		st.processXrayLine(line, now, nowStr)
	case "hysteria", "hysteria2":
		st.processHysteriaLine(line, now, nowStr)
	}
}

func (st *SessionTracker) processSingBoxLine(line string, now int64, nowStr string) {
	if !strings.Contains(line, "inbound connection") && !strings.Contains(line, "accepted") {
		return
	}

	// Extract connection ID if present (e.g. [1978868683 155ms], [12345], [conn-1])
	var connID string
	if m := singboxConnIDPattern.FindStringSubmatch(line); len(m) > 1 {
		connID = m[1]
	}

	var fromIP string
	if m := singboxFromPattern.FindStringSubmatch(line); len(m) > 1 {
		fromIP = parseCleanIP(m[1])
	}

	// 1. Stage 1: Handshake with Source IP
	if strings.Contains(line, "inbound connection from") || strings.Contains(line, "from ") || fromIP != "" {
		if fromIP != "" && connID != "" {
			st.mu.Lock()
			st.singboxConns[connID] = fromIP
			if len(st.singboxConns) > 1000 {
				for k := range st.singboxConns {
					delete(st.singboxConns, k)
					if len(st.singboxConns) <= 500 {
						break
					}
				}
			}
			st.mu.Unlock()
		}
	}

	// 2. Stage 2: Authenticated user routing
	if m := singboxUserPattern.FindStringSubmatch(line); len(m) > 1 {
		email := m[1]
		if email == "" && len(m) > 2 {
			email = m[2]
		}
		email = strings.Trim(email, "[]'\"")
		if email != "" && email != "INFO" && email != "ERROR" && email != "WARN" && email != "DEBUG" && !strings.HasPrefix(email, "inbound-") {
			var srcIP string
			if fromIP != "" {
				srcIP = fromIP
			} else if connID != "" {
				st.mu.RLock()
				srcIP = st.singboxConns[connID]
				st.mu.RUnlock()
			}

			if srcIP != "" {
				st.registerConnect("sing-box", email, srcIP, now, nowStr)
			}
		}
	}
}

func (st *SessionTracker) processXrayLine(line string, now int64, nowStr string) {
	if !strings.Contains(line, "accepted") || !strings.Contains(line, "email:") {
		return
	}

	var srcIP, email string
	if m := xrayAcceptedPattern.FindStringSubmatch(line); len(m) > 1 {
		srcIP = parseCleanIP(m[1])
	}
	if m := xrayEmailPattern.FindStringSubmatch(line); len(m) > 1 {
		email = strings.TrimSpace(m[1])
	}

	if srcIP != "" && email != "" {
		st.registerConnect("xray", email, srcIP, now, nowStr)
	}
}

func (st *SessionTracker) processHysteriaLine(line string, now int64, nowStr string) {
	// 1. JSON format (Hysteria 2 structured logs)
	if strings.Contains(line, "{") {
		var obj map[string]any
		if err := json.Unmarshal([]byte(line), &obj); err == nil {
			msg, _ := obj["msg"].(string)
			email, _ := obj["id"].(string)
			if email == "" {
				email, _ = obj["auth"].(string)
			}
			if email == "" {
				email, _ = obj["user"].(string)
			}
			addr, _ := obj["addr"].(string)
			if addr == "" {
				addr, _ = obj["client_ip"].(string)
			}
			if addr == "" {
				addr, _ = obj["client"].(string)
			}

			if email != "" && addr != "" && (strings.Contains(msg, "authenticated") || strings.Contains(msg, "connected") || msg == "") {
				srcIP := parseCleanIP(addr)
				if srcIP != "" {
					st.registerConnect("hysteria2", email, srcIP, now, nowStr)
					return
				}
			}
		}
	}

	// 2. [TCP]/[UDP] format: [TCP] 1.2.3.4:5678 -> target:443 (user: alice)
	if m := hyTCPRegex.FindStringSubmatch(line); len(m) >= 3 {
		srcIP := parseCleanIP(m[1])
		email := strings.TrimSpace(m[2])
		if srcIP != "" && email != "" {
			st.registerConnect("hysteria2", email, srcIP, now, nowStr)
			return
		}
	}

	// 3. "authenticated as <email> (<ip>)"
	if m := hyAuthAsRegex.FindStringSubmatch(line); len(m) >= 2 {
		email := strings.TrimSpace(m[1])
		var srcIP string
		if len(m) >= 3 && m[2] != "" {
			srcIP = parseCleanIP(m[2])
		}
		if srcIP == "" {
			parts := strings.Fields(line)
			for _, p := range parts {
				cleanP := strings.Trim(p, "():")
				if strings.Contains(cleanP, ".") && !strings.Contains(cleanP, "@") {
					srcIP = parseCleanIP(cleanP)
					break
				}
			}
		}
		if email != "" && srcIP != "" {
			st.registerConnect("hysteria2", email, srcIP, now, nowStr)
			return
		}
	}

	// 4. Fallback: key=value format (auth_user=..., client_ip=...)
	if strings.Contains(line, "auth_user=") || strings.Contains(line, "auth=") {
		var email, srcIP string
		parts := strings.Fields(line)
		for _, p := range parts {
			if strings.HasPrefix(p, "auth_user=") {
				email = strings.TrimPrefix(p, "auth_user=")
			} else if strings.HasPrefix(p, "auth=") {
				email = strings.TrimPrefix(p, "auth=")
			} else if strings.HasPrefix(p, "client_ip=") || strings.HasPrefix(p, "client=") || strings.HasPrefix(p, "addr=") {
				val := strings.Split(p, "=")[1]
				srcIP = parseCleanIP(val)
			}
		}
		if email != "" && srcIP != "" {
			st.registerConnect("hysteria2", email, srcIP, now, nowStr)
		}
	}
}

// RegisterExternalConnect allows external callers (e.g. Hysteria HTTP Auth) to register connections.
func (st *SessionTracker) RegisterExternalConnect(core, email, ip string) {
	if email == "" || ip == "" {
		return
	}
	now := time.Now().Unix()
	nowStr := time.Now().Format("2006-01-02 15:04:05")
	st.registerConnect(core, email, parseCleanIP(ip), now, nowStr)
}

func (st *SessionTracker) registerConnect(core, email, ip string, now int64, nowStr string) {
	key := core + ":" + strings.ToLower(email) + ":" + ip
	st.mu.Lock()
	defer st.mu.Unlock()

	sess, exists := st.sessions[key]
	if !exists {
		st.sessions[key] = &SessionInfo{
			Email:       email,
			IP:          ip,
			Core:        core,
			StartedAt:   now,
			LastSeenAt:  now,
			ConnectedAt: nowStr,
		}
		event := &SessionEvent{
			Action:    "connect",
			Core:      core,
			Email:     email,
			IP:        ip,
			Timestamp: now,
			TimeStr:   nowStr,
		}
		st.events = append(st.events, event)
		if len(st.events) > st.maxEvents {
			st.events = st.events[len(st.events)-st.maxEvents:]
		}
		log.Printf("[sentinel-core] %s", i18n.TGlobal("LOG_SESSION_CONNECTED", core, email, ip))
	} else {
		sess.LastSeenAt = now
	}
}

// GetActiveSessions returns a snapshot of all currently active sessions across all cores.
func (st *SessionTracker) GetActiveSessions() []*SessionInfo {
	st.mu.RLock()
	defer st.mu.RUnlock()

	res := make([]*SessionInfo, 0, len(st.sessions))
	for _, s := range st.sessions {
		copySess := *s
		res = append(res, &copySess)
	}
	return res
}

// GetOnlineEmails returns a list of distinct active emails currently online.
func (st *SessionTracker) GetOnlineEmails() []string {
	st.mu.RLock()
	defer st.mu.RUnlock()

	emailSet := make(map[string]bool)
	for _, s := range st.sessions {
		if s.Email != "" {
			emailSet[s.Email] = true
		}
	}

	result := make([]string, 0, len(emailSet))
	for e := range emailSet {
		result = append(result, e)
	}
	return result
}

// GetRecentEvents returns the recent connect/disconnect events since a given timestamp.
func (st *SessionTracker) GetRecentEvents(sinceTimestamp int64, limit int) []*SessionEvent {
	st.mu.RLock()
	defer st.mu.RUnlock()

	if limit <= 0 || limit > len(st.events) {
		limit = len(st.events)
	}

	res := make([]*SessionEvent, 0, limit)
	for i := len(st.events) - 1; i >= 0 && len(res) < limit; i-- {
		ev := st.events[i]
		if ev.Timestamp >= sinceTimestamp {
			res = append(res, ev)
		}
	}
	return res
}

func (st *SessionTracker) inactivityCleanerLoop() {
	ticker := time.NewTicker(10 * time.Second)
	for range ticker.C {
		st.mu.Lock()
		now := time.Now().Unix()
		nowStr := time.Now().Format("2006-01-02 15:04:05")

		for key, sess := range st.sessions {
			if now-sess.LastSeenAt > 180 {
				durSec := sess.LastSeenAt - sess.StartedAt
				if durSec < 0 {
					durSec = 0
				}
				var durStr string
				if durSec < 60 {
					durStr = "несколько секунд"
				} else if durSec < 3600 {
					durStr = time.Duration(durSec * int64(time.Second)).String()
				} else {
					durStr = time.Duration(durSec * int64(time.Second)).String()
				}

				event := &SessionEvent{
					Action:    "disconnect",
					Core:      sess.Core,
					Email:     sess.Email,
					IP:        sess.IP,
					Timestamp: now,
					TimeStr:   nowStr,
					Duration:  durStr,
				}
				st.events = append(st.events, event)
				if len(st.events) > st.maxEvents {
					st.events = st.events[len(st.events)-st.maxEvents:]
				}
				delete(st.sessions, key)
				log.Printf("[sentinel-core] %s", i18n.TGlobal("LOG_SESSION_DISCONNECTED", sess.Core, sess.Email, sess.IP, durStr))
			}
		}
		st.mu.Unlock()
	}
}

// GetActiveSessionsJSON returns the active sessions formatted as JSON.
func (st *SessionTracker) GetActiveSessionsJSON() string {
	sessions := st.GetActiveSessions()
	data, _ := json.Marshal(sessions)
	return string(data)
}

// GetRecentEventsJSON returns recent events formatted as JSON.
func (st *SessionTracker) GetRecentEventsJSON(since int64, limit int) string {
	events := st.GetRecentEvents(since, limit)
	data, _ := json.Marshal(events)
	return string(data)
}
