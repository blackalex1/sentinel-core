package supervisor

import (
	"encoding/json"
	"fmt"
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

	singboxConnIDPattern = regexp.MustCompile(`\[(?:conn-)?([0-9]{1,16})\s+[0-9\.]+(?:ms|µs|us|s|ns|m)\]|\[(?:conn-)?([0-9]{5,16})\]`)
	singboxFromPattern   = regexp.MustCompile(`(?:from|client|accepted(?:\s+(?:tcp|udp):?)?)\s*(?:tcp:|udp:)?\[?([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|[0-9a-fA-F:]{3,39})\]?(?::\d+)?`)
	singboxUserPattern   = regexp.MustCompile(`(?:inbound/[^:]+|inbound[^:]*):\s*\[([a-zA-Z0-9_.+@-]+)\]|router:\s*match\[\d+\]\s*(?:inbound/[^\s]+\s+)?\[([a-zA-Z0-9_.+@-]+)\]|\[([a-zA-Z0-9_.+@-]+)\]\s+(?:inbound connection|accepted|router|route|match|connection closed)|accepted\s+(?:tcp|udp):?\S*\s+\[([a-zA-Z0-9_.+@-]+)\]|(?:user|email|client|username|auth)[:=\s]+([a-zA-Z0-9_.+@-]+)|\[([a-zA-Z0-9_.+@-]+@[a-zA-Z0-9_.+@-]+)\]`)
	xrayAcceptedPattern  = regexp.MustCompile(`(?:from\s+)?(?:tcp:|udp:)?\[?([0-9a-fA-F.:]+)\]?(?::\d+)?\s+accepted`)
	xrayEmailPattern     = regexp.MustCompile(`email:\s+([^\s,\]]+)`)
	hyTCPRegex           = regexp.MustCompile(`\[(?:TCP|UDP)\]\s+([^\s:]+):\d+\s+->\s+\S+\s+\(user:\s*([^\s\)]+)\)`)
	hyAuthAsRegex        = regexp.MustCompile(`(?:client\s+)?authenticated as\s+([^\s(]+)(?:\s+\(?([^\s:)]+)(?::\d+)?\)?)?`)
	ipCandidatePattern   = regexp.MustCompile(`\b([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})(?::\d+)?\b`)
)

func isIgnoredTagOrLevel(val string) bool {
	if val == "" {
		return true
	}
	upper := strings.ToUpper(val)
	if upper == "INFO" || upper == "DEBUG" || upper == "WARN" || upper == "WARNING" || upper == "ERROR" || upper == "TRACE" || upper == "FATAL" || upper == "PANIC" {
		return true
	}
	lower := strings.ToLower(val)
	if lower == "direct" || lower == "block" || lower == "dns" || lower == "dns-out" || lower == "mixed-in" || lower == "vless-in" || lower == "ss-in" || lower == "trojan-in" || lower == "hysteria-in" || lower == "tuic-in" {
		return true
	}
	if strings.HasPrefix(lower, "inbound-") && !strings.Contains(lower, "@") {
		return true
	}
	return false
}

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

var ansiRegex = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]|\x1b\([a-zA-Z]|\x1b\][^\x07]*\x07|\x1b[0-9]`)

func stripANSI(str string) string {
	if !strings.Contains(str, "\x1b") {
		return str
	}
	return ansiRegex.ReplaceAllString(str, "")
}

// ProcessLogLine parses a raw log line from a core and updates session tracking.
func (st *SessionTracker) ProcessLogLine(coreName, line string) {
	normCore := normalizeCoreName(coreName)
	cleanLine := stripANSI(line)
	now := time.Now().Unix()
	nowStr := time.Now().Format("2006-01-02 15:04:05")

	switch normCore {
	case "sing-box", "singbox":
		st.processSingBoxLine(cleanLine, now, nowStr)
	case "xray":
		st.processXrayLine(cleanLine, now, nowStr)
	case "hysteria", "hysteria2":
		st.processHysteriaLine(cleanLine, now, nowStr)
	}
}

func (st *SessionTracker) processSingBoxLine(line string, now int64, nowStr string) {
	if !strings.Contains(line, "inbound connection") && !strings.Contains(line, "accepted") && !strings.Contains(line, "inbound/") && !strings.Contains(line, "router:") {
		return
	}

	// Extract connection ID if present (e.g. [388439065 0ms], [388439065 79ms])
	var connID string
	if m := singboxConnIDPattern.FindStringSubmatch(line); len(m) > 1 {
		for _, g := range m[1:] {
			if g != "" {
				connID = g
				break
			}
		}
	}

	var fromIP string
	if m := singboxFromPattern.FindStringSubmatch(line); len(m) > 1 {
		fromIP = parseCleanIP(m[1])
	}
	if fromIP == "" && (strings.Contains(line, "inbound connection from") || strings.Contains(line, "accepted")) {
		fromIP = extractAnyNonLoopbackIP(line)
	}

	// 1. Stage 1: Handshake with Source IP
	if fromIP != "" && connID != "" {
		st.mu.Lock()
		st.singboxConns[connID] = fromIP
		if len(st.singboxConns) > 5000 {
			count := 0
			for k := range st.singboxConns {
				delete(st.singboxConns, k)
				count++
				if count >= 2500 {
					break
				}
			}
		}
		st.mu.Unlock()
	}

	// 2. Stage 2: Authenticated user routing
	var email string
	if m := singboxUserPattern.FindStringSubmatch(line); len(m) > 1 {
		for _, g := range m[1:] {
			if g != "" {
				email = g
				break
			}
		}
	}
	email = strings.Trim(email, "[]'\"")
	if isIgnoredTagOrLevel(email) {
		email = ""
	}

	if email != "" {
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
	lowerLine := strings.ToLower(line)

	// 1. JSON format (Hysteria 2 structured logs)
	if idx := strings.Index(line, "{"); idx != -1 {
		var obj map[string]any
		if err := json.Unmarshal([]byte(line[idx:]), &obj); err == nil {
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

			if email != "" && addr != "" {
				srcIP := parseCleanIP(addr)
				if srcIP != "" {
					// 1. Disconnect event
					if strings.Contains(lowerLine, "client disconnected") || strings.Contains(lowerLine, "disconnect") {
						st.registerDisconnect("hysteria2", email, srcIP, now, nowStr)
						return
					}

					// 2. Connect / authenticated event
					if strings.Contains(lowerLine, "client connected") || strings.Contains(lowerLine, "authenticated") {
						st.registerConnect("hysteria2", email, srcIP, now, nowStr)
						return
					}

					// 3. TCP error or TCP request activity: update LastSeenAt on active session
					st.touchSession("hysteria2", email, srcIP, now)
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
			if strings.Contains(lowerLine, "disconnect") {
				st.registerDisconnect("hysteria2", email, srcIP, now, nowStr)
			} else {
				st.registerConnect("hysteria2", email, srcIP, now, nowStr)
			}
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
			if strings.Contains(lowerLine, "disconnect") {
				st.registerDisconnect("hysteria2", email, srcIP, now, nowStr)
			} else {
				st.registerConnect("hysteria2", email, srcIP, now, nowStr)
			}
		}
	}
}

func (st *SessionTracker) touchSession(core, email, ip string, now int64) {
	normEmail := strings.ToLower(email)
	key := core + ":" + normEmail + ":" + ip
	st.mu.Lock()
	defer st.mu.Unlock()

	if sess, exists := st.sessions[key]; exists {
		sess.LastSeenAt = now
	}
}

func (st *SessionTracker) registerDisconnect(core, email, ip string, now int64, nowStr string) {
	normEmail := strings.ToLower(email)
	key := core + ":" + normEmail + ":" + ip
	st.mu.Lock()
	defer st.mu.Unlock()

	sess, exists := st.sessions[key]
	if !exists {
		// Fallback match: if IP varied slightly or session under core:email
		for k, s := range st.sessions {
			if s.Core == core && strings.ToLower(s.Email) == normEmail {
				key = k
				sess = s
				exists = true
				break
			}
		}
	}

	if exists {
		durSec := now - sess.StartedAt
		durStr := formatDuration(durSec)
		st.events = append(st.events, &SessionEvent{
			Action:    "disconnect",
			Core:      core,
			Email:     sess.Email,
			IP:        sess.IP,
			Timestamp: now,
			TimeStr:   nowStr,
			Duration:  durStr,
		})
		if len(st.events) > st.maxEvents {
			st.events = st.events[len(st.events)-st.maxEvents:]
		}
		delete(st.sessions, key)
		log.Printf("[sentinel-core] %s", i18n.TGlobal("LOG_SESSION_DISCONNECTED", core, sess.Email, sess.IP, durStr))
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

func formatDuration(durSec int64) string {
	loc := i18n.GetLocale()
	if loc == i18n.LocaleEN {
		if durSec <= 0 {
			return "1s"
		}
		if durSec < 60 {
			return fmt.Sprintf("%ds", durSec)
		}
		if durSec < 3600 {
			mins := durSec / 60
			secs := durSec % 60
			if secs > 0 {
				return fmt.Sprintf("%dm %ds", mins, secs)
			}
			return fmt.Sprintf("%dm", mins)
		}
		hours := durSec / 3600
		mins := (durSec % 3600) / 60
		if mins > 0 {
			return fmt.Sprintf("%dh %dm", hours, mins)
		}
		return fmt.Sprintf("%dh", hours)
	}

	if durSec <= 0 {
		return "1 сек"
	}
	if durSec < 60 {
		return fmt.Sprintf("%d сек", durSec)
	}
	if durSec < 3600 {
		mins := durSec / 60
		secs := durSec % 60
		if secs > 0 {
			return fmt.Sprintf("%d мин %d сек", mins, secs)
		}
		return fmt.Sprintf("%d мин", mins)
	}
	hours := durSec / 3600
	mins := (durSec % 3600) / 60
	if mins > 0 {
		return fmt.Sprintf("%d ч %d мин", hours, mins)
	}
	return fmt.Sprintf("%d ч", hours)
}

func (st *SessionTracker) registerConnect(core, email, ip string, now int64, nowStr string) {
	normEmail := strings.ToLower(email)
	key := core + ":" + normEmail + ":" + ip
	st.mu.Lock()
	defer st.mu.Unlock()

	sess, exists := st.sessions[key]
	if !exists {
		// Close previous active session of the same user on different IP (Network Roaming / Reconnect)
		for oldKey, oldSess := range st.sessions {
			if oldSess.Core == core && strings.ToLower(oldSess.Email) == normEmail && oldSess.IP != ip {
				durSec := now - oldSess.StartedAt
				durStr := formatDuration(durSec)
				st.events = append(st.events, &SessionEvent{
					Action:    "disconnect",
					Core:      oldSess.Core,
					Email:     oldSess.Email,
					IP:        oldSess.IP,
					Timestamp: now,
					TimeStr:   nowStr,
					Duration:  durStr,
				})
				delete(st.sessions, oldKey)
				log.Printf("[sentinel-core] %s", i18n.TGlobal("LOG_SESSION_DISCONNECTED", oldSess.Core, oldSess.Email, oldSess.IP, durStr))
			}
		}

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

// FindClientByIP searches active sessions for an email associated with the given client IP.
func (st *SessionTracker) FindClientByIP(ip string) string {
	if ip == "" {
		return ""
	}
	cleanIP := parseCleanIP(ip)
	st.mu.RLock()
	defer st.mu.RUnlock()

	for _, s := range st.sessions {
		if s.IP == cleanIP || s.IP == ip {
			return s.Email
		}
	}
	return ""
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

// GetRecentEvents returns the recent connect/disconnect events since a given timestamp in chronological order.
func (st *SessionTracker) GetRecentEvents(sinceTimestamp int64, limit int) []*SessionEvent {
	st.mu.RLock()
	defer st.mu.RUnlock()

	if limit <= 0 || limit > len(st.events) {
		limit = len(st.events)
	}

	res := make([]*SessionEvent, 0, limit)
	startIdx := len(st.events) - limit
	if startIdx < 0 {
		startIdx = 0
	}
	for i := startIdx; i < len(st.events); i++ {
		ev := st.events[i]
		if sinceTimestamp <= 0 || ev.Timestamp >= sinceTimestamp {
			res = append(res, ev)
		}
	}
	return res
}

// Clear resets all active sessions, tracked connections, and event history.
func (st *SessionTracker) Clear() {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.sessions = make(map[string]*SessionInfo)
	st.singboxConns = make(map[string]string)
	st.events = make([]*SessionEvent, 0, st.maxEvents)
}

func (st *SessionTracker) inactivityCleanerLoop() {
	ticker := time.NewTicker(10 * time.Second)
	for range ticker.C {
		now := time.Now().Unix()
		nowStr := time.Now().Format("2006-01-02 15:04:05")

		// Query live active traffic across all engines to keep active sessions alive
		activeTraffic, _ := GetController().GetUnifiedTraffic()

		st.mu.Lock()
		if activeTraffic != nil {
			for _, sess := range st.sessions {
				normEmail := strings.ToLower(sess.Email)
				for em, ct := range activeTraffic {
					if strings.ToLower(em) == normEmail {
						if ct.Online || ct.Connections > 0 {
							sess.LastSeenAt = now
						}
						break
					}
				}
			}
		}

		for key, sess := range st.sessions {
			if now-sess.LastSeenAt > 180 {
				durSec := now - sess.StartedAt
				durStr := formatDuration(durSec)

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
