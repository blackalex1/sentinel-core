package detector

import (
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	singboxConnRegex      = regexp.MustCompile(`(?:inbound|outbound).*?connection to\s+([^\s:]+):(\d+)`)
	singboxInboundRegex   = regexp.MustCompile(`inbound connection to ([^:]+):(\d+).*?(?:from process ([^\s,]+)|by process ([^\s,]+)|from user ([^\s,]+)|from ([^\s:]+)(?::\d+)?)`)
	singboxRejectRegex    = regexp.MustCompile(`(?:rule|router).*?(?:match|rejected).*?(?:for|to)\s+([^\s:]+):(\d+)`)
	singboxProcessRegex   = regexp.MustCompile(`(?i)(?:found process path:\s*|process path:\s*)([^\r\n,\]\)]+)|(?i)(?:from process|by process|process[:=\s]+|user[:=\s]+)\s*([^\s,\]\)]+)`)
	singboxConnIDRegex    = regexp.MustCompile(`\[(\d+)\s+\d+m?s\]`)
	singboxProcEventRegex = regexp.MustCompile(`(?:router:\s+)?found process path:\s+([^\r\n]+)`)
	singboxMetadataRegex  = regexp.MustCompile(`(?:169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200)`)
)

// SingboxParser handles log parsing and connection translation for Sing-box.
type SingboxParser struct {
	connProcCache sync.Map // map[string]string (connID -> processName)
	connPathCache sync.Map // map[string]string (connID -> fullExecutablePath)
	pendingEvents sync.Map // map[string]*ParsedLogEvent (connID -> *ParsedLogEvent)
}

// NewSingboxParser creates a new Singbox log parser.
func NewSingboxParser() *SingboxParser {
	return &SingboxParser{}
}

func (p *SingboxParser) CoreName() string {
	return "sing-box"
}

// ParseLogLine extracts security events from a Sing-box log line.
func (p *SingboxParser) ParseLogLine(line string) (*ParsedLogEvent, bool) {
	cleanLine := strings.TrimSpace(line)
	if cleanLine == "" {
		return nil, false
	}

	// 0. Correlate found process path event with connection ID
	var connID string
	if cMatches := singboxConnIDRegex.FindStringSubmatch(cleanLine); len(cMatches) >= 2 {
		connID = cMatches[1]
	}
	if pMatches := singboxProcEventRegex.FindStringSubmatch(cleanLine); len(pMatches) >= 2 {
		fullPath := strings.TrimSpace(pMatches[1])
		procName := cleanProcessName(fullPath)
		if connID != "" && procName != "" {
			p.connProcCache.Store(connID, procName)
			p.connPathCache.Store(connID, fullPath)

			// Check if we had a pending inbound connection waiting for this process name
			if v, ok := p.pendingEvents.LoadAndDelete(connID); ok {
				ev := v.(*ParsedLogEvent)
				ev.ClientRawID = procName
				ev.ExecutablePath = fullPath
				return ev, true
			}
		}
	}

	// 1. Check for Cloud Metadata / SSRF Attempt
	if singboxMetadataRegex.MatchString(cleanLine) {
		proc := extractProcessOrUser(cleanLine)
		if (proc == "" || strings.HasPrefix(proc, "172.") || strings.HasPrefix(proc, "192.")) && connID != "" {
			if v, ok := p.connProcCache.Load(connID); ok {
				proc = v.(string)
			}
		}

		return &ParsedLogEvent{
			CoreName:    "sing-box",
			ClientRawID: proc,
			TargetHost:  "169.254.169.254",
			TargetPort:  80,
			EventType:   "SSRF_PROBE",
			RawLine:     cleanLine,
		}, true
	}

	// 2. Check for connection to target (inbound or outbound)
	if matches := singboxConnRegex.FindStringSubmatch(cleanLine); len(matches) >= 3 {
		port, _ := strconv.Atoi(matches[2])
		targetHost := matches[1]

		identifiedID := ""
		identifiedPath := ""
		if connID != "" {
			if v, ok := p.connProcCache.Load(connID); ok {
				identifiedID = v.(string)
			}
			if v, ok := p.connPathCache.Load(connID); ok {
				identifiedPath = v.(string)
			}
		}
		if identifiedID == "" {
			identifiedID = extractProcessOrUser(cleanLine)
		}

		if identifiedID == "" && connID != "" && strings.Contains(cleanLine, "inbound connection to") {
			// Buffer this pending event until 'found process path' arrives for this connID
			p.pendingEvents.Store(connID, &ParsedLogEvent{
				CoreName:    "sing-box",
				ClientRawID: "pending",
				TargetHost:  targetHost,
				TargetPort:  port,
				EventType:   "SENSITIVE_PORT_PROBE",
				RawLine:     cleanLine,
			})
			return nil, false
		}

		if identifiedID == "" {
			if fromMatch := regexp.MustCompile(`(?:from|by)\s+([^\s:]+)`).FindStringSubmatch(cleanLine); len(fromMatch) >= 2 {
				identifiedID = fromMatch[1]
			}
		}

		if identifiedID == "" {
			identifiedID = "system"
		} else {
			identifiedID = cleanProcessName(identifiedID)
		}

		return &ParsedLogEvent{
			CoreName:       "sing-box",
			ClientRawID:    identifiedID,
			ExecutablePath: identifiedPath,
			TargetHost:     targetHost,
			TargetPort:     port,
			EventType:      "SENSITIVE_PORT_PROBE",
			RawLine:        cleanLine,
		}, true
	}

	// 3. Check for router rule rejects
	if matches := singboxRejectRegex.FindStringSubmatch(cleanLine); len(matches) >= 3 {
		port, _ := strconv.Atoi(matches[2])
		return &ParsedLogEvent{
			CoreName:    "sing-box",
			ClientRawID: extractProcessOrUser(cleanLine),
			TargetHost:  matches[1],
			TargetPort:  port,
			EventType:   "ROUTING_REJECT",
			RawLine:     cleanLine,
		}, true
	}

	return nil, false
}

// ParseSingboxConnections parses Clash API /connections JSON into ActiveConnections.
func ParseSingboxConnections(rawJSON []byte) ([]ActiveConnection, error) {
	type clashConn struct {
		ID       string `json:"id"`
		Metadata struct {
			User        string `json:"user"`
			SourceIP    string `json:"sourceIP"`
			Host        string `json:"host"`
			Destination string `json:"destinationIP"`
			DestPort    string `json:"destinationPort"`
		} `json:"metadata"`
		Upload   int64 `json:"upload"`
		Download int64 `json:"download"`
	}

	type clashResp struct {
		Connections []clashConn `json:"connections"`
	}

	var resp clashResp
	if err := json.Unmarshal(rawJSON, &resp); err != nil {
		return nil, err
	}

	var res []ActiveConnection
	for _, c := range resp.Connections {
		port, _ := strconv.Atoi(c.Metadata.DestPort)
		host := c.Metadata.Host
		if host == "" {
			host = c.Metadata.Destination
		}
		user := c.Metadata.User
		if user == "" {
			user = c.Metadata.SourceIP
		}

		res = append(res, ActiveConnection{
			ID:            c.ID,
			User:          user,
			SourceIP:      c.Metadata.SourceIP,
			DestHost:      host,
			DestPort:      port,
			UploadBytes:   c.Upload,
			DownloadBytes: c.Download,
			StartTime:     time.Now(),
		})
	}

	return res, nil
}

func cleanProcessName(s string) string {
	s = strings.TrimSpace(s)
	s = strings.Trim(s, "()\"',:;[] \t\r\n")
	if idx := strings.LastIndexAny(s, "/\\"); idx != -1 {
		s = s[idx+1:]
	}
	return strings.TrimSpace(s)
}

func extractProcessOrUser(line string) string {
	if m := singboxProcessRegex.FindStringSubmatch(line); len(m) >= 2 {
		raw := m[1]
		if raw == "" && len(m) >= 3 {
			raw = m[2]
		}
		proc := cleanProcessName(raw)
		if proc != "" && !strings.Contains(proc, ":") {
			return proc
		}
	}
	return extractUserID(line)
}

func extractUserID(line string) string {
	words := strings.Fields(line)
	for _, w := range words {
		if strings.Contains(w, "@") && !strings.HasPrefix(w, "http") {
			return strings.Trim(w, "(),:;[]")
		}
	}
	for i, w := range words {
		if (w == "user" || w == "client") && i+1 < len(words) {
			return strings.Trim(words[i+1], "(),:;[]")
		}
	}
	return ""
}
