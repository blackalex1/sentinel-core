package detector

import (
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	singboxInboundRegex  = regexp.MustCompile(`inbound connection to ([^:]+):(\d+).*?(?:from process ([^\s,]+)|by process ([^\s,]+)|from user ([^\s,]+)|from ([^\s:]+)(?::\d+)?)`)
	singboxRejectRegex   = regexp.MustCompile(`(?:rule|router).*?(?:match|rejected).*?(?:for|to)\s+([^\s:]+):(\d+)`)
	singboxProcessRegex  = regexp.MustCompile(`(?i)(?:from process|by process|process[:=\s]+|user[:=\s]+)([^\s,\]\)]+)`)
	singboxMetadataRegex = regexp.MustCompile(`(?:169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200)`)
)

// SingboxParser handles log parsing and connection translation for Sing-box.
type SingboxParser struct{}

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

	// 1. Check for Cloud Metadata / SSRF Attempt
	if singboxMetadataRegex.MatchString(cleanLine) {
		return &ParsedLogEvent{
			CoreName:    "sing-box",
			ClientRawID: extractProcessOrUser(cleanLine),
			TargetHost:  "169.254.169.254",
			TargetPort:  80,
			EventType:   "SSRF_PROBE",
			RawLine:     cleanLine,
		}, true
	}

	// 2. Check for inbound connection (e.g. sensitive port probes)
	if matches := singboxInboundRegex.FindStringSubmatch(cleanLine); len(matches) >= 3 {
		port, _ := strconv.Atoi(matches[2])
		proc1 := matches[3] // from process
		proc2 := matches[4] // by process
		user := matches[5]  // from user
		clientIP := matches[6]

		identifiedID := proc1
		if identifiedID == "" {
			identifiedID = proc2
		}
		if identifiedID == "" {
			identifiedID = user
		}
		if identifiedID == "" {
			identifiedID = extractProcessOrUser(cleanLine)
		}
		if identifiedID == "" {
			identifiedID = clientIP
		} else {
			identifiedID = cleanProcessName(identifiedID)
		}

		return &ParsedLogEvent{
			CoreName:    "sing-box",
			ClientRawID: identifiedID,
			ClientIP:    clientIP,
			TargetHost:  matches[1],
			TargetPort:  port,
			EventType:   "SENSITIVE_PORT_PROBE",
			RawLine:     cleanLine,
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
	s = strings.Trim(s, "()\"',:;[]")
	if idx := strings.LastIndexAny(s, "/\\"); idx != -1 {
		s = s[idx+1:]
	}
	return s
}

func extractProcessOrUser(line string) string {
	if m := singboxProcessRegex.FindStringSubmatch(line); len(m) >= 2 {
		proc := cleanProcessName(m[1])
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
