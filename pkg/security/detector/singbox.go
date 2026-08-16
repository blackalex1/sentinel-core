package detector

import (
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	singboxInboundRegex = regexp.MustCompile(`inbound connection to ([^:]+):(\d+).*?(?:from user ([^\s]+)|from ([^\s:]+)(?::\d+)?)`)
	singboxRejectRegex  = regexp.MustCompile(`(?:rule|router).*?(?:match|rejected).*?(?:for|to)\s+([^\s:]+):(\d+)`)
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
			ClientRawID: extractUserID(cleanLine),
			TargetHost:  "169.254.169.254",
			TargetPort:  80,
			EventType:   "SSRF_PROBE",
			RawLine:     cleanLine,
		}, true
	}

	// 2. Check for inbound connection (e.g. sensitive port probes)
	if matches := singboxInboundRegex.FindStringSubmatch(cleanLine); len(matches) >= 3 {
		port, _ := strconv.Atoi(matches[2])
		user := matches[3]
		clientIP := matches[4]
		if user == "" {
			user = clientIP
		}

		return &ParsedLogEvent{
			CoreName:    "sing-box",
			ClientRawID: user,
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
			ClientRawID: extractUserID(cleanLine),
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
