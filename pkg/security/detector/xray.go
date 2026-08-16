package detector

import (
	"regexp"
	"strconv"
	"strings"
)

var (
	// Xray log format:
	// [Info] [12345678] proxy/vless/inbound: ... from tcp:1.2.3.4:5678 accepted tcp:example.com:443 [vless-in -> direct] email: user@example.com
	xrayInboundRegex = regexp.MustCompile(`from\s+(?:tcp|udp):([^\s:]+):\d+\s+accepted\s+(?:tcp|udp):([^\s:]+):(\d+).*?email:\s*([^\s]+)`)
	xrayRejectRegex  = regexp.MustCompile(`connection from\s+(?:tcp|udp):([^\s:]+):\d+\s+rejected`)
	xrayMetadataRegex = regexp.MustCompile(`(?:169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200)`)
)

// XrayParser handles log parsing and threat extraction for Xray-core.
type XrayParser struct{}

// NewXrayParser creates a new Xray log parser.
func NewXrayParser() *XrayParser {
	return &XrayParser{}
}

func (p *XrayParser) CoreName() string {
	return "xray"
}

// ParseLogLine extracts security events from an Xray-core log line.
func (p *XrayParser) ParseLogLine(line string) (*ParsedLogEvent, bool) {
	cleanLine := strings.TrimSpace(line)
	if cleanLine == "" {
		return nil, false
	}

	// 1. Check for Cloud Metadata / SSRF Attempt
	if xrayMetadataRegex.MatchString(cleanLine) {
		return &ParsedLogEvent{
			CoreName:    "xray",
			ClientRawID: extractUserID(cleanLine),
			TargetHost:  "169.254.169.254",
			TargetPort:  80,
			EventType:   "SSRF_PROBE",
			RawLine:     cleanLine,
		}, true
	}

	// 2. Check for inbound connection with client email
	if matches := xrayInboundRegex.FindStringSubmatch(cleanLine); len(matches) >= 5 {
		port, _ := strconv.Atoi(matches[3])
		return &ParsedLogEvent{
			CoreName:    "xray",
			ClientRawID: matches[4], // email
			ClientIP:    matches[1],
			TargetHost:  matches[2],
			TargetPort:  port,
			EventType:   "SENSITIVE_PORT_PROBE",
			RawLine:     cleanLine,
		}, true
	}

	// 3. Check for rejected authentication / connections
	if matches := xrayRejectRegex.FindStringSubmatch(cleanLine); len(matches) >= 2 {
		return &ParsedLogEvent{
			CoreName:    "xray",
			ClientRawID: matches[1],
			ClientIP:    matches[1],
			EventType:   "AUTH_FAIL",
			RawLine:     cleanLine,
		}, true
	}

	return nil, false
}
