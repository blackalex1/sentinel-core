package detector

import (
	"regexp"
	"strconv"
	"strings"
)

var (
	// Hysteria 2 log format:
	// [TCP] 1.2.3.4:5678 -> target.com:22 (user: alice)
	hysteriaTCPRegex      = regexp.MustCompile(`\[(?:TCP|UDP)\]\s+([^\s:]+):\d+\s+->\s+([^\s:]+):(\d+)\s+\(user:\s*([^\s\)]+)\)`)
	hysteriaAuthFailRegex = regexp.MustCompile(`auth failed for (?:user|client)\s+([^\s]+)`)
	hysteriaMetadataRegex = regexp.MustCompile(`(?:169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200)`)
)

// HysteriaParser handles log parsing and threat extraction for Hysteria 2.
type HysteriaParser struct{}

// NewHysteriaParser creates a new Hysteria 2 log parser.
func NewHysteriaParser() *HysteriaParser {
	return &HysteriaParser{}
}

func (p *HysteriaParser) CoreName() string {
	return "hysteria2"
}

// ParseLogLine extracts security events from a Hysteria 2 log line.
func (p *HysteriaParser) ParseLogLine(line string) (*ParsedLogEvent, bool) {
	cleanLine := strings.TrimSpace(line)
	if cleanLine == "" {
		return nil, false
	}

	// 1. Check for Cloud Metadata / SSRF Attempt
	if hysteriaMetadataRegex.MatchString(cleanLine) {
		return &ParsedLogEvent{
			CoreName:    "hysteria2",
			ClientRawID: extractUserID(cleanLine),
			TargetHost:  "169.254.169.254",
			TargetPort:  80,
			EventType:   "SSRF_PROBE",
			RawLine:     cleanLine,
		}, true
	}

	// 2. Check for TCP/UDP forwarded session
	if matches := hysteriaTCPRegex.FindStringSubmatch(cleanLine); len(matches) >= 5 {
		port, _ := strconv.Atoi(matches[3])
		return &ParsedLogEvent{
			CoreName:    "hysteria2",
			ClientRawID: matches[4], // username
			ClientIP:    matches[1],
			TargetHost:  matches[2],
			TargetPort:  port,
			EventType:   "SENSITIVE_PORT_PROBE",
			RawLine:     cleanLine,
		}, true
	}

	// 3. Check for auth failures
	if matches := hysteriaAuthFailRegex.FindStringSubmatch(cleanLine); len(matches) >= 2 {
		return &ParsedLogEvent{
			CoreName:    "hysteria2",
			ClientRawID: matches[1],
			EventType:   "AUTH_FAIL",
			RawLine:     cleanLine,
		}, true
	}

	return nil, false
}
