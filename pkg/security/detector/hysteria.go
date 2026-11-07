package detector

import (
	"encoding/json"
	"net"
	"regexp"
	"strconv"
	"strings"
)

var (
	// Hysteria 2 log format:
	// [TCP] 1.2.3.4:5678 -> target.com:22 (user: alice)
	// [TCP] [2001:db8::1]:5678 -> [2001:db8::2]:22 (user: alice)
	hysteriaTCPRegex      = regexp.MustCompile(`\[(?:TCP|UDP)\]\s+(\[[a-fA-F0-9:]+\]|[^:\s]+):\d+\s+->\s+(\[[a-fA-F0-9:]+\]|[^:\s]+):(\d+)\s+\(user:\s*([^\s\)]+)\)`)
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

	// 1. Structured JSON format (Hysteria 2 standard logger)
	if strings.Contains(cleanLine, "{") && strings.Contains(cleanLine, "}") {
		if idx := strings.Index(cleanLine, "{"); idx != -1 {
			var obj map[string]any
			if err := json.Unmarshal([]byte(cleanLine[idx:]), &obj); err == nil {
				id, _ := obj["id"].(string)
				if id == "" {
					id, _ = obj["auth"].(string)
				}
				if id == "" {
					id, _ = obj["user"].(string)
				}

				reqAddr, _ := obj["reqAddr"].(string)
				if reqAddr == "" {
					reqAddr, _ = obj["dst"].(string)
				}
				if reqAddr == "" {
					reqAddr, _ = obj["addr"].(string)
				}

				clientAddr, _ := obj["client_ip"].(string)
				if clientAddr == "" {
					clientAddr, _ = obj["client"].(string)
				}

				clientIP := strings.Trim(clientAddr, "[]")
				if host, _, err := net.SplitHostPort(clientAddr); err == nil {
					clientIP = strings.Trim(host, "[]")
				}

				targetHost := ""
				targetPort := 0
				if reqAddr != "" {
					if host, portStr, err := net.SplitHostPort(reqAddr); err == nil {
						targetHost = strings.Trim(host, "[]")
						targetPort, _ = strconv.Atoi(portStr)
					} else {
						targetHost = strings.Trim(reqAddr, "[]")
					}
				}

				msg, _ := obj["msg"].(string)
				lowerMsg := strings.ToLower(msg)

				if strings.Contains(lowerMsg, "auth fail") {
					return &ParsedLogEvent{
						CoreName:    "hysteria2",
						ClientRawID: id,
						ClientIP:    clientIP,
						EventType:   "AUTH_FAIL",
						RawLine:     cleanLine,
					}, true
				}

				if targetHost != "" && targetPort > 0 {
					eventType := "SENSITIVE_PORT_PROBE"
					if hysteriaMetadataRegex.MatchString(targetHost) {
						eventType = "SSRF_PROBE"
					}
					return &ParsedLogEvent{
						CoreName:    "hysteria2",
						ClientRawID: id,
						ClientIP:    clientIP,
						TargetHost:  targetHost,
						TargetPort:  targetPort,
						EventType:   eventType,
						RawLine:     cleanLine,
					}, true
				}
			}
		}
	}

	// 2. Check for Cloud Metadata / SSRF Attempt
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

	// 3. Check for TCP/UDP forwarded session
	if matches := hysteriaTCPRegex.FindStringSubmatch(cleanLine); len(matches) >= 5 {
		port, _ := strconv.Atoi(matches[3])
		return &ParsedLogEvent{
			CoreName:    "hysteria2",
			ClientRawID: matches[4], // username
			ClientIP:    strings.Trim(matches[1], "[]"),
			TargetHost:  strings.Trim(matches[2], "[]"),
			TargetPort:  port,
			EventType:   "SENSITIVE_PORT_PROBE",
			RawLine:     cleanLine,
		}, true
	}

	// 4. Check for auth failures
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
