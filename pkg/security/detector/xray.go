package detector

import (
	"regexp"
	"strconv"
	"strings"
)

var (
	// Xray log formats:
	// [Info] [12345678] proxy/vless/inbound: from tcp:1.2.3.4:5678 accepted tcp:example.com:443 [vless-in -> direct] email: user@example.com
	// [Info] [12345678] proxy/socks: from tcp:127.0.0.1:52341 accepted tcp:198.51.100.22:22 (process: ssh.exe)
	xrayInboundRegex  = regexp.MustCompile(`from\s+(?:tcp|udp):(\[[a-fA-F0-9:]+\]|[^:\s]+):\d+\s+accepted\s+(?:tcp|udp):(\[[a-fA-F0-9:]+\]|[^:\s]+):(\d+)(?:.*?email:\s*([^\s]+))?`)
	xrayRejectRegex   = regexp.MustCompile(`(?i)(?:rule|router|dispatcher|block).*?(?:match|rejected|block|connection).*?(?:for|to)\s+(?:tcp|udp):(\[[a-fA-F0-9:]+\]|[^:\s]+):(\d+)|connection from\s+(?:tcp|udp):(\[[a-fA-F0-9:]+\]|[^:\s]+):\d+\s+rejected`)
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
			ClientRawID: extractProcessOrUser(cleanLine),
			TargetHost:  "169.254.169.254",
			TargetPort:  80,
			EventType:   "SSRF_PROBE",
			RawLine:     cleanLine,
		}, true
	}

	// 2. Check for inbound connection with client email or process
	if matches := xrayInboundRegex.FindStringSubmatch(cleanLine); len(matches) >= 4 {
		clientIP := strings.Trim(matches[1], "[]")
		targetHost := strings.Trim(matches[2], "[]")
		port, _ := strconv.Atoi(matches[3])
		email := ""
		if len(matches) >= 5 {
			email = matches[4]
		}

		identifiedID := email
		if identifiedID == "" {
			identifiedID = extractProcessOrUser(cleanLine)
		}
		if identifiedID == "" {
			identifiedID = clientIP
		} else {
			identifiedID = cleanProcessName(identifiedID)
		}

		return &ParsedLogEvent{
			CoreName:    "xray",
			ClientRawID: identifiedID,
			ClientIP:    clientIP,
			TargetHost:  targetHost,
			TargetPort:  port,
			EventType:   "SENSITIVE_PORT_PROBE",
			RawLine:     cleanLine,
		}, true
	}

	// 3. Check for rejected authentication / routing blocks
	if matches := xrayRejectRegex.FindStringSubmatch(cleanLine); len(matches) >= 3 {
		targetHost := strings.Trim(matches[1], "[]")
		port, _ := strconv.Atoi(matches[2])
		clientIP := ""
		if targetHost == "" && len(matches) >= 4 {
			clientIP = strings.Trim(matches[3], "[]")
			targetHost = clientIP
		}
		return &ParsedLogEvent{
			CoreName:    "xray",
			ClientRawID: extractProcessOrUser(cleanLine),
			ClientIP:    clientIP,
			TargetHost:  targetHost,
			TargetPort:  port,
			EventType:   "ROUTING_REJECT",
			RawLine:     cleanLine,
		}, true
	}

	return nil, false
}
