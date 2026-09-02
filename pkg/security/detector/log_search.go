package detector

import (
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	// xrayTimeRegex optionally captures a leading +HHMM timezone offset (sing-box format: "+0300 2026-08-31 14:10:09").
	xrayTimeRegex     = regexp.MustCompile(`([+-]\d{4})\s+(\d{4}[/-]\d{2}[/-]\d{2}[ T]\d{2}:\d{2}:\d{2})|(\d{4}[/-]\d{2}[/-]\d{2}[ T]\d{2}:\d{2}:\d{2})`)
	hyTimeJSONRegex   = regexp.MustCompile(`\{.*"time"\s*:\s*"([^"]+)".*\}`)
	hyTimeISO8601     = regexp.MustCompile(`(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})`)
	hyTimeNoYear      = regexp.MustCompile(`\b(\d{2}-\d{2}T\d{2}:\d{2}:\d{2})`)

	hyIDJSONRegex     = regexp.MustCompile(`"id"\s*:\s*"([^"]+)"`)
	hyAuthJSONRegex   = regexp.MustCompile(`"auth"\s*:\s*"([^"]+)"`)
	hyAuthTextRegex   = regexp.MustCompile(`auth\s*=\s*([^\s,}]+)`)
	hyConnTextRegex   = regexp.MustCompile(`connection:\s*([^\s(]+)`)
	hyEmailRegex      = regexp.MustCompile(`[\w\.-]+@[\w\.-]+\.\w+`)
	hyDestHostRegex   = regexp.MustCompile(`->\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):\d+`)
	hyClientConnRegex = regexp.MustCompile(`(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})`)

	sbInboundTagRegex = regexp.MustCompile(`(?:inbound/[^:]+|inbound[^:]*):\s*\[([a-zA-Z0-9_\.\-]+)\]\s+inbound connection to`)
	sbBracketUser     = regexp.MustCompile(`\[([a-zA-Z0-9_\.\-]+)\]\s+inbound connection to`)
	sbRouterMatchRegex = regexp.MustCompile(`router:\s*match\[\d+\]\s*(?:inbound/[^\s]+\s+)?\[([a-zA-Z0-9_\.\-]+)\]`)
	sbAcceptedRegex   = regexp.MustCompile(`accepted\s+(?:tcp|udp):?\S*\s+\[([a-zA-Z0-9_\.\-]+)\]`)
	xrayEmailRegex    = regexp.MustCompile(`email:\s*(\S+)`)
	xrayAcceptedRegex = regexp.MustCompile(`accepted\s+(?:tcp|udp):\S+\s+\[[^\]]+\]\s+([a-zA-Z0-9_\.\-]+)`)
	xrayUserTagRegex  = regexp.MustCompile(`(?:user|username|clientUser|auth_user):\s*([^\s,\]]+)`)
	xrayJSONUserRegex = regexp.MustCompile(`"(?:user|username|id|email|auth)"\s*:\s*"([^"]+)"`)
	sbConnUserRegex   = regexp.MustCompile(`inbound connection\s+.*?\s+\[([a-zA-Z0-9_\.\-]+)\]`)
	sbEndUserRegex    = regexp.MustCompile(`\[([a-zA-Z0-9_\.\-]+@[a-zA-Z0-9_\.\-]+|[a-zA-Z0-9_\.\-]+)\]\s*$`)
	genericEmailRegex = regexp.MustCompile(`([a-zA-Z0-9_\.\-]+@[a-zA-Z0-9_\.\-]+)`)

	xrayIPAcceptedRegex = regexp.MustCompile(`(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):\d+\s+(?:accepted|inbound connection)`)
	xrayIPFromRegex     = regexp.MustCompile(`from\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})`)
	xrayTagMatchRegex   = regexp.MustCompile(`(?:accepted|connection)\s+(?:tcp|udp):\S+\s+\[([^\]]+)\]`)
	sbInboundTagFromPrefix = regexp.MustCompile(`inbound/[a-zA-Z0-9_\.\-]+\[([a-zA-Z0-9_\.\-]+)\]`)
	sbInboundConnTag    = regexp.MustCompile(`\[([^\]]+)\]\s+inbound connection`)
	xrayDestMatchRegex  = regexp.MustCompile(`(?:accepted|connection)\s+(?:tcp|udp):([^:]+):`)
	ipv4CheckRegex      = regexp.MustCompile(`^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$`)

	// sing-box two-line format: connID links "inbound connection from IP" and "[user] inbound connection to DST".
	// sbConnIDLineRegex extracts the connID from any timed log line: [338227781 79ms].
	sbConnIDLineRegex = regexp.MustCompile(`\[(\d+)\s+[\d.]+(?:ms|µs|us|s|ns|m)\]`)
	// sbFromIPLineRegex extracts (connID, clientIP) from "inbound connection from IP:PORT" lines.
	sbFromIPLineRegex = regexp.MustCompile(`\[(\d+)\s+[\d.]+(?:ms|µs|us|s|ns|m)\]\s+\S+:\s+inbound connection from\s+([^\s:]+):\d+`)
)

// ParseXrayTimestamp extracts a time.Time from an Xray/Sing-box log line.
// Handles the sing-box format with timezone prefix: "+0000 2026-08-31 11:33:20"
// as well as plain Xray format: "2026/08/31 11:33:20".
// The returned time is always in UTC.
func ParseXrayTimestamp(line string) *time.Time {
	m := xrayTimeRegex.FindStringSubmatch(line)
	if len(m) < 2 {
		return nil
	}

	var tzOffset, dateStr string
	// xrayTimeRegex has 3 groups: (tzOffset) (dateWithTZ) | (dateNoTZ)
	if m[1] != "" {
		// Groups 1+2: timezone offset + date string
		tzOffset = m[1]
		dateStr = m[2]
	} else {
		// Group 3: plain date without timezone prefix (Xray format)
		dateStr = m[3]
	}
	if dateStr == "" {
		return nil
	}

	normalized := strings.ReplaceAll(dateStr, "/", "-")
	normalized = strings.ReplaceAll(normalized, "T", " ")

	if tzOffset != "" && len(tzOffset) == 5 {
		// sing-box: explicit offset present — parse naive, then shift to UTC.
		// "+0300 14:10:09" → UTC 11:10:09 ; "+0000 11:10:09" → UTC 11:10:09
		t, err := time.Parse("2006-01-02 15:04:05", normalized)
		if err != nil {
			return nil
		}
		sign := 1
		if tzOffset[0] == '-' {
			sign = -1
		}
		hh := int(tzOffset[1]-'0')*10 + int(tzOffset[2]-'0')
		mm := int(tzOffset[3]-'0')*10 + int(tzOffset[4]-'0')
		offsetSec := sign * (hh*3600 + mm*60)
		utc := t.Add(-time.Duration(offsetSec) * time.Second).UTC()
		return &utc
	}

	// No offset — Xray writes in server local time without prefix.
	// Parse as local time so the result converts correctly to real UTC.
	t, err := time.ParseInLocation("2006-01-02 15:04:05", normalized, time.Local)
	if err != nil {
		return nil
	}
	utc := t.UTC()
	return &utc
}

// checkAge returns true if the log timestamp is within maxAgeSec seconds of now.
func checkAge(logTime *time.Time, maxAgeSec int) bool {
	if logTime == nil || maxAgeSec <= 0 {
		return true
	}
	diff := time.Since(*logTime)
	if diff < 0 {
		diff = -diff
	}
	if diff <= time.Duration(maxAgeSec)*time.Second {
		return true
	}

	// Fallback for timezone differences (e.g. log wrote local time formatted with Z or UTC vs Local)
	locTime := time.Date(logTime.Year(), logTime.Month(), logTime.Day(), logTime.Hour(), logTime.Minute(), logTime.Second(), 0, time.Local)
	diffLoc := time.Since(locTime)
	if diffLoc < 0 {
		diffLoc = -diffLoc
	}
	return diffLoc <= time.Duration(maxAgeSec)*time.Second
}


// ParseHysteriaTimestamp extracts a time.Time from a Hysteria 2 log line.
func ParseHysteriaTimestamp(line string) *time.Time {
	clean := strings.TrimSpace(line)
	// 1. JSON substring with "time" field
	if m := hyTimeJSONRegex.FindStringSubmatch(clean); len(m) >= 2 {
		tStr := strings.TrimSuffix(m[1], "Z")
		if idx := strings.Index(tStr, "."); idx > 0 {
			tStr = tStr[:idx]
		}
		if idx := strings.Index(tStr, "+"); idx > 0 {
			tStr = tStr[:idx]
		}
		if t, err := time.Parse("2006-01-02T15:04:05", tStr); err == nil {
			return &t
		}
	}

	if strings.HasPrefix(clean, "{") {
		var obj map[string]any
		if err := json.Unmarshal([]byte(clean), &obj); err == nil {
			if tVal, ok := obj["time"].(string); ok && tVal != "" {
				tStr := strings.TrimSuffix(tVal, "Z")
				if idx := strings.Index(tStr, "."); idx > 0 {
					tStr = tStr[:idx]
				}
				if idx := strings.Index(tStr, "+"); idx > 0 {
					tStr = tStr[:idx]
				}
				if t, err := time.Parse("2006-01-02T15:04:05", tStr); err == nil {
					return &t
				}
			}
		}
	}

	// 2. ISO8601 text format
	if m := hyTimeISO8601.FindStringSubmatch(clean); len(m) >= 2 {
		if t, err := time.Parse("2006-01-02T15:04:05", m[1]); err == nil {
			return &t
		}
	}

	// 3. No year format (e.g. 06-16T15:17:37)
	if m := hyTimeNoYear.FindStringSubmatch(clean); len(m) >= 2 {
		curYear := strconv.Itoa(time.Now().Year())
		fullStr := curYear + "-" + m[1]
		if t, err := time.Parse("2006-01-02T15:04:05", fullStr); err == nil {
			return &t
		}
	}

	return nil
}

// FindEmailInHysteriaLog searches Hysteria 2 log lines for the user ID associated with a target IP:port.
func FindEmailInHysteriaLog(lines []string, dstIP string, dstPort int, maxAgeSec int) string {
	dstPortStr := ":" + strconv.Itoa(dstPort)

	extractEmail := func(line string) string {
		if m := hyIDJSONRegex.FindStringSubmatch(line); len(m) >= 2 {
			return strings.Trim(m[1], "\"'[]")
		}
		if m := hyAuthJSONRegex.FindStringSubmatch(line); len(m) >= 2 {
			return strings.Trim(m[1], "\"'[]")
		}
		if m := hyAuthTextRegex.FindStringSubmatch(line); len(m) >= 2 {
			return strings.Trim(m[1], "\"'[]")
		}
		if m := hyConnTextRegex.FindStringSubmatch(line); len(m) >= 2 {
			return strings.Trim(m[1], "\"'[]")
		}
		if m := hyEmailRegex.FindStringSubmatch(line); len(m) >= 1 {
			return strings.Trim(m[0], "\"'[]")
		}
		return ""
	}

	extractDestHost := func(line string) string {
		if idx := strings.Index(line, "{"); idx != -1 {
			var obj map[string]any
			if err := json.Unmarshal([]byte(line[idx:]), &obj); err == nil {
				reqVal, _ := obj["reqAddr"].(string)
				if reqVal == "" {
					reqVal, _ = obj["req"].(string)
				}
				if reqVal != "" && strings.Contains(reqVal, ":") {
					return strings.Trim(strings.Split(reqVal, ":")[0], "[]")
				}
			}
		}
		if m := hyDestHostRegex.FindStringSubmatch(line); len(m) >= 2 {
			return strings.Trim(m[1], "[]")
		}
		return ""
	}

	for i := len(lines) - 1; i >= 0; i-- {
		line := lines[i]
		t := ParseHysteriaTimestamp(line)
		if !checkAge(t, maxAgeSec) {
			continue
		}

		if !strings.Contains(line, dstPortStr) {
			continue
		}

		if dstIP != "" {
			destHost := extractDestHost(line)
			if destHost != "" {
				if destHost != dstIP {
					continue
				}
			} else if !strings.Contains(line, dstIP) {
				continue
			}
		}

		if email := extractEmail(line); email != "" {
			return email
		}
	}

	return ""
}

// FindClientIPForEmailInHysteriaLog searches for the latest client IP used by an email.
func FindClientIPForEmailInHysteriaLog(lines []string, email string, maxAgeSec int) string {
	for i := len(lines) - 1; i >= 0; i-- {
		line := lines[i]
		t := ParseHysteriaTimestamp(line)
		if !checkAge(t, maxAgeSec) {
			continue
		}

		if idx := strings.Index(line, "{"); idx != -1 {
			var obj map[string]any
			if err := json.Unmarshal([]byte(line[idx:]), &obj); err == nil {
				idVal, _ := obj["id"].(string)
				if idVal == "" {
					idVal, _ = obj["auth"].(string)
				}
				if idVal == email {
					if addr, ok := obj["addr"].(string); ok && addr != "" {
						if strings.Contains(addr, ":") {
							return strings.Split(addr, ":")[0]
						}
						return addr
					}
				}
			}
		}

		if strings.Contains(line, "client connected") && strings.Contains(line, email) {
			if m := hyClientConnRegex.FindStringSubmatch(line); len(m) >= 2 {
				return m[1]
			}
		}
	}
	return ""
}

// FindEmailAndIPInXrayLog searches Xray and Sing-box log lines for client email, IP, and inbound tag.
func FindEmailAndIPInXrayLog(lines []string, clientIP, dstIP string, dstPort int, maxAgeSec int) (email, ip, inboundTag string) {
	dstPortStr := ":" + strconv.Itoa(dstPort)

	extractInfo := func(line string) (foundEmail, foundIP, foundTag string) {
		if m := xrayEmailRegex.FindStringSubmatch(line); len(m) >= 2 {
			foundEmail = m[1]
		} else if m := sbInboundTagRegex.FindStringSubmatch(line); len(m) >= 2 {
			foundEmail = m[1]
		} else if m := sbBracketUser.FindStringSubmatch(line); len(m) >= 2 {
			foundEmail = m[1]
		} else if m := sbRouterMatchRegex.FindStringSubmatch(line); len(m) >= 2 {
			foundEmail = m[1]
		} else if m := genericEmailRegex.FindStringSubmatch(line); len(m) >= 2 {
			foundEmail = m[1]
		} else if m := xrayAcceptedRegex.FindStringSubmatch(line); len(m) >= 2 {
			foundEmail = m[1]
		} else if m := xrayUserTagRegex.FindStringSubmatch(line); len(m) >= 2 {
			foundEmail = m[1]
		} else if m := xrayJSONUserRegex.FindStringSubmatch(line); len(m) >= 2 {
			foundEmail = m[1]
		} else if m := sbConnUserRegex.FindStringSubmatch(line); len(m) >= 2 {
			foundEmail = m[1]
		} else if m := sbAcceptedRegex.FindStringSubmatch(line); len(m) >= 2 {
			foundEmail = m[1]
		} else if m := sbEndUserRegex.FindStringSubmatch(line); len(m) >= 2 {
			foundEmail = m[1]
		}

		if foundEmail == "" {
			return "", "", ""
		}

		foundEmail = strings.Trim(foundEmail, "[]'\"")
		if isIgnoredTagOrLevel(foundEmail) {
			return "", "", ""
		}

		if m := xrayIPAcceptedRegex.FindStringSubmatch(line); len(m) >= 2 {
			foundIP = m[1]
		} else if m := xrayIPFromRegex.FindStringSubmatch(line); len(m) >= 2 {
			foundIP = m[1]
		} else {
			foundIP = clientIP
		}

		if m := sbInboundTagFromPrefix.FindStringSubmatch(line); len(m) >= 2 {
			foundTag = m[1]
		} else if m := xrayTagMatchRegex.FindStringSubmatch(line); len(m) >= 2 {
			foundTag = m[1]
		} else if m := sbInboundConnTag.FindStringSubmatch(line); len(m) >= 2 {
			foundTag = m[1]
		} else {
			foundTag = "proxy"
		}

		return foundEmail, foundIP, foundTag
	}

	extractDestHost := func(line string) string {
		if m := xrayDestMatchRegex.FindStringSubmatch(line); len(m) >= 2 {
			return strings.Trim(m[1], "[]")
		}
		if idx := strings.Index(line, "inbound connection to "); idx != -1 {
			rem := line[idx+len("inbound connection to "):]
			if parts := strings.Split(rem, ":"); len(parts) >= 2 {
				return strings.Trim(parts[0], "[] \t")
			}
		}
		return ""
	}

	// Pre-compute connID→clientIP map for sing-box two-line log format.
	connIDToIP := make(map[string]string)
	for _, l := range lines {
		if m := sbFromIPLineRegex.FindStringSubmatch(l); len(m) >= 3 {
			connIDToIP[m[1]] = m[2]
		}
	}

	for i := len(lines) - 1; i >= 0; i-- {
		line := lines[i]
		t := ParseXrayTimestamp(line)
		if !checkAge(t, maxAgeSec) {
			continue
		}

		if !strings.Contains(line, dstPortStr) {
			continue
		}

		// Verify dstIP strictly if specified
		if dstIP != "" {
			destHost := extractDestHost(line)
			if destHost != "" {
				if destHost != dstIP {
					continue
				}
			} else if !strings.Contains(line, dstIP) {
				continue
			}
		}

		// Verify clientIP if specified
		if clientIP != "" {
			matchClient := strings.Contains(line, clientIP)
			if !matchClient {
				if m := sbConnIDLineRegex.FindStringSubmatch(line); len(m) >= 2 {
					if cachedIP, ok := connIDToIP[m[1]]; ok && cachedIP == clientIP {
						matchClient = true
					}
				}
			}
			if !matchClient {
				continue
			}
		}

		e, p, tag := extractInfo(line)
		if e != "" {
			// If IP not found in this line, fill from connID cache.
			if p == "" || p == clientIP {
				if m := sbConnIDLineRegex.FindStringSubmatch(line); len(m) >= 2 {
					if cachedIP, ok := connIDToIP[m[1]]; ok {
						p = cachedIP
					}
				}
			}
			return e, p, tag
		}
	}

	return "", "", ""
}

