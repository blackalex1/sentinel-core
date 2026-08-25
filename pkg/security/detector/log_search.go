package detector

import (
	"encoding/json"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	xrayTimeRegex     = regexp.MustCompile(`(\d{4}[/-]\d{2}[/-]\d{2}[ T]\d{2}:\d{2}:\d{2})`)
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
	sbInboundConnTag    = regexp.MustCompile(`\[([^\]]+)\]\s+inbound connection`)
	xrayDestMatchRegex  = regexp.MustCompile(`(?:accepted|connection)\s+(?:tcp|udp):([^:]+):`)
	ipv4CheckRegex      = regexp.MustCompile(`^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$`)
)

// ParseXrayTimestamp extracts a time.Time from an Xray/Sing-box log line.
func ParseXrayTimestamp(line string) *time.Time {
	if m := xrayTimeRegex.FindStringSubmatch(line); len(m) >= 2 {
		normalized := strings.ReplaceAll(m[1], "/", "-")
		normalized = strings.ReplaceAll(normalized, "T", " ")
		if t, err := time.Parse("2006-01-02 15:04:05", normalized); err == nil {
			return &t
		}
	}
	return nil
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

func checkAge(logTime *time.Time, maxAgeSec int) bool {
	if logTime == nil || maxAgeSec <= 0 {
		return true
	}
	nowLocal := time.Now()
	nowUTC := time.Now().UTC()

	logSec := logTime.Unix()
	nowLocalNaiveSec := time.Date(nowLocal.Year(), nowLocal.Month(), nowLocal.Day(), nowLocal.Hour(), nowLocal.Minute(), nowLocal.Second(), 0, time.UTC).Unix()
	nowUTCNaiveSec := time.Date(nowUTC.Year(), nowUTC.Month(), nowUTC.Day(), nowUTC.Hour(), nowUTC.Minute(), nowUTC.Second(), 0, time.UTC).Unix()

	diffLocal := math.Abs(float64(nowLocalNaiveSec - logSec))
	diffUTC := math.Abs(float64(nowUTCNaiveSec - logSec))

	return diffLocal <= float64(maxAgeSec) || diffUTC <= float64(maxAgeSec)
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

	// Pass 1: Match port and IP (main search from newest to oldest)
	for i := len(lines) - 1; i >= 0; i-- {
		line := lines[i]
		t := ParseHysteriaTimestamp(line)
		if !checkAge(t, maxAgeSec) {
			continue
		}

		if !strings.Contains(line, dstPortStr) {
			continue
		}

		if dstIP != "" && !strings.Contains(line, dstIP) {
			continue
		}

		if email := extractEmail(line); email != "" {
			return email
		}
	}

	// Pass 2: Match port only with destination IP verification fallback
	for i := len(lines) - 1; i >= 0; i-- {
		line := lines[i]
		t := ParseHysteriaTimestamp(line)
		if !checkAge(t, maxAgeSec) {
			continue
		}

		if !strings.Contains(line, dstPortStr) {
			continue
		}

		destHost := ""
		if strings.Contains(line, "{") {
			var obj map[string]any
			if err := json.Unmarshal([]byte(line), &obj); err == nil {
				reqVal, _ := obj["reqAddr"].(string)
				if reqVal == "" {
					reqVal, _ = obj["req"].(string)
				}
				if reqVal != "" && strings.Contains(reqVal, ":") {
					destHost = strings.Trim(strings.Split(reqVal, ":")[0], "[]")
				}
			}
		}

		if destHost == "" {
			if m := hyDestHostRegex.FindStringSubmatch(line); len(m) >= 2 {
				destHost = strings.Trim(m[1], "[]")
			}
		}

		if destHost != "" && dstIP != "" && ipv4CheckRegex.MatchString(destHost) {
			if destHost != dstIP {
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

		if strings.Contains(line, "{") {
			var obj map[string]any
			if err := json.Unmarshal([]byte(line), &obj); err == nil {
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
		if m := sbInboundTagRegex.FindStringSubmatch(line); len(m) >= 2 {
			foundEmail = m[1]
		} else if m := sbBracketUser.FindStringSubmatch(line); len(m) >= 2 {
			foundEmail = m[1]
		} else if m := xrayEmailRegex.FindStringSubmatch(line); len(m) >= 2 {
			foundEmail = m[1]
		} else if m := xrayAcceptedRegex.FindStringSubmatch(line); len(m) >= 2 {
			foundEmail = m[1]
		} else if m := xrayUserTagRegex.FindStringSubmatch(line); len(m) >= 2 {
			foundEmail = m[1]
		} else if m := xrayJSONUserRegex.FindStringSubmatch(line); len(m) >= 2 {
			foundEmail = m[1]
		} else if m := sbConnUserRegex.FindStringSubmatch(line); len(m) >= 2 {
			foundEmail = m[1]
		} else if m := sbEndUserRegex.FindStringSubmatch(line); len(m) >= 2 {
			foundEmail = m[1]
		} else if m := genericEmailRegex.FindStringSubmatch(line); len(m) >= 2 {
			foundEmail = m[1]
		}

		if foundEmail == "" {
			return "", "", ""
		}

		foundEmail = strings.Trim(foundEmail, "[]'\"")

		if m := xrayIPAcceptedRegex.FindStringSubmatch(line); len(m) >= 2 {
			foundIP = m[1]
		} else if m := xrayIPFromRegex.FindStringSubmatch(line); len(m) >= 2 {
			foundIP = m[1]
		} else {
			foundIP = clientIP
		}

		if m := xrayTagMatchRegex.FindStringSubmatch(line); len(m) >= 2 {
			foundTag = m[1]
		} else if m := sbInboundConnTag.FindStringSubmatch(line); len(m) >= 2 {
			foundTag = m[1]
		} else {
			foundTag = "proxy"
		}

		return foundEmail, foundIP, foundTag
	}

	// Pass 1: Match port and IP/client_ip
	for i := len(lines) - 1; i >= 0; i-- {
		line := lines[i]
		t := ParseXrayTimestamp(line)
		if !checkAge(t, maxAgeSec) {
			continue
		}

		if !strings.Contains(line, dstPortStr) {
			continue
		}

		matchIP := (dstIP != "" && strings.Contains(line, dstIP)) || (clientIP != "" && strings.Contains(line, clientIP)) || dstIP == ""
		if !matchIP {
			continue
		}

		e, p, tag := extractInfo(line)
		if e != "" {
			return e, p, tag
		}
	}

	// Pass 2: Match port only with destination verification fallback
	for i := len(lines) - 1; i >= 0; i-- {
		line := lines[i]
		t := ParseXrayTimestamp(line)
		if !checkAge(t, maxAgeSec) {
			continue
		}

		if !strings.Contains(line, dstPortStr) {
			continue
		}

		if m := xrayDestMatchRegex.FindStringSubmatch(line); len(m) >= 2 {
			destHost := strings.Trim(m[1], "[]")
			if dstIP != "" && ipv4CheckRegex.MatchString(destHost) {
				if destHost != dstIP {
					continue
				}
			}
		}

		e, p, tag := extractInfo(line)
		if e != "" {
			return e, p, tag
		}
	}

	return "", "", ""
}
