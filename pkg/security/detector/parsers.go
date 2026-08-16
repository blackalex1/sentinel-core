package detector

import (
	"strings"
)

var (
	defaultSingboxParser  = NewSingboxParser()
	defaultXrayParser     = NewXrayParser()
	defaultHysteriaParser = NewHysteriaParser()
)

// ParseCoreLogLine dispatches parsing to the corresponding core-specific parser.
func ParseCoreLogLine(coreName, line string) (*ParsedLogEvent, bool) {
	cleanLine := strings.TrimSpace(line)
	if cleanLine == "" {
		return nil, false
	}

	normCore := strings.ToLower(strings.TrimSpace(coreName))

	switch {
	case strings.Contains(normCore, "sing-box") || strings.Contains(normCore, "singbox"):
		return defaultSingboxParser.ParseLogLine(cleanLine)

	case strings.Contains(normCore, "xray"):
		return defaultXrayParser.ParseLogLine(cleanLine)

	case strings.Contains(normCore, "hysteria"):
		return defaultHysteriaParser.ParseLogLine(cleanLine)

	default:
		// Fallback: try all registered parsers sequentially
		if ev, ok := defaultSingboxParser.ParseLogLine(cleanLine); ok {
			return ev, true
		}
		if ev, ok := defaultXrayParser.ParseLogLine(cleanLine); ok {
			return ev, true
		}
		if ev, ok := defaultHysteriaParser.ParseLogLine(cleanLine); ok {
			return ev, true
		}
	}

	return nil, false
}
