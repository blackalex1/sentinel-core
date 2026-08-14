package routing

import (
	"net"
	"net/url"
	"strings"
)

// SanitizeDomain cleans and extracts a valid domain name from user input.
// Handles cases like: "https://example.com/path", "*.example.com", ".example.com", "example.com:8080", "geosite:google".
func SanitizeDomain(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}

	// Preserve geosite / domain / regexp / regex prefixes if present
	if strings.HasPrefix(s, "geosite:") || strings.HasPrefix(s, "regexp:") || strings.HasPrefix(s, "regex:") {
		return s
	}
	if strings.HasPrefix(s, "domain:") {
		return "domain:" + SanitizeDomain(strings.TrimPrefix(s, "domain:"))
	}
	if strings.HasPrefix(s, "full:") {
		return "full:" + SanitizeDomain(strings.TrimPrefix(s, "full:"))
	}
	if strings.HasPrefix(s, "keyword:") {
		return s
	}

	// Strip URL scheme and path if user pasted a full URL
	if strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") {
		if u, err := url.Parse(s); err == nil && u.Hostname() != "" {
			s = u.Hostname()
		}
	} else if strings.Contains(s, "/") {
		parts := strings.SplitN(s, "/", 2)
		s = parts[0]
	}

	// Strip port if user entered domain:port
	if strings.Contains(s, ":") && !strings.Contains(s, "]") { // Ignore raw IPv6 brackets
		host, _, err := net.SplitHostPort(s)
		if err == nil && host != "" {
			s = host
		}
	}

	// Strip wildcards (*.example.com -> example.com)
	s = strings.TrimPrefix(s, "*.")
	s = strings.TrimPrefix(s, ".")
	s = strings.ToLower(strings.TrimSpace(s))

	return s
}

// SanitizeIP cleans and validates user-entered IP or CIDR range.
// Handles cases like: "1.2.3.4", "1.2.3.4:8080", "192.168.1.0/24", "geoip:ru".
func SanitizeIP(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}

	if strings.HasPrefix(s, "geoip:") {
		return s
	}
	if strings.HasPrefix(s, "ip:") {
		return strings.TrimPrefix(s, "ip:")
	}

	// Strip port if IP:port
	if strings.Contains(s, ":") && !strings.Contains(s, "/") {
		host, _, err := net.SplitHostPort(s)
		if err == nil && host != "" {
			s = host
		}
	}

	// If valid plain IP without mask, return it
	if parsedIP := net.ParseIP(s); parsedIP != nil {
		if parsedIP.To4() != nil {
			return s + "/32" // Single IPv4 host
		}
		return s + "/128" // Single IPv6 host
	}

	// If valid CIDR
	if _, _, err := net.ParseCIDR(s); err == nil {
		return s
	}

	return s
}

// CleanStringList splits by comma/newline/space and sanitizes all domains
func CleanDomainList(items []string) []string {
	var result []string
	seen := make(map[string]bool)

	for _, item := range items {
		// Support comma or newline separated lists in single string
		parts := strings.FieldsFunc(item, func(r rune) bool {
			return r == ',' || r == '\n' || r == '\r' || r == ';' || r == ' '
		})
		for _, p := range parts {
			cleaned := SanitizeDomain(p)
			if cleaned != "" && !seen[cleaned] {
				seen[cleaned] = true
				result = append(result, cleaned)
			}
		}
	}
	return result
}

// CleanIPList splits and sanitizes IP addresses and CIDR blocks
func CleanIPList(items []string) []string {
	var result []string
	seen := make(map[string]bool)

	for _, item := range items {
		parts := strings.FieldsFunc(item, func(r rune) bool {
			return r == ',' || r == '\n' || r == '\r' || r == ';' || r == ' '
		})
		for _, p := range parts {
			cleaned := SanitizeIP(p)
			if cleaned != "" && !seen[cleaned] {
				seen[cleaned] = true
				result = append(result, cleaned)
			}
		}
	}
	return result
}
