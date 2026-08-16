package integrity

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

var (
	// Dangerous cloud metadata endpoints (SSRF vectors)
	cloudMetadataIPs = []string{
		"169.254.169.254", // AWS, Azure, OpenStack, GCP metadata
		"100.100.100.200", // Alibaba Cloud metadata
		"169.254.170.2",   // AWS ECS Task metadata
	}

	cloudMetadataHosts = []string{
		"metadata.google.internal",
		"metadata.goog",
		"instance-data",
	}

	// Shell command injection tokens
	dangerousExecPatterns = regexp.MustCompile(`[;&|` + "`" + `$\\]`)
)

// Sanitizer audits and cleans configs and endpoints to prevent SSRF and injection vulnerabilities.
type Sanitizer struct {
	blockMetadata bool
}

// NewSanitizer creates a new configuration and URI sanitizer.
func NewSanitizer(blockMetadata bool) *Sanitizer {
	return &Sanitizer{
		blockMetadata: blockMetadata,
	}
}

// AuditEndpoint checks if an address/host and port are safe to connect to.
func (s *Sanitizer) AuditEndpoint(host string, port int) error {
	trimmedHost := strings.TrimSpace(host)
	if trimmedHost == "" {
		return fmt.Errorf("host cannot be empty")
	}

	if port < 1 || port > 65535 {
		return fmt.Errorf("invalid port number: %d (must be 1-65535)", port)
	}

	// Check shell injection symbols
	if dangerousExecPatterns.MatchString(trimmedHost) {
		return fmt.Errorf("host contains illegal shell injection characters")
	}

	if s.blockMetadata {
		lowerHost := strings.ToLower(trimmedHost)
		for _, metaHost := range cloudMetadataHosts {
			if lowerHost == metaHost || strings.HasSuffix(lowerHost, "."+metaHost) {
				return fmt.Errorf("SSRF violation: connection to cloud metadata domain '%s' is prohibited", host)
			}
		}

		parsedIP := net.ParseIP(trimmedHost)
		if parsedIP != nil {
			for _, metaIP := range cloudMetadataIPs {
				if parsedIP.Equal(net.ParseIP(metaIP)) {
					return fmt.Errorf("SSRF violation: connection to cloud metadata IP '%s' is prohibited", metaIP)
				}
			}
		}
	}

	return nil
}

// AuditURI parses and validates an outbound proxy link (vless://, vmess://, hy2://, trojan://).
func (s *Sanitizer) AuditURI(rawURI string) error {
	trimmed := strings.TrimSpace(rawURI)
	if trimmed == "" {
		return fmt.Errorf("URI cannot be empty")
	}

	u, err := url.Parse(trimmed)
	if err != nil {
		return fmt.Errorf("malformed URI syntax: %w", err)
	}

	host := u.Hostname()
	portStr := u.Port()

	var port int = 443
	if portStr != "" {
		p, err := strconv.Atoi(portStr)
		if err != nil {
			return fmt.Errorf("invalid port in URI: %s", portStr)
		}
		port = p
	}

	return s.AuditEndpoint(host, port)
}

// SanitizeJSONConfig inspects a JSON configuration string for illegal structures or metadata injection.
func (s *Sanitizer) SanitizeJSONConfig(jsonConfig []byte) error {
	var obj map[string]interface{}
	if err := json.Unmarshal(jsonConfig, &obj); err != nil {
		return fmt.Errorf("invalid JSON config syntax: %w", err)
	}

	// Recursively walk through string values and check for cloud metadata addresses
	return s.walkAndInspect(obj)
}

func (s *Sanitizer) walkAndInspect(val interface{}) error {
	switch v := val.(type) {
	case map[string]interface{}:
		for key, child := range v {
			// If key is server, address, host, or server_name, check endpoint
			if strings.EqualFold(key, "server") || strings.EqualFold(key, "address") || strings.EqualFold(key, "host") {
				if strVal, ok := child.(string); ok {
					if err := s.AuditEndpoint(strVal, 443); err != nil {
						return err
					}
				}
			}
			if err := s.walkAndInspect(child); err != nil {
				return err
			}
		}
	case []interface{}:
		for _, elem := range v {
			if err := s.walkAndInspect(elem); err != nil {
				return err
			}
		}
	}
	return nil
}
