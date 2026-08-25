package parser

import (
	"bufio"
	"strings"

	"github.com/blackalex1/sentinel-core/pkg/ast"
)

// ParseSubscription parses a multi-line or base64-encoded subscription containing proxy URIs (vless://, hy2://, trojan://, ss://, etc.)
func ParseSubscription(rawContent string) ([]*ast.ServerProfile, error) {
	trimmed := strings.TrimSpace(rawContent)
	if trimmed == "" {
		return []*ast.ServerProfile{}, nil
	}

	// Try base64 decoding first if it looks like a single continuous base64 block
	if !strings.Contains(trimmed, "://") && !strings.Contains(trimmed, "\n") {
		if decoded, err := decodeBase64Safe(trimmed); err == nil && strings.Contains(decoded, "://") {
			trimmed = decoded
		}
	}

	var profiles []*ast.ServerProfile
	scanner := bufio.NewScanner(strings.NewReader(trimmed))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}

		// Handle inline base64 if needed
		if !strings.Contains(line, "://") {
			if decoded, err := decodeBase64Safe(line); err == nil && strings.Contains(decoded, "://") {
				line = strings.TrimSpace(decoded)
			}
		}

		// Parse the URI into ServerProfile
		p, err := ParseURI(line)
		if err == nil && p != nil {
			profiles = append(profiles, p)
		}
	}

	return profiles, scanner.Err()
}
