package parser

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/blackalex1/sentinel-core/pkg/ast"
)

// isValidHost validates if the parsed hostname is non-empty and well-formed
func isValidHost(host string) bool {
	if host == "" {
		return false
	}
	if strings.Contains(host, ":") {
		return net.ParseIP(host) != nil
	}
	return true
}

// extractFragmentAndClean strips out and properly decodes the URI fragment (#name)
// before passing the URL to net/url.Parse to avoid parser failures on emojis, Unicode,
// spaces, pipes, and special characters.
func extractFragmentAndClean(rawURI string) (string, string) {
	trimmed := strings.TrimSpace(rawURI)
	fragment := ""
	if idx := strings.Index(trimmed, "#"); idx != -1 {
		rawFrag := trimmed[idx+1:]
		trimmed = trimmed[:idx]
		if unescaped, err := url.QueryUnescape(rawFrag); err == nil && unescaped != "" {
			fragment = unescaped
		} else {
			fragment = rawFrag
		}
	}
	return trimmed, fragment
}

// decodeBase64Safe decodes base64 strings with or without padding (standard, URL-safe, raw).
func decodeBase64Safe(s string) (string, error) {
	s = strings.TrimSpace(s)
	if rem := len(s) % 4; rem > 0 {
		s += strings.Repeat("=", 4-rem)
	}
	bytes, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		bytes, err = base64.URLEncoding.DecodeString(s)
		if err != nil {
			bytes, err = base64.RawStdEncoding.DecodeString(s)
			if err != nil {
				return "", err
			}
		}
	}
	return string(bytes), nil
}

// ParseURI converts any proxy URI link into a normalized ast.ServerProfile.
func ParseURI(rawURI string) (*ast.ServerProfile, error) {
	trimmed := strings.TrimSpace(rawURI)
	if trimmed == "" {
		return nil, fmt.Errorf("URI cannot be empty")
	}

	lower := strings.ToLower(trimmed)
	if strings.HasPrefix(trimmed, "{") {
		return ParseXrayConfigJSON(trimmed)
	} else if strings.HasPrefix(lower, "vless://") {
		return parseVLESS(trimmed)
	} else if strings.HasPrefix(lower, "vmess://") {
		return parseVMess(trimmed)
	} else if strings.HasPrefix(lower, "trojan://") {
		return parseTrojan(trimmed)
	} else if strings.HasPrefix(lower, "hy2://") || strings.HasPrefix(lower, "hysteria2://") {
		return parseHysteria2(trimmed)
	} else if strings.HasPrefix(lower, "ss://") {
		return parseShadowsocks(trimmed)
	} else if strings.HasPrefix(lower, "tuic://") {
		return parseTUIC(trimmed)
	} else if strings.HasPrefix(lower, "shadowtls://") {
		return parseShadowTLS(trimmed)
	} else if strings.HasPrefix(lower, "wireguard://") || strings.HasPrefix(lower, "wg://") {
		return parseWireGuard(trimmed)
	} else if strings.HasPrefix(lower, "socks5://") || strings.HasPrefix(lower, "socks://") {
		return parseSocks(trimmed)
	} else if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		return parseHTTP(trimmed)
	}

	return nil, fmt.Errorf("unsupported or unrecognized URI scheme: %s", trimmed)
}
