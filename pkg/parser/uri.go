package parser

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/blackalex1/sentinel-core/pkg/ast"
)

// isValidHost validates if the parsed hostname is non-empty and well-formed
func isValidHost(host string) bool {
	if host == "" {
		return false
	}
	clean := strings.Trim(host, "[]")
	if strings.Contains(clean, ":") {
		return net.ParseIP(clean) != nil
	}
	return true
}

// normalizeUnbracketedIPv6 fixes unbracketed IPv6 URLs before url.Parse.
// E.g.: "vless://uuid@2001:db8::1:443?query#frag" -> "vless://uuid@[2001:db8::1]:443?query#frag"
func normalizeUnbracketedIPv6(rawURI string) string {
	idxScheme := strings.Index(rawURI, "://")
	if idxScheme == -1 {
		return rawURI
	}
	prefix := rawURI[:idxScheme+3]
	rest := rawURI[idxScheme+3:]

	idxCut := strings.IndexAny(rest, "/?#")
	authority := rest
	suffix := ""
	if idxCut != -1 {
		authority = rest[:idxCut]
		suffix = rest[idxCut:]
	}

	if strings.Contains(authority, "[") && strings.Contains(authority, "]") {
		return rawURI
	}

	userinfo := ""
	hostport := authority
	if atIdx := strings.LastIndex(authority, "@"); atIdx != -1 {
		userinfo = authority[:atIdx+1]
		hostport = authority[atIdx+1:]
	}

	if strings.Count(hostport, ":") > 1 {
		lastColon := strings.LastIndex(hostport, ":")
		possibleHost := hostport[:lastColon]
		possiblePort := hostport[lastColon+1:]
		if ip := net.ParseIP(possibleHost); ip != nil && ip.To4() == nil {
			if _, err := strconv.Atoi(possiblePort); err == nil {
				return prefix + userinfo + "[" + possibleHost + "]:" + possiblePort + suffix
			}
		}
		if ip := net.ParseIP(hostport); ip != nil && ip.To4() == nil {
			return prefix + userinfo + "[" + hostport + "]" + suffix
		}
	}

	return rawURI
}

// extractFragmentAndClean strips out and properly decodes the URI fragment (#name)
// before passing the URL to net/url.Parse to avoid parser failures on emojis, Unicode,
// spaces, pipes, and special characters.
// Also normalizes unbracketed IPv6 host:port into RFC 3986 bracketed form.
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
	trimmed = normalizeUnbracketedIPv6(trimmed)
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
