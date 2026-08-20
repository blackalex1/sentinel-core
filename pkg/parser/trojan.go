package parser

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/blackalex1/sentinel-core/pkg/ast"
)

func parseTrojan(raw string) (*ast.ServerProfile, error) {
	cleanURI, fragment := extractFragmentAndClean(raw)
	u, err := url.Parse(cleanURI)
	if err != nil {
		return nil, fmt.Errorf("failed to parse trojan URI: %w", err)
	}

	port := 443
	if u.Port() != "" {
		p, err := strconv.Atoi(u.Port())
		if err != nil || p <= 0 || p > 65535 {
			return nil, fmt.Errorf("invalid port in trojan URI: %s", u.Port())
		}
		port = p
	}

	if !isValidHost(u.Hostname()) {
		return nil, fmt.Errorf("invalid host in trojan URI")
	}

	if u.User == nil || u.User.Username() == "" {
		return nil, fmt.Errorf("trojan URI missing password")
	}
	password := u.User.Username()

	q := u.Query()
	var alpn []string
	if alpnStr := q.Get("alpn"); alpnStr != "" {
		alpn = strings.Split(alpnStr, ",")
	}

	name := fragment
	if name == "" {
		name = u.Fragment
	}

	profile := &ast.ServerProfile{
		Protocol:    ast.ProtoTrojan,
		Password:    password,
		Address:     u.Hostname(),
		Port:        port,
		Name:        name,
		Transport:   q.Get("type"),
		Security:    q.Get("security"),
		SNI:         q.Get("sni"),
		Fingerprint: q.Get("fp"),
		Path:        q.Get("path"),
		Host:        q.Get("host"),
		ServiceName: q.Get("serviceName"),
		ALPN:        alpn,
		Insecure:    q.Get("allowInsecure") == "1" || q.Get("insecure") == "1",
	}

	if profile.Security == "" {
		profile.Security = ast.SecurityTLS
	}
	if profile.Name == "" {
		profile.Name = fmt.Sprintf("Trojan-%s:%d", profile.Address, profile.Port)
	}
	profile.Normalize()
	return profile, nil
}
