package parser

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/blackalex1/sentinel-core/pkg/ast"
)

func parseVLESS(raw string) (*ast.ServerProfile, error) {
	cleanURI, fragment := extractFragmentAndClean(raw)
	u, err := url.Parse(cleanURI)
	if err != nil {
		return nil, fmt.Errorf("failed to parse vless URI: %w", err)
	}

	port := 443
	if u.Port() != "" {
		p, err := strconv.Atoi(u.Port())
		if err != nil || p <= 0 || p > 65535 {
			return nil, fmt.Errorf("invalid port in vless URI: %s", u.Port())
		}
		port = p
	}

	if !isValidHost(u.Hostname()) {
		return nil, fmt.Errorf("invalid host in vless URI")
	}

	if u.User == nil || u.User.Username() == "" {
		return nil, fmt.Errorf("vless URI missing uuid")
	}
	uuid := u.User.Username()

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
		Protocol:    ast.ProtoVLESS,
		UUID:        uuid,
		Address:     u.Hostname(),
		Port:        port,
		Name:        name,
		Transport:   q.Get("type"),
		Security:    q.Get("security"),
		Flow:        q.Get("flow"),
		Encryption:  q.Get("encryption"),
		SNI:         q.Get("sni"),
		Fingerprint: q.Get("fp"),
		PublicKey:   q.Get("pbk"),
		ShortID:     q.Get("sid"),
		SpiderX:     q.Get("spx"),
		Path:        q.Get("path"),
		Host:        q.Get("host"),
		ServiceName: q.Get("serviceName"),
		ALPN:        alpn,
		Insecure:    q.Get("allowInsecure") == "1" || q.Get("insecure") == "1",
		PostQuantum: q.Get("pq") == "1" || q.Get("post_quantum") == "true" || q.Get("post_quantum") == "1" || strings.HasPrefix(q.Get("encryption"), "mlkem"),
		Mux:         q.Get("mux") == "1" || q.Get("mux") == "true",
	}

	if profile.Name == "" {
		profile.Name = fmt.Sprintf("VLESS-%s:%d", profile.Address, profile.Port)
	}
	profile.Normalize()
	return profile, nil
}
