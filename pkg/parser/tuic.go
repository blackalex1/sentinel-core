package parser

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/blackalex1/sentinel-core/pkg/ast"
)

func parseTUIC(raw string) (*ast.ServerProfile, error) {
	cleanURI, fragment := extractFragmentAndClean(raw)
	u, err := url.Parse(cleanURI)
	if err != nil {
		return nil, fmt.Errorf("failed to parse tuic URI: %w", err)
	}

	port := 443
	if u.Port() != "" {
		p, err := strconv.Atoi(u.Port())
		if err != nil || p <= 0 || p > 65535 {
			return nil, fmt.Errorf("invalid port in tuic URI: %s", u.Port())
		}
		port = p
	}

	if !isValidHost(u.Hostname()) {
		return nil, fmt.Errorf("invalid host in tuic URI")
	}

	q := u.Query()
	password := ""
	uuid := ""
	if u.User != nil {
		uuid = u.User.Username()
		if pass, ok := u.User.Password(); ok {
			password = pass
		}
	}

	var alpn []string
	if alpnStr := q.Get("alpn"); alpnStr != "" {
		alpn = strings.Split(alpnStr, ",")
	}

	name := fragment
	if name == "" {
		name = u.Fragment
	}

	profile := &ast.ServerProfile{
		Protocol:          ast.ProtoTUIC,
		UUID:              uuid,
		Password:          password,
		Address:           u.Hostname(),
		Port:              port,
		Name:              name,
		SNI:               q.Get("sni"),
		CongestionControl: q.Get("congestion_control"),
		UDPRelayMode:      q.Get("udp_relay_mode"),
		Insecure:          q.Get("allow_insecure") == "1" || q.Get("insecure") == "1",
		ZeroRTTHandshake:  q.Get("zero_rtt") == "1" || q.Get("zero_rtt_handshake") == "1",
		ALPN:              alpn,
	}

	if profile.Name == "" {
		profile.Name = fmt.Sprintf("TUIC-%s:%d", profile.Address, profile.Port)
	}
	profile.Normalize()
	return profile, nil
}
