package parser

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/blackalex1/sentinel-core/pkg/ast"
)

func parseSocks(raw string) (*ast.ServerProfile, error) {
	cleanURI, fragment := extractFragmentAndClean(raw)
	clean := cleanURI
	if strings.HasPrefix(clean, "socks5://") {
		clean = "socks://" + strings.TrimPrefix(clean, "socks5://")
	}
	u, err := url.Parse(clean)
	if err != nil {
		return nil, fmt.Errorf("failed to parse socks URI: %w", err)
	}

	port := 1080
	if u.Port() != "" {
		p, err := strconv.Atoi(u.Port())
		if err != nil || p <= 0 || p > 65535 {
			return nil, fmt.Errorf("invalid port in socks URI: %s", u.Port())
		}
		port = p
	}

	if !isValidHost(u.Hostname()) {
		return nil, fmt.Errorf("invalid host in socks URI")
	}

	user := ""
	pass := ""
	if u.User != nil {
		user = u.User.Username()
		pass, _ = u.User.Password()
	}

	name := fragment
	if name == "" {
		name = u.Fragment
	}

	profile := &ast.ServerProfile{
		Protocol: ast.ProtoSocks,
		Username: user,
		Password: pass,
		Address:  u.Hostname(),
		Port:     port,
		Name:     name,
	}

	if profile.Name == "" {
		profile.Name = fmt.Sprintf("Socks-%s:%d", profile.Address, profile.Port)
	}
	profile.Normalize()
	return profile, nil
}

func parseHTTP(raw string) (*ast.ServerProfile, error) {
	cleanURI, fragment := extractFragmentAndClean(raw)
	isTLS := strings.HasPrefix(cleanURI, "https://")
	u, err := url.Parse(cleanURI)
	if err != nil {
		return nil, fmt.Errorf("failed to parse http proxy URI: %w", err)
	}

	if !isValidHost(u.Hostname()) {
		return nil, fmt.Errorf("missing host in http proxy URI")
	}

	port := 80
	if isTLS {
		port = 443
	}
	if u.Port() != "" {
		p, err := strconv.Atoi(u.Port())
		if err != nil || p <= 0 || p > 65535 {
			return nil, fmt.Errorf("invalid port in http proxy URI: %s", u.Port())
		}
		port = p
	}

	user := ""
	pass := ""
	if u.User != nil {
		user = u.User.Username()
		pass, _ = u.User.Password()
	}

	name := fragment
	if name == "" {
		name = u.Fragment
	}

	profile := &ast.ServerProfile{
		Protocol: ast.ProtoHTTP,
		Username: user,
		Password: pass,
		Address:  u.Hostname(),
		Port:     port,
		Name:     name,
	}
	if isTLS {
		profile.Security = ast.SecurityTLS
		profile.SNI = u.Hostname()
	}

	if profile.Name == "" {
		profile.Name = fmt.Sprintf("HTTP-%s:%d", profile.Address, profile.Port)
	}
	profile.Normalize()
	return profile, nil
}
