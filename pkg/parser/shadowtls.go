package parser

import (
	"fmt"
	"net/url"
	"strconv"

	"github.com/blackalex1/sentinel-core/pkg/ast"
)

func parseShadowTLS(raw string) (*ast.ServerProfile, error) {
	cleanURI, fragment := extractFragmentAndClean(raw)
	u, err := url.Parse(cleanURI)
	if err != nil {
		return nil, fmt.Errorf("failed to parse shadowtls URI: %w", err)
	}

	port := 443
	if u.Port() != "" {
		p, err := strconv.Atoi(u.Port())
		if err != nil || p <= 0 || p > 65535 {
			return nil, fmt.Errorf("invalid port in shadowtls URI: %s", u.Port())
		}
		port = p
	}

	if !isValidHost(u.Hostname()) {
		return nil, fmt.Errorf("invalid host in shadowtls URI")
	}

	q := u.Query()
	version := 3
	if vStr := q.Get("v"); vStr != "" {
		if v, err := strconv.Atoi(vStr); err == nil {
			version = v
		}
	} else if vStr := q.Get("version"); vStr != "" {
		if v, err := strconv.Atoi(vStr); err == nil {
			version = v
		}
	}

	sni := q.Get("sni")
	if sni == "" {
		sni = q.Get("host")
	}

	password := ""
	if u.User != nil {
		password = u.User.Username()
		if pass, ok := u.User.Password(); ok && pass != "" {
			password = pass
		}
	}
	if password == "" {
		password = q.Get("password")
	}

	name := fragment
	if name == "" {
		name = u.Fragment
	}

	profile := &ast.ServerProfile{
		Protocol:          ast.ProtoShadowTLS,
		Password:          password,
		ShadowTLSPassword: password,
		Address:           u.Hostname(),
		Port:              port,
		Name:              name,
		Security:          ast.SecurityShadowTLS,
		ShadowTLSSNI:      sni,
		SNI:               sni,
		ShadowTLSVersion:  version,
	}

	if profile.Name == "" {
		profile.Name = fmt.Sprintf("ShadowTLS-%s:%d", profile.Address, profile.Port)
	}
	profile.Normalize()
	return profile, nil
}
