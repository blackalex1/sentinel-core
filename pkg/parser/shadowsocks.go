package parser

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/blackalex1/sentinel-core/pkg/ast"
)

func parseShadowsocks(raw string) (*ast.ServerProfile, error) {
	// Format: ss://BASE64@host:port#name or ss://BASE64#name
	cleanURI, fragment := extractFragmentAndClean(raw)
	trimmed := strings.TrimPrefix(cleanURI, "ss://")

	var method, password, host string
	var port int

	if strings.Contains(trimmed, "@") {
		// SIP002 format
		parts := strings.SplitN(trimmed, "@", 2)
		userinfo := parts[0]
		hostport := parts[1]

		decodedUser, err := decodeBase64Safe(userinfo)
		if err == nil {
			userinfo = decodedUser
		}

		userParts := strings.SplitN(userinfo, ":", 2)
		if len(userParts) == 2 {
			method = userParts[0]
			password = userParts[1]
		}

		u, err := url.Parse("http://" + hostport)
		if err == nil {
			host = u.Hostname()
			port, _ = strconv.Atoi(u.Port())
		}
	} else {
		// Legacy Base64 whole string
		decoded, err := decodeBase64Safe(trimmed)
		if err != nil {
			return nil, fmt.Errorf("failed to decode shadowsocks base64: %w", err)
		}
		// format: method:password@host:port
		parts := strings.SplitN(decoded, "@", 2)
		if len(parts) == 2 {
			userParts := strings.SplitN(parts[0], ":", 2)
			if len(userParts) == 2 {
				method = userParts[0]
				password = userParts[1]
			}
			hp := strings.SplitN(parts[1], ":", 2)
			if len(hp) == 2 {
				host = hp[0]
				port, _ = strconv.Atoi(hp[1])
			}
		}
	}

	if !isValidHost(host) || port <= 0 {
		return nil, fmt.Errorf("invalid shadowsocks configuration")
	}

	profile := &ast.ServerProfile{
		Protocol: ast.ProtoShadowsocks,
		Cipher:   method,
		Password: password,
		Address:  host,
		Port:     port,
		Name:     fragment,
	}

	if profile.Name == "" {
		profile.Name = fmt.Sprintf("SS-%s:%d", profile.Address, profile.Port)
	}
	profile.Normalize()
	return profile, nil
}
