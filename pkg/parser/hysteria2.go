package parser

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/blackalex1/sentinel-core/pkg/ast"
)

func parseHysteria2(raw string) (*ast.ServerProfile, error) {
	cleanURI, fragment := extractFragmentAndClean(raw)
	clean := strings.Replace(cleanURI, "hysteria2://", "hy2://", 1)
	u, err := url.Parse(clean)
	if err != nil {
		return nil, fmt.Errorf("failed to parse hysteria2 URI: %w", err)
	}

	port := 443
	if u.Port() != "" {
		p, err := strconv.Atoi(u.Port())
		if err != nil || p <= 0 || p > 65535 {
			return nil, fmt.Errorf("invalid port in hysteria2 URI: %s", u.Port())
		}
		port = p
	}

	if !isValidHost(u.Hostname()) {
		return nil, fmt.Errorf("invalid host in hysteria2 URI")
	}

	var username, password string
	if u.User != nil {
		username = u.User.Username()
		if p, ok := u.User.Password(); ok {
			password = p
		} else {
			password = username
			username = ""
		}
	}

	q := u.Query()
	portHopping := q.Get("mport")
	if portHopping == "" {
		portHopping = q.Get("ports")
	}
	if portHopping == "" {
		portHopping = q.Get("port_hopping")
	}
	if portHopping == "" {
		portHopping = q.Get("hop")
	}

	var alpn []string
	if alpnStr := q.Get("alpn"); alpnStr != "" {
		alpn = strings.Split(alpnStr, ",")
	}

	pinSHA256 := q.Get("pinSHA256")
	if pinSHA256 == "" {
		pinSHA256 = q.Get("pin_sha256")
	}
	if pinSHA256 == "" {
		pinSHA256 = q.Get("pin-sha256")
	}
	if pinSHA256 == "" {
		pinSHA256 = q.Get("pinnedPeerCertSha256")
	}
	if pinSHA256 == "" {
		pinSHA256 = q.Get("pinned_peer_cert_sha256")
	}
	if pinSHA256 == "" {
		pinSHA256 = q.Get("ca-sha256")
	}

	obfsType := q.Get("obfs")
	if obfsType == "" {
		obfsType = q.Get("obfs-type")
	}
	if obfsType == "" {
		obfsType = q.Get("obfs_type")
	}

	obfsPassword := q.Get("obfs-password")
	if obfsPassword == "" {
		obfsPassword = q.Get("obfs_password")
	}
	if obfsPassword == "" {
		obfsPassword = q.Get("obfsPassword")
	}
	if obfsPassword == "" {
		obfsPassword = q.Get("obfs-pass")
	}
	if obfsPassword == "" {
		obfsPassword = q.Get("obfspass")
	}
	if obfsPassword == "" {
		obfsPassword = q.Get("obfs_pass")
	}

	insecureVal := q.Get("insecure")
	allowInsecVal := q.Get("allowInsecure")
	isInsecure := insecureVal == "1" || insecureVal == "true" || allowInsecVal == "1" || allowInsecVal == "true"

	name := fragment
	if name == "" {
		name = u.Fragment
	}

	bwUp := q.Get("up")
	if bwUp == "" {
		bwUp = q.Get("upmbps")
	}
	if bwUp == "" {
		bwUp = q.Get("up_mbps")
	}
	if bwUp == "" {
		bwUp = q.Get("upload")
	}

	bwDown := q.Get("down")
	if bwDown == "" {
		bwDown = q.Get("downmbps")
	}
	if bwDown == "" {
		bwDown = q.Get("down_mbps")
	}
	if bwDown == "" {
		bwDown = q.Get("download")
	}

	profile := &ast.ServerProfile{
		Protocol:             ast.ProtoHysteria2,
		Username:             username,
		Password:             password,
		Address:              u.Hostname(),
		Port:                 port,
		Name:                 name,
		SNI:                  q.Get("sni"),
		Insecure:             isInsecure,
		PinnedPeerCertSha256: pinSHA256,
		ObfsType:             obfsType,
		ObfsPassword:         obfsPassword,
		PortHopping:          portHopping,
		BandwidthUp:          bwUp,
		BandwidthDown:        bwDown,
		ALPN:                 alpn,
	}

	if profile.Name == "" {
		profile.Name = fmt.Sprintf("Hy2-%s:%d", profile.Address, profile.Port)
	}
	profile.Normalize()
	return profile, nil
}
