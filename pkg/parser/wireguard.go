package parser

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/blackalex1/sentinel-core/pkg/ast"
)

func parseWireGuard(raw string) (*ast.ServerProfile, error) {
	cleanURI, fragment := extractFragmentAndClean(raw)
	clean := cleanURI
	if strings.HasPrefix(clean, "wg://") {
		clean = "wireguard://" + strings.TrimPrefix(clean, "wg://")
	}
	u, err := url.Parse(clean)
	if err != nil {
		return nil, fmt.Errorf("failed to parse wireguard URI: %w", err)
	}

	port := 51820
	if u.Port() != "" {
		p, err := strconv.Atoi(u.Port())
		if err != nil || p <= 0 || p > 65535 {
			return nil, fmt.Errorf("invalid port in wireguard URI: %s", u.Port())
		}
		port = p
	}

	if !isValidHost(u.Hostname()) {
		return nil, fmt.Errorf("invalid host in wireguard URI")
	}

	q := u.Query()
	privKey := ""
	if u.User != nil {
		privKey = u.User.Username()
	}
	if privKey == "" {
		privKey = q.Get("privatekey")
	}

	peerPub := q.Get("publickey")
	if peerPub == "" {
		peerPub = q.Get("peer_public_key")
	}
	if peerPub == "" {
		peerPub = q.Get("peer_pub")
	}

	psk := q.Get("presharedkey")
	if psk == "" {
		psk = q.Get("psk")
	}

	ipStr := q.Get("ip")
	if ipStr == "" {
		ipStr = q.Get("address")
	}
	if ipStr == "" {
		ipStr = q.Get("local_address")
	}

	var localAddrs []string
	if ipStr != "" {
		for _, addr := range strings.Split(ipStr, ",") {
			trimmed := strings.TrimSpace(addr)
			if trimmed != "" {
				localAddrs = append(localAddrs, trimmed)
			}
		}
	}

	mtu, _ := strconv.Atoi(q.Get("mtu"))

	var reserved []int
	if resStr := q.Get("reserved"); resStr != "" {
		for _, r := range strings.Split(resStr, ",") {
			if num, err := strconv.Atoi(strings.TrimSpace(r)); err == nil {
				reserved = append(reserved, num)
			}
		}
	}

	name := fragment
	if name == "" {
		name = u.Fragment
	}

	profile := &ast.ServerProfile{
		Protocol:      ast.ProtoWireGuard,
		Address:       u.Hostname(),
		Port:          port,
		Name:          name,
		PrivateKey:    privKey,
		PeerPublicKey: peerPub,
		PreSharedKey:  psk,
		LocalAddress:  localAddrs,
		MTU:           mtu,
		ReservedBytes: reserved,
	}

	if profile.Name == "" {
		profile.Name = fmt.Sprintf("WG-%s:%d", profile.Address, profile.Port)
	}
	profile.Normalize()
	return profile, nil
}
