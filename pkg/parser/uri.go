package parser

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"github.com/blackalex1/sentinel-core/pkg/ast"
)

// ParseURI converts any proxy URI link into a normalized ast.ServerProfile.
func ParseURI(rawURI string) (*ast.ServerProfile, error) {
	trimmed := strings.TrimSpace(rawURI)
	if trimmed == "" {
		return nil, fmt.Errorf("URI cannot be empty")
	}

	if strings.HasPrefix(trimmed, "vless://") {
		return parseVLESS(trimmed)
	} else if strings.HasPrefix(trimmed, "vmess://") {
		return parseVMess(trimmed)
	} else if strings.HasPrefix(trimmed, "trojan://") {
		return parseTrojan(trimmed)
	} else if strings.HasPrefix(trimmed, "hy2://") || strings.HasPrefix(trimmed, "hysteria2://") {
		return parseHysteria2(trimmed)
	} else if strings.HasPrefix(trimmed, "ss://") {
		return parseShadowsocks(trimmed)
	} else if strings.HasPrefix(trimmed, "tuic://") {
		return parseTUIC(trimmed)
	} else if strings.HasPrefix(trimmed, "shadowtls://") {
		return parseShadowTLS(trimmed)
	} else if strings.HasPrefix(trimmed, "wireguard://") || strings.HasPrefix(trimmed, "wg://") {
		return parseWireGuard(trimmed)
	} else if strings.HasPrefix(trimmed, "socks5://") || strings.HasPrefix(trimmed, "socks://") {
		return parseSocks(trimmed)
	} else if strings.HasPrefix(trimmed, "http://") || strings.HasPrefix(trimmed, "https://") {
		return parseHTTP(trimmed)
	}

	return nil, fmt.Errorf("unsupported or unrecognized URI scheme: %s", trimmed)
}

func parseVLESS(raw string) (*ast.ServerProfile, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("failed to parse vless URI: %w", err)
	}

	port, err := strconv.Atoi(u.Port())
	if err != nil {
		return nil, fmt.Errorf("invalid port in vless URI: %w", err)
	}

	q := u.Query()
	var alpn []string
	if alpnStr := q.Get("alpn"); alpnStr != "" {
		alpn = strings.Split(alpnStr, ",")
	}

	profile := &ast.ServerProfile{
		Protocol:    ast.ProtoVLESS,
		UUID:        u.User.Username(),
		Address:     u.Hostname(),
		Port:        port,
		Name:        u.Fragment,
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

func parseTrojan(raw string) (*ast.ServerProfile, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("failed to parse trojan URI: %w", err)
	}

	port, err := strconv.Atoi(u.Port())
	if err != nil {
		return nil, fmt.Errorf("invalid port in trojan URI: %w", err)
	}

	q := u.Query()
	var alpn []string
	if alpnStr := q.Get("alpn"); alpnStr != "" {
		alpn = strings.Split(alpnStr, ",")
	}

	profile := &ast.ServerProfile{
		Protocol:    ast.ProtoTrojan,
		Password:    u.User.Username(),
		Address:     u.Hostname(),
		Port:        port,
		Name:        u.Fragment,
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

func parseHysteria2(raw string) (*ast.ServerProfile, error) {
	clean := strings.Replace(raw, "hysteria2://", "hy2://", 1)
	u, err := url.Parse(clean)
	if err != nil {
		return nil, fmt.Errorf("failed to parse hysteria2 URI: %w", err)
	}

	port, err := strconv.Atoi(u.Port())
	if err != nil {
		port = 443
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

	profile := &ast.ServerProfile{
		Protocol:      ast.ProtoHysteria2,
		Username:      username,
		Password:      password,
		Address:       u.Hostname(),
		Port:          port,
		Name:          u.Fragment,
		SNI:           q.Get("sni"),
		Insecure:      q.Get("insecure") == "1" || q.Get("allowInsecure") == "1",
		ObfsType:      q.Get("obfs"),
		ObfsPassword:  q.Get("obfs-password"),
		PortHopping:   portHopping,
		BandwidthUp:   q.Get("up"),
		BandwidthDown: q.Get("down"),
		ALPN:          alpn,
	}

	if profile.Name == "" {
		profile.Name = fmt.Sprintf("Hy2-%s:%d", profile.Address, profile.Port)
	}
	profile.Normalize()
	return profile, nil
}

func parseShadowsocks(raw string) (*ast.ServerProfile, error) {
	// Format: ss://BASE64@host:port#name or ss://BASE64#name
	trimmed := strings.TrimPrefix(raw, "ss://")
	fragment := ""
	if idx := strings.Index(trimmed, "#"); idx != -1 {
		fragment, _ = url.QueryUnescape(trimmed[idx+1:])
		trimmed = trimmed[:idx]
	}

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

	if host == "" || port <= 0 {
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

func parseVMess(raw string) (*ast.ServerProfile, error) {
	b64 := strings.TrimPrefix(raw, "vmess://")
	decoded, err := decodeBase64Safe(b64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode vmess base64: %w", err)
	}

	var v struct {
		V    string      `json:"v"`
		PS   string      `json:"ps"`
		Add  string      `json:"add"`
		Port interface{} `json:"port"`
		ID   string      `json:"id"`
		Net  string      `json:"net"`
		Type string      `json:"type"`
		Host string      `json:"host"`
		Path string      `json:"path"`
		TLS  string      `json:"tls"`
		SNI  string      `json:"sni"`
		ALPN string      `json:"alpn"`
		FP   string      `json:"fp"`
	}

	if err := json.Unmarshal([]byte(decoded), &v); err != nil {
		return nil, fmt.Errorf("failed to parse vmess json: %w", err)
	}

	port := 0
	switch p := v.Port.(type) {
	case float64:
		port = int(p)
	case string:
		port, _ = strconv.Atoi(p)
	}

	var alpn []string
	if v.ALPN != "" {
		alpn = strings.Split(v.ALPN, ",")
	}

	profile := &ast.ServerProfile{
		Protocol:    ast.ProtoVMess,
		Name:        v.PS,
		Address:     v.Add,
		Port:        port,
		UUID:        v.ID,
		Transport:   v.Net,
		Path:        v.Path,
		Host:        v.Host,
		SNI:         v.SNI,
		Fingerprint: v.FP,
		ALPN:        alpn,
	}
	if v.TLS == "tls" {
		profile.Security = ast.SecurityTLS
	}

	if profile.Name == "" {
		profile.Name = fmt.Sprintf("VMess-%s:%d", profile.Address, profile.Port)
	}
	profile.Normalize()
	return profile, nil
}

func parseTUIC(raw string) (*ast.ServerProfile, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("failed to parse tuic URI: %w", err)
	}

	port, err := strconv.Atoi(u.Port())
	if err != nil || u.Hostname() == "" {
		return nil, fmt.Errorf("invalid host or port in tuic URI")
	}
	q := u.Query()

	password := ""
	if pass, ok := u.User.Password(); ok {
		password = pass
	}

	var alpn []string
	if alpnStr := q.Get("alpn"); alpnStr != "" {
		alpn = strings.Split(alpnStr, ",")
	}

	profile := &ast.ServerProfile{
		Protocol:          ast.ProtoTUIC,
		UUID:              u.User.Username(),
		Password:          password,
		Address:           u.Hostname(),
		Port:              port,
		Name:              u.Fragment,
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

func parseShadowTLS(raw string) (*ast.ServerProfile, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("failed to parse shadowtls URI: %w", err)
	}

	port, err := strconv.Atoi(u.Port())
	if err != nil || u.Hostname() == "" {
		return nil, fmt.Errorf("invalid host or port in shadowtls URI: %w", err)
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

	profile := &ast.ServerProfile{
		Protocol:          ast.ProtoShadowTLS,
		Password:          password,
		ShadowTLSPassword: password,
		Address:           u.Hostname(),
		Port:              port,
		Name:              u.Fragment,
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

func parseWireGuard(raw string) (*ast.ServerProfile, error) {
	clean := raw
	if strings.HasPrefix(clean, "wg://") {
		clean = "wireguard://" + strings.TrimPrefix(clean, "wg://")
	}
	u, err := url.Parse(clean)
	if err != nil {
		return nil, fmt.Errorf("failed to parse wireguard URI: %w", err)
	}

	port, err := strconv.Atoi(u.Port())
	if err != nil || u.Hostname() == "" {
		return nil, fmt.Errorf("invalid host or port in wireguard URI: %w", err)
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

	profile := &ast.ServerProfile{
		Protocol:      ast.ProtoWireGuard,
		Address:       u.Hostname(),
		Port:          port,
		Name:          u.Fragment,
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

func parseSocks(raw string) (*ast.ServerProfile, error) {
	clean := raw
	if strings.HasPrefix(clean, "socks5://") {
		clean = "socks://" + strings.TrimPrefix(clean, "socks5://")
	}
	u, err := url.Parse(clean)
	if err != nil {
		return nil, fmt.Errorf("failed to parse socks URI: %w", err)
	}

	port, err := strconv.Atoi(u.Port())
	if err != nil || u.Hostname() == "" {
		return nil, fmt.Errorf("invalid host or port in socks URI: %w", err)
	}

	user := ""
	pass := ""
	if u.User != nil {
		user = u.User.Username()
		pass, _ = u.User.Password()
	}

	profile := &ast.ServerProfile{
		Protocol: ast.ProtoSocks,
		Username: user,
		Password: pass,
		Address:  u.Hostname(),
		Port:     port,
		Name:     u.Fragment,
	}

	if profile.Name == "" {
		profile.Name = fmt.Sprintf("Socks-%s:%d", profile.Address, profile.Port)
	}
	profile.Normalize()
	return profile, nil
}

func parseHTTP(raw string) (*ast.ServerProfile, error) {
	isTLS := strings.HasPrefix(raw, "https://")
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("failed to parse http proxy URI: %w", err)
	}

	if u.Hostname() == "" {
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

	profile := &ast.ServerProfile{
		Protocol: ast.ProtoHTTP,
		Username: user,
		Password: pass,
		Address:  u.Hostname(),
		Port:     port,
		Name:     u.Fragment,
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

func decodeBase64Safe(s string) (string, error) {
	s = strings.TrimSpace(s)
	// Add padding if needed
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
