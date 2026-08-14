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
	profile := &ast.ServerProfile{
		Protocol:    ast.ProtoVLESS,
		UUID:        u.User.Username(),
		Address:     u.Hostname(),
		Port:        port,
		Name:        u.Fragment,
		Transport:   q.Get("type"),
		Security:    q.Get("security"),
		Flow:        q.Get("flow"),
		SNI:         q.Get("sni"),
		Fingerprint: q.Get("fp"),
		PublicKey:   q.Get("pbk"),
		ShortID:     q.Get("sid"),
		SpiderX:     q.Get("spx"),
		Path:        q.Get("path"),
		ServiceName: q.Get("serviceName"),
		Insecure:    q.Get("allowInsecure") == "1" || q.Get("insecure") == "1",
		PostQuantum: q.Get("pq") == "1" || q.Get("post_quantum") == "true",
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
		ServiceName: q.Get("serviceName"),
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

	q := u.Query()
	portHopping := q.Get("mport")
	if portHopping == "" {
		portHopping = q.Get("ports")
	}
	if portHopping == "" {
		portHopping = q.Get("port_hopping")
	}

	profile := &ast.ServerProfile{
		Protocol:      ast.ProtoHysteria2,
		Password:      u.User.Username(),
		Address:       u.Hostname(),
		Port:          port,
		Name:          u.Fragment,
		SNI:           q.Get("sni"),
		Insecure:      q.Get("insecure") == "1",
		ObfsType:      q.Get("obfs"),
		ObfsPassword:  q.Get("obfs-password"),
		PortHopping:   portHopping,
		BandwidthUp:   q.Get("up"),
		BandwidthDown: q.Get("down"),
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

	port, _ := strconv.Atoi(u.Port())
	q := u.Query()

	password := ""
	if pass, ok := u.User.Password(); ok {
		password = pass
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
		Insecure:          q.Get("allow_insecure") == "1",
		ALPN:              strings.Split(q.Get("alpn"), ","),
	}

	if profile.Name == "" {
		profile.Name = fmt.Sprintf("TUIC-%s:%d", profile.Address, profile.Port)
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
