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

// GenerateURI converts a ServerProfile into a canonical, RFC/Standard-compliant proxy link.
func GenerateURI(p *ast.ServerProfile) (string, error) {
	if p == nil {
		return "", fmt.Errorf("profile cannot be nil")
	}

	proto := strings.ToLower(strings.TrimSpace(p.Protocol))
	switch proto {
	case ast.ProtoVLESS:
		return generateVLESS(p)
	case ast.ProtoHysteria2, "hysteria":
		return generateHysteria2(p)
	case ast.ProtoTrojan:
		return generateTrojan(p)
	case ast.ProtoShadowsocks:
		return generateShadowsocks(p)
	case ast.ProtoVMess:
		return generateVMess(p)
	case ast.ProtoTUIC:
		return generateTUIC(p)
	case ast.ProtoShadowTLS:
		return generateShadowTLS(p)
	case ast.ProtoWireGuard, "wg":
		return generateWireGuard(p)
	case ast.ProtoSocks, "socks5":
		return generateSocks(p)
	case ast.ProtoHTTP, "https":
		return generateHTTP(p)
	default:
		return "", fmt.Errorf("unsupported protocol for URI generation: %s", proto)
	}
}

func generateVLESS(p *ast.ServerProfile) (string, error) {
	q := url.Values{}
	if p.Transport != "" && p.Transport != "tcp" {
		q.Set("type", p.Transport)
	} else if p.Transport == "tcp" {
		q.Set("type", "tcp")
	}

	if p.Security != "" && p.Security != "none" {
		q.Set("security", p.Security)
	}

	if p.Flow != "" {
		q.Set("flow", p.Flow)
	}
	if p.Encryption != "" {
		q.Set("encryption", p.Encryption)
	}
	if p.SNI != "" {
		q.Set("sni", p.SNI)
	}
	if p.Fingerprint != "" {
		q.Set("fp", p.Fingerprint)
	}
	if p.PublicKey != "" {
		q.Set("pbk", p.PublicKey)
	}
	if p.ShortID != "" {
		q.Set("sid", p.ShortID)
	}
	if p.SpiderX != "" {
		q.Set("spx", p.SpiderX)
	}
	if p.Path != "" {
		q.Set("path", p.Path)
	}
	if p.Host != "" {
		q.Set("host", p.Host)
	}
	if p.ServiceName != "" {
		q.Set("serviceName", p.ServiceName)
	}
	if len(p.ALPN) > 0 {
		q.Set("alpn", strings.Join(p.ALPN, ","))
	}
	if p.Insecure {
		q.Set("allowInsecure", "1")
	}

	queryStr := q.Encode()
	uri := fmt.Sprintf("vless://%s@%s:%d", p.UUID, p.Address, p.Port)
	if queryStr != "" {
		uri += "?" + queryStr
	}
	if p.Name != "" {
		uri += "#" + url.QueryEscape(p.Name)
	}
	return uri, nil
}

func generateHysteria2(p *ast.ServerProfile) (string, error) {
	q := url.Values{}
	if p.SNI != "" {
		q.Set("sni", p.SNI)
	}
	if p.Insecure {
		q.Set("insecure", "1")
	}
	if p.ObfsType != "" {
		q.Set("obfs", p.ObfsType)
	}
	if p.ObfsPassword != "" {
		q.Set("obfs-password", p.ObfsPassword)
	}
	if p.PortHopping != "" {
		q.Set("mport", p.PortHopping)
	}
	if len(p.ALPN) > 0 {
		q.Set("alpn", strings.Join(p.ALPN, ","))
	}

	queryStr := q.Encode()
	uri := fmt.Sprintf("hysteria2://%s@%s:%d", url.QueryEscape(p.Password), p.Address, p.Port)
	if queryStr != "" {
		uri += "?" + queryStr
	}
	if p.Name != "" {
		uri += "#" + url.QueryEscape(p.Name)
	}
	return uri, nil
}

func generateTrojan(p *ast.ServerProfile) (string, error) {
	q := url.Values{}
	if p.Transport != "" && p.Transport != "tcp" {
		q.Set("type", p.Transport)
	}
	if p.Security != "" {
		q.Set("security", p.Security)
	}
	if p.SNI != "" {
		q.Set("sni", p.SNI)
	}
	if len(p.ALPN) > 0 {
		q.Set("alpn", strings.Join(p.ALPN, ","))
	}
	if p.Fingerprint != "" {
		q.Set("fp", p.Fingerprint)
	}
	if p.Insecure {
		q.Set("allowInsecure", "1")
	}
	if p.Path != "" {
		q.Set("path", p.Path)
	}
	if p.Host != "" {
		q.Set("host", p.Host)
	}
	if p.ServiceName != "" {
		q.Set("serviceName", p.ServiceName)
	}

	queryStr := q.Encode()
	uri := fmt.Sprintf("trojan://%s@%s:%d", url.QueryEscape(p.Password), p.Address, p.Port)
	if queryStr != "" {
		uri += "?" + queryStr
	}
	if p.Name != "" {
		uri += "#" + url.QueryEscape(p.Name)
	}
	return uri, nil
}

func generateShadowsocks(p *ast.ServerProfile) (string, error) {
	cipher := p.Cipher
	if cipher == "" {
		cipher = "aes-256-gcm"
	}
	userPass := fmt.Sprintf("%s:%s", cipher, p.Password)
	b64Auth := base64.URLEncoding.EncodeToString([]byte(userPass))
	uri := fmt.Sprintf("ss://%s@%s:%d", b64Auth, p.Address, p.Port)
	if p.Name != "" {
		uri += "#" + url.QueryEscape(p.Name)
	}
	return uri, nil
}

func generateVMess(p *ast.ServerProfile) (string, error) {
	vmessMap := map[string]interface{}{
		"v":    "2",
		"ps":   p.Name,
		"add":  p.Address,
		"port": strconv.Itoa(p.Port),
		"id":   p.UUID,
		"aid":  "0",
		"net":  p.Transport,
		"type": "none",
		"host": p.Host,
		"path": p.Path,
		"tls":  p.Security,
		"sni":  p.SNI,
		"fp":   p.Fingerprint,
	}
	if p.Transport == "" {
		vmessMap["net"] = "tcp"
	}
	if p.Security == "" {
		vmessMap["tls"] = "none"
	}

	jsonBytes, err := json.Marshal(vmessMap)
	if err != nil {
		return "", err
	}
	return "vmess://" + base64.StdEncoding.EncodeToString(jsonBytes), nil
}

func generateTUIC(p *ast.ServerProfile) (string, error) {
	q := url.Values{}
	if p.SNI != "" {
		q.Set("sni", p.SNI)
	}
	if p.CongestionControl != "" {
		q.Set("congestion_control", p.CongestionControl)
	}
	if p.UDPRelayMode != "" {
		q.Set("udp_relay_mode", p.UDPRelayMode)
	}
	if p.Insecure {
		q.Set("allow_insecure", "1")
	}
	if p.ZeroRTTHandshake {
		q.Set("zero_rtt", "1")
	}
	if len(p.ALPN) > 0 {
		q.Set("alpn", strings.Join(p.ALPN, ","))
	}
	queryStr := q.Encode()
	uri := fmt.Sprintf("tuic://%s:%s@%s:%d", p.UUID, url.QueryEscape(p.Password), p.Address, p.Port)
	if queryStr != "" {
		uri += "?" + queryStr
	}
	if p.Name != "" {
		uri += "#" + url.QueryEscape(p.Name)
	}
	return uri, nil
}

func generateShadowTLS(p *ast.ServerProfile) (string, error) {
	q := url.Values{}
	sni := p.ShadowTLSSNI
	if sni == "" {
		sni = p.SNI
	}
	if sni != "" {
		q.Set("sni", sni)
	}
	v := p.ShadowTLSVersion
	if v <= 0 {
		v = 3
	}
	q.Set("v", strconv.Itoa(v))

	password := p.ShadowTLSPassword
	if password == "" {
		password = p.Password
	}
	queryStr := q.Encode()
	uri := fmt.Sprintf("shadowtls://%s@%s:%d", url.QueryEscape(password), p.Address, p.Port)
	if queryStr != "" {
		uri += "?" + queryStr
	}
	if p.Name != "" {
		uri += "#" + url.QueryEscape(p.Name)
	}
	return uri, nil
}

func generateWireGuard(p *ast.ServerProfile) (string, error) {
	q := url.Values{}
	if p.PeerPublicKey != "" {
		q.Set("publickey", p.PeerPublicKey)
	}
	if p.PreSharedKey != "" {
		q.Set("presharedkey", p.PreSharedKey)
	}
	if len(p.LocalAddress) > 0 {
		q.Set("ip", strings.Join(p.LocalAddress, ","))
	}
	if p.MTU > 0 {
		q.Set("mtu", strconv.Itoa(p.MTU))
	}
	if len(p.ReservedBytes) > 0 {
		var strVals []string
		for _, b := range p.ReservedBytes {
			strVals = append(strVals, strconv.Itoa(b))
		}
		q.Set("reserved", strings.Join(strVals, ","))
	}
	queryStr := q.Encode()
	uri := fmt.Sprintf("wireguard://%s@%s:%d", url.QueryEscape(p.PrivateKey), p.Address, p.Port)
	if queryStr != "" {
		uri += "?" + queryStr
	}
	if p.Name != "" {
		uri += "#" + url.QueryEscape(p.Name)
	}
	return uri, nil
}

func generateSocks(p *ast.ServerProfile) (string, error) {
	auth := ""
	if p.Username != "" || p.Password != "" {
		auth = fmt.Sprintf("%s:%s@", url.QueryEscape(p.Username), url.QueryEscape(p.Password))
	}
	uri := fmt.Sprintf("socks5://%s%s:%d", auth, p.Address, p.Port)
	if p.Name != "" {
		uri += "#" + url.QueryEscape(p.Name)
	}
	return uri, nil
}

func generateHTTP(p *ast.ServerProfile) (string, error) {
	scheme := "http"
	if p.Security == ast.SecurityTLS {
		scheme = "https"
	}
	auth := ""
	if p.Username != "" || p.Password != "" {
		auth = fmt.Sprintf("%s:%s@", url.QueryEscape(p.Username), url.QueryEscape(p.Password))
	}
	uri := fmt.Sprintf("%s://%s%s:%d", scheme, auth, p.Address, p.Port)
	if p.Name != "" {
		uri += "#" + url.QueryEscape(p.Name)
	}
	return uri, nil
}
