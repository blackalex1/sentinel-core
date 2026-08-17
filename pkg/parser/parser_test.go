package parser

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/blackalex1/sentinel-core/pkg/ast"
)

func TestParseURI_EmptyAndWhitespace(t *testing.T) {
	_, err := ParseURI("")
	if err == nil {
		t.Errorf("expected error for empty URI")
	}

	_, err = ParseURI("   \n\t  ")
	if err == nil {
		t.Errorf("expected error for whitespace URI")
	}

	_, err = ParseURI("ftp://invalid.com:21")
	if err == nil {
		t.Errorf("expected error for unsupported scheme")
	}
}

func TestParseAndGenerate_VLESS_Comprehensive(t *testing.T) {
	// Full VLESS Reality URI with all query parameters
	raw := "vless://a6c8e874-a4ee-4c38-89c0-6d427d1421bf@1.2.3.4:443?type=tcp&security=reality&flow=xtls-rprx-vision&sni=example.com&fp=chrome&pbk=publicKey123&sid=abcdef12&spx=%2F&path=%2Fws&host=example.com&serviceName=my-grpc&alpn=h2%2Chttp%2F1.1&allowInsecure=1&pq=1&mux=1#MyVLESS"
	p, err := ParseURI(raw)
	if err != nil {
		t.Fatalf("failed to parse VLESS URI: %v", err)
	}

	if p.Protocol != ast.ProtoVLESS {
		t.Errorf("expected protocol vless, got %s", p.Protocol)
	}
	if p.UUID != "a6c8e874-a4ee-4c38-89c0-6d427d1421bf" {
		t.Errorf("unexpected uuid: %s", p.UUID)
	}
	if p.Address != "1.2.3.4" || p.Port != 443 {
		t.Errorf("unexpected host/port: %s:%d", p.Address, p.Port)
	}
	if p.Security != ast.SecurityReality || p.PublicKey != "publicKey123" || p.ShortID != "abcdef12" || p.SpiderX != "/" {
		t.Errorf("unexpected reality fields: %+v", p)
	}
	if p.Flow != "xtls-rprx-vision" || p.Transport != "tcp" || p.Fingerprint != "chrome" {
		t.Errorf("unexpected transport/flow/fp: %+v", p)
	}
	if p.Path != "/ws" || p.Host != "example.com" || p.ServiceName != "my-grpc" {
		t.Errorf("unexpected path/host/serviceName: %+v", p)
	}
	if len(p.ALPN) != 2 || p.ALPN[0] != "h2" || p.ALPN[1] != "http/1.1" {
		t.Errorf("unexpected alpn: %+v", p.ALPN)
	}
	if !p.Insecure || !p.PostQuantum || !p.Mux {
		t.Errorf("expected Insecure, PostQuantum, Mux to be true: %+v", p)
	}
	if p.Name != "MyVLESS" {
		t.Errorf("unexpected name: %s", p.Name)
	}

	// Test generation
	genURI, err := GenerateURI(p)
	if err != nil {
		t.Fatalf("failed to generate VLESS URI: %v", err)
	}
	if !strings.HasPrefix(genURI, "vless://") {
		t.Fatalf("expected vless:// prefix, got: %s", genURI)
	}

	// Round-trip parse generated URI
	p2, err := ParseURI(genURI)
	if err != nil {
		t.Fatalf("failed to parse generated VLESS URI: %v", err)
	}
	if p2.UUID != p.UUID || p2.Address != p.Address || p2.Port != p.Port || p2.PublicKey != p.PublicKey {
		t.Errorf("roundtrip mismatch: %+v vs %+v", p, p2)
	}
}

func TestParseVLESS_DefaultNameAndVariations(t *testing.T) {
	// Without fragment, with insecure=1, post_quantum=true
	raw := "vless://a6c8e874-a4ee-4c38-89c0-6d427d1421bf@myhost.org:8443?type=ws&security=tls&insecure=1&post_quantum=true"
	p, err := ParseURI(raw)
	if err != nil {
		t.Fatalf("failed to parse vless: %v", err)
	}
	if p.Name != "VLESS-myhost.org:8443" {
		t.Errorf("expected default name 'VLESS-myhost.org:8443', got '%s'", p.Name)
	}
	if !p.Insecure || !p.PostQuantum {
		t.Errorf("expected insecure and post_quantum: %+v", p)
	}

	// Invalid port
	_, err = ParseURI("vless://user@host:invalidport?type=tcp")
	if err == nil {
		t.Errorf("expected error on invalid port")
	}

	// Malformed URL
	_, err = ParseURI("vless://::invalid-url::")
	if err == nil {
		t.Errorf("expected error on malformed vless URI")
	}
}

func TestParseAndGenerate_Trojan_Comprehensive(t *testing.T) {
	raw := "trojan://mypassword123@trojan.example.com:443?type=ws&security=tls&sni=trojan.example.com&fp=chrome&path=%2Ftrojan-ws&host=trojan.example.com&serviceName=grpc-svc&alpn=h2%2Chttp%2F1.1&allowInsecure=1#MyTrojanNode"
	p, err := ParseURI(raw)
	if err != nil {
		t.Fatalf("failed to parse Trojan URI: %v", err)
	}

	if p.Protocol != ast.ProtoTrojan || p.Password != "mypassword123" {
		t.Errorf("unexpected protocol/password: %+v", p)
	}
	if p.Address != "trojan.example.com" || p.Port != 443 {
		t.Errorf("unexpected host/port: %+v", p)
	}
	if p.Transport != "ws" || p.Security != ast.SecurityTLS || p.SNI != "trojan.example.com" {
		t.Errorf("unexpected transport/security/sni: %+v", p)
	}
	if p.Path != "/trojan-ws" || p.Host != "trojan.example.com" || p.ServiceName != "grpc-svc" {
		t.Errorf("unexpected path/host/serviceName: %+v", p)
	}
	if len(p.ALPN) != 2 || !p.Insecure || p.Name != "MyTrojanNode" {
		t.Errorf("unexpected alpn/insecure/name: %+v", p)
	}

	// Generation
	gen, err := GenerateURI(p)
	if err != nil {
		t.Fatalf("failed to generate trojan URI: %v", err)
	}
	if !strings.HasPrefix(gen, "trojan://") {
		t.Fatalf("expected trojan:// prefix, got %s", gen)
	}

	p2, err := ParseURI(gen)
	if err != nil {
		t.Fatalf("failed to parse generated trojan URI: %v", err)
	}
	if p2.Password != p.Password || p2.Address != p.Address || p2.Port != p.Port {
		t.Errorf("roundtrip trojan mismatch: %+v vs %+v", p, p2)
	}

	// Default name and error cases
	pDefault, err := ParseURI("trojan://pass@host.com:443")
	if err != nil || pDefault.Name != "Trojan-host.com:443" {
		t.Errorf("expected default name, got %s", pDefault.Name)
	}

	_, err = ParseURI("trojan://pass@host.com:notaport")
	if err == nil {
		t.Errorf("expected error on invalid port in trojan")
	}

	_, err = ParseURI("trojan://::bad-uri::")
	if err == nil {
		t.Errorf("expected error on bad trojan uri")
	}
}

func TestParseAndGenerate_Hysteria2_Comprehensive(t *testing.T) {
	// Test hy2:// and hysteria2:// schemes
	raw1 := "hy2://secr3tpass@hy2.example.com:443?sni=hy2.example.com&insecure=1&obfs=salamander&obfs-password=obfspass123&mport=20000-40000&up=100mbps&down=200mbps&alpn=h3#Hy2Test"
	p1, err := ParseURI(raw1)
	if err != nil {
		t.Fatalf("failed to parse hy2 URI: %v", err)
	}

	if p1.Protocol != ast.ProtoHysteria2 || p1.Password != "secr3tpass" || p1.Address != "hy2.example.com" || p1.Port != 443 {
		t.Errorf("unexpected hy2 profile: %+v", p1)
	}
	if p1.SNI != "hy2.example.com" || !p1.Insecure || p1.ObfsType != "salamander" || p1.ObfsPassword != "obfspass123" {
		t.Errorf("unexpected hy2 security/obfs: %+v", p1)
	}
	if p1.PortHopping != "20000-40000" || p1.BandwidthUp != "100mbps" || p1.BandwidthDown != "200mbps" {
		t.Errorf("unexpected hy2 port hopping/bandwidth: %+v", p1)
	}
	if len(p1.ALPN) != 1 || p1.ALPN[0] != "h3" {
		t.Errorf("unexpected alpn: %+v", p1.ALPN)
	}

	// Test port hopping aliases: ports, port_hopping
	raw2 := "hysteria2://pass@hy2.example.com:8443?ports=1000-2000"
	p2, err := ParseURI(raw2)
	if err != nil || p2.PortHopping != "1000-2000" {
		t.Errorf("expected port hopping from 'ports', got: %+v", p2)
	}

	raw3 := "hysteria2://pass@hy2.example.com:8443?port_hopping=3000-4000"
	p3, err := ParseURI(raw3)
	if err != nil || p3.PortHopping != "3000-4000" {
		t.Errorf("expected port hopping from 'port_hopping', got: %+v", p3)
	}

	// Test default port 443 when not provided
	raw4 := "hysteria2://pass@hy2.example.com"
	p4, err := ParseURI(raw4)
	if err != nil || p4.Port != 443 {
		t.Errorf("expected default port 443 for hysteria2, got %d", p4.Port)
	}
	if p4.Name != "Hy2-hy2.example.com:443" {
		t.Errorf("unexpected default name: %s", p4.Name)
	}

	// Test mock URI with pinSHA256 and salamander obfs
	mockRaw := "hysteria2://mock_user:mock_secret_pass@mock-node.example.org:443?sni=mock-sni.example.org&pinSHA256=abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789&insecure=1&up=100&down=100&obfs=salamander&obfs-password=mock_obfs_pass&hop=20000-30000&mport=20000-30000&ports=20000-30000#Mock-Hy2-Outbound"
	pMock, err := ParseURI(mockRaw)
	if err != nil {
		t.Fatalf("failed to parse mock hy2 URI: %v", err)
	}
	if pMock.Username != "mock_user" || pMock.Password != "mock_secret_pass" || pMock.Address != "mock-node.example.org" || pMock.Port != 443 {
		t.Errorf("unexpected mock profile credentials/address: %+v", pMock)
	}
	if pMock.SNI != "mock-sni.example.org" || !pMock.Insecure {
		t.Errorf("unexpected mock SNI/insecure: %+v", pMock)
	}
	if pMock.PinnedPeerCertSha256 != "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789" {
		t.Errorf("expected pinned cert SHA256, got: %s", pMock.PinnedPeerCertSha256)
	}
	if pMock.ObfsType != "salamander" || pMock.ObfsPassword != "mock_obfs_pass" {
		t.Errorf("unexpected mock obfs: type=%s, pass=%s", pMock.ObfsType, pMock.ObfsPassword)
	}
	if pMock.PortHopping != "20000-30000" || pMock.BandwidthUp != "100" || pMock.BandwidthDown != "100" {
		t.Errorf("unexpected mock port hopping / bandwidth: %+v", pMock)
	}
	if pMock.Name != "Mock-Hy2-Outbound" {
		t.Errorf("unexpected mock name: %s", pMock.Name)
	}

	// Generation
	gen, err := GenerateURI(p1)
	if err != nil {
		t.Fatalf("failed to generate hysteria2 URI: %v", err)
	}
	if !strings.HasPrefix(gen, "hysteria2://") {
		t.Fatalf("expected hysteria2:// prefix, got: %s", gen)
	}
}

func TestParseAndGenerate_Shadowsocks_Comprehensive(t *testing.T) {
	// 1. SIP002 format (base64 encoded userinfo)
	userPass := "aes-256-gcm:mySecretPassword"
	b64User := base64.URLEncoding.EncodeToString([]byte(userPass))
	sipURI := "ss://" + b64User + "@ss.example.com:8388#MyShadowsocks"

	p, err := ParseURI(sipURI)
	if err != nil {
		t.Fatalf("failed to parse SIP002 shadowsocks: %v", err)
	}
	if p.Protocol != ast.ProtoShadowsocks || p.Cipher != "aes-256-gcm" || p.Password != "mySecretPassword" {
		t.Errorf("unexpected shadowsocks fields: %+v", p)
	}
	if p.Address != "ss.example.com" || p.Port != 8388 || p.Name != "MyShadowsocks" {
		t.Errorf("unexpected ss endpoint/name: %+v", p)
	}

	// 2. Unencoded userinfo format: ss://method:password@host:port#name
	rawPlain := "ss://2022-blake3-aes-128-gcm:mypass@ss.example.com:8389#PlainSS"
	pPlain, err := ParseURI(rawPlain)
	if err != nil {
		t.Fatalf("failed to parse plain shadowsocks: %v", err)
	}
	if pPlain.Cipher != "2022-blake3-aes-128-gcm" || pPlain.Password != "mypass" || pPlain.Port != 8389 {
		t.Errorf("unexpected plain ss profile: %+v", pPlain)
	}

	// 3. Legacy base64 whole string: ss://BASE64(method:password@host:port)#name
	legacyPayload := "aes-128-gcm:legacyPass@ss.example.com:9000"
	b64Legacy := base64.StdEncoding.EncodeToString([]byte(legacyPayload))
	legacyURI := "ss://" + b64Legacy + "#LegacySS"

	pLegacy, err := ParseURI(legacyURI)
	if err != nil {
		t.Fatalf("failed to parse legacy shadowsocks: %v", err)
	}
	if pLegacy.Cipher != "aes-128-gcm" || pLegacy.Password != "legacyPass" || pLegacy.Address != "ss.example.com" || pLegacy.Port != 9000 {
		t.Errorf("unexpected legacy ss profile: %+v", pLegacy)
	}

	// 4. Default name fallback
	pDefault, err := ParseURI("ss://" + b64User + "@ss.example.com:8388")
	if err != nil || pDefault.Name != "SS-ss.example.com:8388" {
		t.Errorf("expected default name, got %s", pDefault.Name)
	}

	// 5. Generation
	gen, err := GenerateURI(p)
	if err != nil {
		t.Fatalf("failed to generate ss URI: %v", err)
	}
	if !strings.HasPrefix(gen, "ss://") {
		t.Fatalf("expected ss:// prefix, got: %s", gen)
	}

	// Test generator default cipher
	pNoCipher := &ast.ServerProfile{Protocol: ast.ProtoShadowsocks, Password: "pass", Address: "1.1.1.1", Port: 8388}
	genNoCipher, err := GenerateURI(pNoCipher)
	if err != nil || !strings.Contains(genNoCipher, "ss://") {
		t.Errorf("failed to generate ss with default cipher: %v", err)
	}

	// Invalid base64 in legacy
	_, err = ParseURI("ss://!@#$notvalidbase64#Bad")
	if err == nil {
		t.Errorf("expected error on invalid base64 shadowsocks")
	}
}

func TestParseAndGenerate_VMess_Comprehensive(t *testing.T) {
	vmessObj := map[string]interface{}{
		"v":    "2",
		"ps":   "MyVMessNode",
		"add":  "vmess.example.com",
		"port": 443,
		"id":   "a6c8e874-a4ee-4c38-89c0-6d427d1421bf",
		"net":  "ws",
		"type": "none",
		"host": "vmess.example.com",
		"path": "/vmess-path",
		"tls":  "tls",
		"sni":  "vmess.example.com",
		"alpn": "h2,http/1.1",
		"fp":   "chrome",
	}
	data, _ := json.Marshal(vmessObj)
	raw := "vmess://" + base64.StdEncoding.EncodeToString(data)

	p, err := ParseURI(raw)
	if err != nil {
		t.Fatalf("failed to parse VMess URI: %v", err)
	}

	if p.Protocol != ast.ProtoVMess || p.UUID != "a6c8e874-a4ee-4c38-89c0-6d427d1421bf" {
		t.Errorf("unexpected vmess fields: %+v", p)
	}
	if p.Address != "vmess.example.com" || p.Port != 443 || p.Name != "MyVMessNode" {
		t.Errorf("unexpected endpoint/name: %+v", p)
	}
	if p.Transport != "ws" || p.Security != ast.SecurityTLS || p.Fingerprint != "chrome" {
		t.Errorf("unexpected transport/security/fp: %+v", p)
	}
	if len(p.ALPN) != 2 || p.Path != "/vmess-path" || p.Host != "vmess.example.com" {
		t.Errorf("unexpected alpn/path/host: %+v", p)
	}

	// VMess with string port and empty name
	vmessObj2 := map[string]interface{}{
		"v":    "2",
		"add":  "10.0.0.1",
		"port": "8080",
		"id":   "uuid-test",
	}
	data2, _ := json.Marshal(vmessObj2)
	p2, err := ParseURI("vmess://" + base64.StdEncoding.EncodeToString(data2))
	if err != nil || p2.Port != 8080 || p2.Name != "VMess-10.0.0.1:8080" {
		t.Errorf("unexpected vmess profile with string port: %+v", p2)
	}

	// Generation
	gen, err := GenerateURI(p)
	if err != nil {
		t.Fatalf("failed to generate VMess URI: %v", err)
	}
	if !strings.HasPrefix(gen, "vmess://") {
		t.Fatalf("expected vmess:// prefix, got: %s", gen)
	}

	// Generator with default transport/security
	pEmptyTrans := &ast.ServerProfile{Protocol: ast.ProtoVMess, Address: "1.1.1.1", Port: 80, UUID: "id"}
	genEmpty, err := GenerateURI(pEmptyTrans)
	if err != nil || !strings.Contains(genEmpty, "vmess://") {
		t.Errorf("failed to generate VMess with defaults: %v", err)
	}

	// Errors
	_, err = ParseURI("vmess://!!!invalid-base64!!!")
	if err == nil {
		t.Errorf("expected error on invalid base64")
	}

	_, err = ParseURI("vmess://" + base64.StdEncoding.EncodeToString([]byte("invalid json string")))
	if err == nil {
		t.Errorf("expected error on invalid vmess json")
	}
}

func TestParseAndGenerate_TUIC_Comprehensive(t *testing.T) {
	raw := "tuic://a6c8e874-a4ee-4c38-89c0-6d427d1421bf:tuicpassword@tuic.example.com:8443?sni=tuic.example.com&congestion_control=bbr&udp_relay_mode=native&allow_insecure=1&zero_rtt=1&alpn=h3#MyTUIC"
	p, err := ParseURI(raw)
	if err != nil {
		t.Fatalf("failed to parse TUIC URI: %v", err)
	}

	if p.Protocol != ast.ProtoTUIC || p.UUID != "a6c8e874-a4ee-4c38-89c0-6d427d1421bf" || p.Password != "tuicpassword" {
		t.Errorf("unexpected tuic credentials: %+v", p)
	}
	if p.Address != "tuic.example.com" || p.Port != 8443 || p.Name != "MyTUIC" {
		t.Errorf("unexpected endpoint/name: %+v", p)
	}
	if p.CongestionControl != "bbr" || p.UDPRelayMode != "native" || !p.Insecure || !p.ZeroRTTHandshake {
		t.Errorf("unexpected tuic flags: %+v", p)
	}
	if len(p.ALPN) != 1 || p.ALPN[0] != "h3" {
		t.Errorf("unexpected alpn: %+v", p.ALPN)
	}

	// Default name fallback
	pDefault, err := ParseURI("tuic://uuid:pass@tuic.example.com:8443")
	if err != nil || pDefault.Name != "TUIC-tuic.example.com:8443" {
		t.Errorf("expected default name, got %s", pDefault.Name)
	}

	// Generation
	gen, err := GenerateURI(p)
	if err != nil {
		t.Fatalf("failed to generate tuic URI: %v", err)
	}
	if !strings.HasPrefix(gen, "tuic://") {
		t.Fatalf("expected tuic:// prefix, got: %s", gen)
	}

	pRound, err := ParseURI(gen)
	if err != nil || pRound.UUID != p.UUID || pRound.Password != p.Password || !pRound.ZeroRTTHandshake {
		t.Errorf("roundtrip tuic mismatch: %+v vs %+v", p, pRound)
	}

	// Error cases
	_, err = ParseURI("tuic://::invalid::")
	if err == nil {
		t.Errorf("expected error on invalid tuic URI")
	}
}

func TestParseAndGenerate_ShadowTLS_Comprehensive(t *testing.T) {
	raw := "shadowtls://shadowpass123@shadow.example.com:443?sni=gateway.icloud.com&v=3#MyShadowTLS"
	p, err := ParseURI(raw)
	if err != nil {
		t.Fatalf("failed to parse ShadowTLS URI: %v", err)
	}

	if p.Protocol != ast.ProtoShadowTLS || p.Password != "shadowpass123" || p.ShadowTLSPassword != "shadowpass123" {
		t.Errorf("unexpected shadowtls password: %+v", p)
	}
	if p.Address != "shadow.example.com" || p.Port != 443 || p.ShadowTLSVersion != 3 {
		t.Errorf("unexpected endpoint/version: %+v", p)
	}
	if p.ShadowTLSSNI != "gateway.icloud.com" || p.Name != "MyShadowTLS" {
		t.Errorf("unexpected sni/name: %+v", p)
	}

	// ShadowTLS with version query param and password in query
	raw2 := "shadowtls://shadow.example.com:8443?password=pass456&host=www.microsoft.com&version=2"
	p2, err := ParseURI(raw2)
	if err != nil {
		t.Fatalf("failed to parse shadowtls query params: %v", err)
	}
	if p2.Password != "pass456" || p2.ShadowTLSSNI != "www.microsoft.com" || p2.ShadowTLSVersion != 2 {
		t.Errorf("unexpected shadowtls query parsing: %+v", p2)
	}
	if p2.Name != "ShadowTLS-shadow.example.com:8443" {
		t.Errorf("expected default name, got %s", p2.Name)
	}

	// Generation
	gen, err := GenerateURI(p)
	if err != nil {
		t.Fatalf("failed to generate shadowtls URI: %v", err)
	}
	if !strings.HasPrefix(gen, "shadowtls://") {
		t.Fatalf("expected shadowtls:// prefix, got: %s", gen)
	}

	pRound, err := ParseURI(gen)
	if err != nil || pRound.Password != p.Password || pRound.ShadowTLSSNI != p.ShadowTLSSNI {
		t.Errorf("roundtrip shadowtls mismatch: %+v vs %+v", p, pRound)
	}

	// Errors
	_, err = ParseURI("shadowtls://user@host:badport")
	if err == nil {
		t.Errorf("expected error on bad port in shadowtls")
	}
	_, err = ParseURI("shadowtls://::bad::")
	if err == nil {
		t.Errorf("expected error on malformed shadowtls")
	}
}

func TestParseAndGenerate_WireGuard_Comprehensive(t *testing.T) {
	// Full wireguard URI with wg:// and wireguard://
	raw := "wg://aGVsbG9wcml2YXRla2V5MTIzNDU2Nzg5MDEyMzQ1Ng==@wg.example.com:51820?publickey=cGVlcnB1YmxpY2tleTEyMzQ1Njc4OTAxMjM0NTY=&presharedkey=cHJlc2hhcmVka2V5MTIzNDU2Nzg5MDEyMzQ1Ng==&ip=10.0.0.2%2F32%2Cfd00%3A%3A2%2F128&mtu=1420&reserved=0%2C0%2C0#MyWireGuard"
	p, err := ParseURI(raw)
	if err != nil {
		t.Fatalf("failed to parse WireGuard URI: %v", err)
	}

	if p.Protocol != ast.ProtoWireGuard || p.PrivateKey != "aGVsbG9wcml2YXRla2V5MTIzNDU2Nzg5MDEyMzQ1Ng==" {
		t.Errorf("unexpected wireguard private key: %+v", p)
	}
	if p.PeerPublicKey != "cGVlcnB1YmxpY2tleTEyMzQ1Njc4OTAxMjM0NTY=" || p.PreSharedKey != "cHJlc2hhcmVka2V5MTIzNDU2Nzg5MDEyMzQ1Ng==" {
		t.Errorf("unexpected peer pub / psk: %+v", p)
	}
	if len(p.LocalAddress) != 2 || p.LocalAddress[0] != "10.0.0.2/32" || p.LocalAddress[1] != "fd00::2/128" {
		t.Errorf("unexpected local address: %+v", p.LocalAddress)
	}
	if p.MTU != 1420 || len(p.ReservedBytes) != 3 || p.ReservedBytes[0] != 0 {
		t.Errorf("unexpected mtu/reserved: %+v", p)
	}
	if p.Name != "MyWireGuard" {
		t.Errorf("unexpected name: %s", p.Name)
	}

	// WireGuard with peer_pub, psk, address query aliases
	raw2 := "wireguard://wg.example.com:51820?privatekey=priv123&peer_pub=pub456&psk=psk789&address=10.0.0.3/32"
	p2, err := ParseURI(raw2)
	if err != nil {
		t.Fatalf("failed to parse wireguard with aliases: %v", err)
	}
	if p2.PrivateKey != "priv123" || p2.PeerPublicKey != "pub456" || p2.PreSharedKey != "psk789" || len(p2.LocalAddress) != 1 {
		t.Errorf("unexpected wireguard aliases: %+v", p2)
	}
	if p2.Name != "WG-wg.example.com:51820" {
		t.Errorf("expected default name, got %s", p2.Name)
	}

	// Generation
	gen, err := GenerateURI(p)
	if err != nil {
		t.Fatalf("failed to generate WireGuard URI: %v", err)
	}
	if !strings.HasPrefix(gen, "wireguard://") {
		t.Fatalf("expected wireguard:// prefix, got: %s", gen)
	}

	pRound, err := ParseURI(gen)
	if err != nil || pRound.PrivateKey != p.PrivateKey || pRound.PeerPublicKey != p.PeerPublicKey || pRound.MTU != p.MTU {
		t.Errorf("roundtrip wireguard mismatch: %+v vs %+v", p, pRound)
	}

	// Errors
	_, err = ParseURI("wireguard://user@host:badport")
	if err == nil {
		t.Errorf("expected error on bad port in wireguard")
	}
	_, err = ParseURI("wireguard://::bad::")
	if err == nil {
		t.Errorf("expected error on malformed wireguard")
	}
}

func TestParseAndGenerate_Socks_Comprehensive(t *testing.T) {
	// socks5:// and socks://
	raw := "socks5://myuser:mypassword@socks.example.com:1080#MySocks5"
	p, err := ParseURI(raw)
	if err != nil {
		t.Fatalf("failed to parse socks5 URI: %v", err)
	}

	if p.Protocol != ast.ProtoSocks || p.Username != "myuser" || p.Password != "mypassword" {
		t.Errorf("unexpected socks auth: %+v", p)
	}
	if p.Address != "socks.example.com" || p.Port != 1080 || p.Name != "MySocks5" {
		t.Errorf("unexpected endpoint/name: %+v", p)
	}

	// socks:// without auth
	rawNoAuth := "socks://socks.example.com:1080"
	pNoAuth, err := ParseURI(rawNoAuth)
	if err != nil || pNoAuth.Username != "" || pNoAuth.Password != "" {
		t.Errorf("unexpected no-auth socks profile: %+v", pNoAuth)
	}
	if pNoAuth.Name != "Socks-socks.example.com:1080" {
		t.Errorf("unexpected default name: %s", pNoAuth.Name)
	}

	// Generation
	gen, err := GenerateURI(p)
	if err != nil {
		t.Fatalf("failed to generate socks URI: %v", err)
	}
	if !strings.HasPrefix(gen, "socks5://") {
		t.Fatalf("expected socks5:// prefix, got: %s", gen)
	}

	pRound, err := ParseURI(gen)
	if err != nil || pRound.Username != p.Username || pRound.Password != p.Password {
		t.Errorf("roundtrip socks mismatch: %+v vs %+v", p, pRound)
	}

	// Generator without auth
	genNoAuth, err := GenerateURI(pNoAuth)
	if err != nil || !strings.HasPrefix(genNoAuth, "socks5://") {
		t.Errorf("failed to generate no-auth socks: %v", err)
	}

	// Errors
	_, err = ParseURI("socks5://user@host:badport")
	if err == nil {
		t.Errorf("expected error on bad port in socks")
	}
	_, err = ParseURI("socks5://::bad::")
	if err == nil {
		t.Errorf("expected error on malformed socks")
	}
}

func TestParseAndGenerate_HTTP_Comprehensive(t *testing.T) {
	// http:// and https://
	rawHTTP := "http://proxyuser:proxypass@proxy.example.com:8080#MyHTTPProxy"
	pHTTP, err := ParseURI(rawHTTP)
	if err != nil {
		t.Fatalf("failed to parse HTTP proxy URI: %v", err)
	}

	if pHTTP.Protocol != ast.ProtoHTTP || pHTTP.Username != "proxyuser" || pHTTP.Password != "proxypass" {
		t.Errorf("unexpected http auth: %+v", pHTTP)
	}
	if pHTTP.Address != "proxy.example.com" || pHTTP.Port != 8080 || pHTTP.Name != "MyHTTPProxy" {
		t.Errorf("unexpected endpoint/name: %+v", pHTTP)
	}

	// https:// with default port 443
	rawHTTPS := "https://secuser:secpass@secureproxy.com#SecureHTTP"
	pHTTPS, err := ParseURI(rawHTTPS)
	if err != nil {
		t.Fatalf("failed to parse HTTPS proxy URI: %v", err)
	}
	if pHTTPS.Port != 443 || pHTTPS.Security != ast.SecurityTLS || pHTTPS.SNI != "secureproxy.com" {
		t.Errorf("unexpected HTTPS fields: %+v", pHTTPS)
	}

	// http:// with default port 80
	rawHTTP80 := "http://plainproxy.com"
	pHTTP80, err := ParseURI(rawHTTP80)
	if err != nil || pHTTP80.Port != 80 || pHTTP80.Name != "HTTP-plainproxy.com:80" {
		t.Errorf("unexpected plain HTTP 80: %+v", pHTTP80)
	}

	// Generation
	genHTTP, err := GenerateURI(pHTTP)
	if err != nil || !strings.HasPrefix(genHTTP, "http://") {
		t.Errorf("failed to generate http URI: %v, got %s", err, genHTTP)
	}

	genHTTPS, err := GenerateURI(pHTTPS)
	if err != nil || !strings.HasPrefix(genHTTPS, "https://") {
		t.Errorf("failed to generate https URI: %v, got %s", err, genHTTPS)
	}

	// Generation without auth
	pNoAuth := &ast.ServerProfile{Protocol: ast.ProtoHTTP, Address: "proxy.com", Port: 8080}
	genNoAuth, err := GenerateURI(pNoAuth)
	if err != nil || !strings.HasPrefix(genNoAuth, "http://") {
		t.Errorf("failed to generate no-auth http: %v", err)
	}

	// Errors
	_, err = ParseURI("http://:8080")
	if err == nil {
		t.Errorf("expected error on missing host in http URI")
	}
	_, err = ParseURI("http://proxy.com:invalidport")
	if err == nil {
		t.Errorf("expected error on invalid port in http URI")
	}
}

func TestGenerateURI_NilAndUnsupported(t *testing.T) {
	_, err := GenerateURI(nil)
	if err == nil {
		t.Errorf("expected error for nil profile")
	}

	_, err = GenerateURI(&ast.ServerProfile{Protocol: "unknown-proto"})
	if err == nil {
		t.Errorf("expected error for unsupported protocol")
	}
}

func TestDecodeBase64Safe(t *testing.T) {
	// Valid standard base64
	s1 := base64.StdEncoding.EncodeToString([]byte("hello standard"))
	d1, err := decodeBase64Safe(s1)
	if err != nil || d1 != "hello standard" {
		t.Errorf("failed decode std base64: %v", err)
	}

	// Valid URL encoding without padding
	s2 := base64.RawURLEncoding.EncodeToString([]byte("hello?query=1&var=2"))
	d2, err := decodeBase64Safe(s2)
	if err != nil || d2 != "hello?query=1&var=2" {
		t.Errorf("failed decode raw url base64: %v", err)
	}

	// Raw std encoding without padding
	s3 := base64.RawStdEncoding.EncodeToString([]byte("hello raw std"))
	d3, err := decodeBase64Safe(s3)
	if err != nil || d3 != "hello raw std" {
		t.Errorf("failed decode raw std base64: %v", err)
	}

	// Invalid base64
	_, err = decodeBase64Safe("!!!not-valid-base64-characters!!!")
	if err == nil {
		t.Errorf("expected error on invalid base64")
	}
}
