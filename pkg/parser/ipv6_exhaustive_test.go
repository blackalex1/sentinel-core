package parser

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/blackalex1/sentinel-core/pkg/ast"
	"github.com/blackalex1/sentinel-core/pkg/compiler/hysteria"
	"github.com/blackalex1/sentinel-core/pkg/compiler/singbox"
	"github.com/blackalex1/sentinel-core/pkg/compiler/wireguard"
	"github.com/blackalex1/sentinel-core/pkg/compiler/xray"
)

// TestIPv6_ExhaustiveProtocolMatrix tests parsing, round-trip generation,
// and AST consistency for all supported protocols with RFC 3849 & RFC 4193 IPv6 addresses.
func TestIPv6_ExhaustiveProtocolMatrix(t *testing.T) {
	testCases := []struct {
		name          string
		rawURI        string
		unbracketed   string
		expectedProto string
		expectedHost  string
		expectedPort  int
	}{
		{
			name:          "VLESS Reality IPv6 RFC 3849",
			rawURI:        "vless://a6c8e874-a4ee-4c38-89c0-6d427d1421bf@[2001:db8:1000::1]:443?type=tcp&security=reality&flow=xtls-rprx-vision&sni=node.example.test&pbk=publicKey123&sid=abcdef12#VLESS_IPv6",
			unbracketed:   "vless://a6c8e874-a4ee-4c38-89c0-6d427d1421bf@2001:db8:1000::1:443?type=tcp&security=reality&flow=xtls-rprx-vision&sni=node.example.test&pbk=publicKey123&sid=abcdef12#VLESS_IPv6_Unbracketed",
			expectedProto: ast.ProtoVLESS,
			expectedHost:  "2001:db8:1000::1",
			expectedPort:  443,
		},
		{
			name:          "Trojan TLS IPv6 RFC 3849",
			rawURI:        "trojan://mock_trojan_password@[2001:db8:beef::99]:443?security=tls&sni=node.example.test#Trojan_IPv6",
			unbracketed:   "trojan://mock_trojan_password@2001:db8:beef::99:443?security=tls&sni=node.example.test#Trojan_IPv6_Unbracketed",
			expectedProto: ast.ProtoTrojan,
			expectedHost:  "2001:db8:beef::99",
			expectedPort:  443,
		},
		{
			name:          "Hysteria 2 IPv6 RFC 3849",
			rawURI:        "hysteria2://mock_hy2_password@[2001:db8:cafe::42]:8443?sni=node.example.test#Hy2_IPv6",
			unbracketed:   "hysteria2://mock_hy2_password@2001:db8:cafe::42:8443?sni=node.example.test#Hy2_IPv6_Unbracketed",
			expectedProto: ast.ProtoHysteria2,
			expectedHost:  "2001:db8:cafe::42",
			expectedPort:  8443,
		},
		{
			name:          "Shadowsocks SIP002 IPv6 ULA",
			rawURI:        "ss://YWVzLTI1Ni1nY206bW9ja19zc19wYXNzd29yZA==@[fd00:1234:5678:9abc::1]:8388#SS_SIP002_IPv6",
			unbracketed:   "ss://YWVzLTI1Ni1nY206bW9ja19zc19wYXNzd29yZA==@fd00:1234:5678:9abc::1:8388#SS_SIP002_IPv6_Unbracketed",
			expectedProto: ast.ProtoShadowsocks,
			expectedHost:  "fd00:1234:5678:9abc::1",
			expectedPort:  8388,
		},
		{
			name:          "TUIC v5 IPv6 RFC 3849",
			rawURI:        "tuic://a6c8e874-a4ee-4c38-89c0-6d427d1421bf:tuic_pass@[2001:db8:2000::5]:8443?congestion_control=bbr&alpn=h3&sni=node.example.test#TUIC_IPv6",
			unbracketed:   "tuic://a6c8e874-a4ee-4c38-89c0-6d427d1421bf:tuic_pass@2001:db8:2000::5:8443?congestion_control=bbr&alpn=h3&sni=node.example.test#TUIC_IPv6_Unbracketed",
			expectedProto: ast.ProtoTUIC,
			expectedHost:  "2001:db8:2000::5",
			expectedPort:  8443,
		},
		{
			name:          "WireGuard IPv6 RFC 3849",
			rawURI:        "wireguard://aGVsbG9fd2lyZWd1YXJkX3ByaXZhdGVfa2V5XzEyMw==@[2001:db8:3000::8]:51820?publickey=cGVlcl9wdWJsaWNfa2V5X2Zvcl90ZXN0aW5nXzEyMzQ=&ip=fd00::2/64,10.0.0.2/32#WG_IPv6",
			unbracketed:   "wireguard://aGVsbG9fd2lyZWd1YXJkX3ByaXZhdGVfa2V5XzEyMw==@2001:db8:3000::8:51820?publickey=cGVlcl9wdWJsaWNfa2V5X2Zvcl90ZXN0aW5nXzEyMzQ=&ip=fd00::2/64,10.0.0.2/32#WG_IPv6_Unbracketed",
			expectedProto: ast.ProtoWireGuard,
			expectedHost:  "2001:db8:3000::8",
			expectedPort:  51820,
		},
		{
			name:          "ShadowTLS v3 IPv6 RFC 3849",
			rawURI:        "shadowtls://stls_secret_password@[2001:db8:4000::10]:8443?sni=gateway.icloud.com&v=3#STLS_IPv6",
			unbracketed:   "shadowtls://stls_secret_password@2001:db8:4000::10:8443?sni=gateway.icloud.com&v=3#STLS_IPv6_Unbracketed",
			expectedProto: ast.ProtoShadowTLS,
			expectedHost:  "2001:db8:4000::10",
			expectedPort:  8443,
		},
		{
			name:          "Socks5 IPv6 RFC 3849",
			rawURI:        "socks5://socks_user:socks_pass@[2001:db8:5000::12]:1080#Socks5_IPv6",
			unbracketed:   "socks5://socks_user:socks_pass@2001:db8:5000::12:1080#Socks5_IPv6_Unbracketed",
			expectedProto: ast.ProtoSocks,
			expectedHost:  "2001:db8:5000::12",
			expectedPort:  1080,
		},
		{
			name:          "HTTP Proxy IPv6 RFC 3849",
			rawURI:        "http://http_user:http_pass@[2001:db8:6000::15]:8080#HTTP_IPv6",
			unbracketed:   "http://http_user:http_pass@2001:db8:6000::15:8080#HTTP_IPv6_Unbracketed",
			expectedProto: ast.ProtoHTTP,
			expectedHost:  "2001:db8:6000::15",
			expectedPort:  8080,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// 1. Parse standard bracketed URI
			p, err := ParseURI(tc.rawURI)
			if err != nil {
				t.Fatalf("failed to parse %s: %v", tc.name, err)
			}
			if p.Protocol != tc.expectedProto {
				t.Errorf("[%s] protocol mismatch: got %s, expected %s", tc.name, p.Protocol, tc.expectedProto)
			}
			if p.Address != tc.expectedHost {
				t.Errorf("[%s] host mismatch: got %q, expected %q", tc.name, p.Address, tc.expectedHost)
			}
			if p.Port != tc.expectedPort {
				t.Errorf("[%s] port mismatch: got %d, expected %d", tc.name, p.Port, tc.expectedPort)
			}

			// 2. Generate URI and verify RFC 3986 square bracket formatting
			genURI, err := GenerateURI(p)
			if err != nil {
				t.Fatalf("[%s] failed to generate URI: %v", tc.name, err)
			}
			expectedBracket := fmt.Sprintf("[%s]:%d", tc.expectedHost, tc.expectedPort)
			if !strings.Contains(genURI, expectedBracket) {
				t.Errorf("[%s] generated URI must contain %q, got: %s", tc.name, expectedBracket, genURI)
			}

			// 3. Round-trip: parse the generated URI back into AST
			pRoundTrip, err := ParseURI(genURI)
			if err != nil {
				t.Fatalf("[%s] failed to parse round-trip URI: %v", tc.name, err)
			}
			if pRoundTrip.Address != tc.expectedHost || pRoundTrip.Port != tc.expectedPort {
				t.Errorf("[%s] round-trip AST mismatch: address=%s, port=%d", tc.name, pRoundTrip.Address, pRoundTrip.Port)
			}

			// 4. Test tolerance for unbracketed IPv6 URI (user typo / legacy exporter)
			pUnbracketed, err := ParseURI(tc.unbracketed)
			if err != nil {
				t.Fatalf("[%s] unbracketed URI parse failed: %v", tc.name, err)
			}
			if pUnbracketed.Address != tc.expectedHost || pUnbracketed.Port != tc.expectedPort {
				t.Errorf("[%s] unbracketed host/port mismatch: got %s:%d, expected %s:%d",
					tc.name, pUnbracketed.Address, pUnbracketed.Port, tc.expectedHost, tc.expectedPort)
			}
		})
	}
}

// TestIPv6_VMess_Comprehensive tests VMess base64 JSON links with IPv6 addresses
// both with and without square brackets in the "add" field.
func TestIPv6_VMess_Comprehensive(t *testing.T) {
	vmessData := map[string]interface{}{
		"v":    "2",
		"ps":   "VMess_IPv6_RFC3849",
		"add":  "2001:db8:abcd::1",
		"port": 443,
		"id":   "b7c9f8a0-1234-5678-9abc-def012345678",
		"aid":  0,
		"net":  "ws",
		"type": "none",
		"host": "node.example.test",
		"path": "/vmess-ws",
		"tls":  "tls",
		"sni":  "node.example.test",
		"fp":   "chrome",
	}

	jsonBytes, _ := json.Marshal(vmessData)
	rawVMess := "vmess://" + base64.StdEncoding.EncodeToString(jsonBytes)

	// 1. Parse standard VMess IPv6
	p, err := ParseURI(rawVMess)
	if err != nil {
		t.Fatalf("failed to parse VMess IPv6: %v", err)
	}
	if p.Address != "2001:db8:abcd::1" || p.Port != 443 {
		t.Errorf("unexpected VMess host/port: %s:%d", p.Address, p.Port)
	}
	if p.Security != ast.SecurityTLS || p.Transport != "ws" {
		t.Errorf("unexpected security/transport: %+v", p)
	}

	// 2. Generate URI and round-trip
	genURI, err := GenerateURI(p)
	if err != nil {
		t.Fatalf("failed to generate VMess URI: %v", err)
	}
	p2, err := ParseURI(genURI)
	if err != nil {
		t.Fatalf("failed to parse generated VMess URI: %v", err)
	}
	if p2.Address != "2001:db8:abcd::1" || p2.Port != 443 {
		t.Errorf("VMess round-trip mismatch: got %s:%d", p2.Address, p2.Port)
	}

	// 3. Test VMess with bracketed "add": "[2001:db8:abcd::1]"
	vmessDataBracketed := map[string]interface{}{
		"v":    "2",
		"ps":   "VMess_IPv6_Bracketed",
		"add":  "[2001:db8:abcd::1]",
		"port": 443,
		"id":   "b7c9f8a0-1234-5678-9abc-def012345678",
		"net":  "tcp",
	}
	jsonBytesB, _ := json.Marshal(vmessDataBracketed)
	pBracketed, err := ParseURI("vmess://" + base64.StdEncoding.EncodeToString(jsonBytesB))
	if err != nil {
		t.Fatalf("failed to parse bracketed VMess IPv6: %v", err)
	}
	// Must be normalized without brackets
	if pBracketed.Address != "2001:db8:abcd::1" {
		t.Errorf("expected normalized address '2001:db8:abcd::1', got %q", pBracketed.Address)
	}
}

// TestIPv6_Shadowsocks_LegacyBase64 tests Shadowsocks legacy single-string base64 format with IPv6.
func TestIPv6_Shadowsocks_LegacyBase64(t *testing.T) {
	// format: method:password@[ipv6]:port
	rawCredentials := "aes-256-gcm:my_secret_pass@[2001:db8:5555::1]:8388"
	b64Legacy := base64.StdEncoding.EncodeToString([]byte(rawCredentials))
	uri := "ss://" + b64Legacy + "#SS_Legacy_IPv6"

	p, err := ParseURI(uri)
	if err != nil {
		t.Fatalf("failed to parse legacy Shadowsocks IPv6: %v", err)
	}
	if p.Address != "2001:db8:5555::1" || p.Port != 8388 {
		t.Errorf("unexpected host/port: %s:%d", p.Address, p.Port)
	}
	if p.Cipher != "aes-256-gcm" || p.Password != "my_secret_pass" {
		t.Errorf("unexpected cipher/pass: %+v", p)
	}

	// Unbracketed legacy: aes-256-gcm:my_secret_pass@2001:db8:5555::1:8388
	rawUnbracketed := "aes-256-gcm:my_secret_pass@2001:db8:5555::1:8388"
	b64Unbracketed := base64.StdEncoding.EncodeToString([]byte(rawUnbracketed))
	pUnbrack, err := ParseURI("ss://" + b64Unbracketed + "#SS_Legacy_Unbracketed")
	if err != nil {
		t.Fatalf("failed to parse unbracketed legacy Shadowsocks IPv6: %v", err)
	}
	if pUnbrack.Address != "2001:db8:5555::1" || pUnbrack.Port != 8388 {
		t.Errorf("unexpected unbracketed host/port: %s:%d", pUnbrack.Address, pUnbrack.Port)
	}
}

// TestIPv6_AddressFormattingVariations tests exotic IPv6 forms (fully expanded, IPv4-mapped, mixed case, min/max ports).
func TestIPv6_AddressFormattingVariations(t *testing.T) {
	cases := []struct {
		name         string
		hostInput    string
		port         int
		expectedHost string
	}{
		{
			name:         "Fully expanded 8-group hexadecimal",
			hostInput:    "2001:0db8:0000:0000:0000:0000:0000:0001",
			port:         443,
			expectedHost: "2001:0db8:0000:0000:0000:0000:0000:0001",
		},
		{
			name:         "Mixed-case uppercase hexadecimal",
			hostInput:    "2001:0DB8:AAAA:BBBB::1",
			port:         8443,
			expectedHost: "2001:0DB8:AAAA:BBBB::1",
		},
		{
			name:         "Trailing double-colon prefix",
			hostInput:    "2001:db8::",
			port:         1080,
			expectedHost: "2001:db8::",
		},
		{
			name:         "Boundary port 1",
			hostInput:    "2001:db8::1",
			port:         1,
			expectedHost: "2001:db8::1",
		},
		{
			name:         "Boundary port 65535",
			hostInput:    "2001:db8::1",
			port:         65535,
			expectedHost: "2001:db8::1",
		},
		{
			name:         "IPv4-mapped IPv6 address",
			hostInput:    "::ffff:198.51.100.1",
			port:         443,
			expectedHost: "::ffff:198.51.100.1",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := fmt.Sprintf("vless://uuid@[%s]:%d?type=tcp#%s", tc.hostInput, tc.port, tc.name)
			p, err := ParseURI(raw)
			if err != nil {
				t.Fatalf("failed to parse variation %s: %v", tc.name, err)
			}
			if p.Address != tc.expectedHost || p.Port != tc.port {
				t.Errorf("[%s] host/port mismatch: got %s:%d, expected %s:%d",
					tc.name, p.Address, p.Port, tc.expectedHost, tc.port)
			}
			gen, err := GenerateURI(p)
			if err != nil {
				t.Fatalf("[%s] failed to generate URI: %v", tc.name, err)
			}
			if !strings.Contains(gen, fmt.Sprintf("[%s]:%d", tc.expectedHost, tc.port)) {
				t.Errorf("[%s] expected generated URI to contain [%s]:%d, got: %s",
					tc.name, tc.expectedHost, tc.port, gen)
			}
		})
	}
}

// TestIPv6_SubscriptionWithMixedProtocols tests decoding subscriptions containing both IPv4 and IPv6 nodes.
func TestIPv6_SubscriptionWithMixedProtocols(t *testing.T) {
	links := []string{
		"vless://a6c8e874-a4ee-4c38-89c0-6d427d1421bf@198.51.100.1:443?type=tcp&security=reality&sni=node4.test#IPv4_Node",
		"vless://a6c8e874-a4ee-4c38-89c0-6d427d1421bf@[2001:db8:1000::1]:443?type=tcp&security=reality&sni=node6.test#IPv6_VLESS",
		"hysteria2://password@[2001:db8:cafe::42]:8443?sni=hy6.test#IPv6_Hy2",
		"trojan://password@[2001:db8:beef::99]:443?security=tls#IPv6_Trojan",
		"ss://YWVzLTI1Ni1nY206cGFzcw==@[fd00::1]:8388#IPv6_SS",
	}

	payload := base64.StdEncoding.EncodeToString([]byte(strings.Join(links, "\n")))
	parsedNodes, err := ParseSubscription(payload)
	if err != nil {
		t.Fatalf("failed to parse mixed IPv4/IPv6 subscription: %v", err)
	}

	if len(parsedNodes) != 5 {
		t.Fatalf("expected 5 parsed nodes, got %d", len(parsedNodes))
	}

	if parsedNodes[0].Address != "198.51.100.1" {
		t.Errorf("expected IPv4 address, got %s", parsedNodes[0].Address)
	}
	if parsedNodes[1].Address != "2001:db8:1000::1" {
		t.Errorf("expected IPv6 address, got %s", parsedNodes[1].Address)
	}
	if parsedNodes[2].Address != "2001:db8:cafe::42" {
		t.Errorf("expected IPv6 address, got %s", parsedNodes[2].Address)
	}
	if parsedNodes[3].Address != "2001:db8:beef::99" {
		t.Errorf("expected IPv6 address, got %s", parsedNodes[3].Address)
	}
	if parsedNodes[4].Address != "fd00::1" {
		t.Errorf("expected ULA IPv6 address, got %s", parsedNodes[4].Address)
	}
}

// TestIPv6_Compilers_Comprehensive tests config generation with IPv6 across all compilers.
func TestIPv6_Compilers_Comprehensive(t *testing.T) {
	nodeIPv6 := &ast.ServerProfile{
		Protocol:      ast.ProtoWireGuard,
		Address:       "2001:db8:3000::8",
		Port:          51820,
		PrivateKey:    "aGVsbG9fd2lyZWd1YXJkX3ByaXZhdGVfa2V5XzEyMw==",
		PeerPublicKey: "cGVlcl9wdWJsaWNfa2V5X2Zvcl90ZXN0aW5nXzEyMzQ=",
		LocalAddress:  []string{"fd00::2/64", "10.0.0.2/32"},
		MTU:           1420,
	}

	// 1. WireGuard INI compiler must format Endpoint as [2001:db8:3000::8]:51820
	wgConf, err := wireguard.BuildWireGuardConf(nodeIPv6)
	if err != nil {
		t.Fatalf("failed to compile WireGuard IPv6: %v", err)
	}
	if !strings.Contains(wgConf, "Endpoint = [2001:db8:3000::8]:51820") {
		t.Errorf("WireGuard INI config must have bracketed IPv6 Endpoint, got:\n%s", wgConf)
	}
	if !strings.Contains(wgConf, "Address = fd00::2/64, 10.0.0.2/32") {
		t.Errorf("WireGuard INI config must contain IPv6 ULA address, got:\n%s", wgConf)
	}

	// 2. Xray Compiler WireGuard Outbound
	xraySpec := &ast.ConfigSpec{
		TargetCore: ast.CoreXray,
		ServerNode: nodeIPv6,
		ClientInbound: &ast.ClientInboundSpec{
			SocksPort: 10808,
		},
	}
	xrayJSON, _, err := xray.NewCompiler().Compile(xraySpec)
	if err != nil {
		t.Fatalf("failed to compile Xray WireGuard IPv6: %v", err)
	}
	if !strings.Contains(xrayJSON, "[2001:db8:3000::8]:51820") {
		t.Errorf("Xray WireGuard outbound must contain bracketed IPv6 endpoint, got:\n%s", xrayJSON)
	}

	// 3. Sing-box Compiler Outbound with IPv6 Server
	sbSpec := &ast.ConfigSpec{
		TargetCore: ast.CoreSingBox,
		ServerNode: &ast.ServerProfile{
			Protocol:  ast.ProtoVLESS,
			Address:   "2001:db8:1000::1",
			Port:      443,
			UUID:      "a6c8e874-a4ee-4c38-89c0-6d427d1421bf",
			Security:  ast.SecurityReality,
			PublicKey: "publicKey123",
			ShortID:   "abcdef12",
			SNI:       "node.example.test",
		},
		ClientInbound: &ast.ClientInboundSpec{
			SocksPort: 20808,
		},
	}
	sbJSON, _, err := singbox.NewCompiler().Compile(sbSpec)
	if err != nil {
		t.Fatalf("failed to compile Sing-box IPv6: %v", err)
	}
	if !strings.Contains(sbJSON, `"server": "2001:db8:1000::1"`) {
		t.Errorf("Sing-box outbound must have clean unbracketed IPv6 server, got:\n%s", sbJSON)
	}

	// 4. Hysteria Server Compiler with IPv6 Listen Address
	inboundSpec := ast.ServerInboundSpec{
		Protocol:      "hysteria2",
		Port:          8443,
		ListenAddress: "2001:db8:cafe::42",
		AdminPort:     18443,
	}
	hyServerJSON, err := hysteria.NewServerCompiler().CompileServer(inboundSpec, 10808)
	if err != nil {
		t.Fatalf("failed to compile Hysteria server IPv6: %v", err)
	}
	if !strings.Contains(hyServerJSON, `"[2001:db8:cafe::42]:8443"`) {
		t.Errorf("Hysteria server must have bracketed IPv6 listen address, got:\n%s", hyServerJSON)
	}
}
