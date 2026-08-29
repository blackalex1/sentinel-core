package ast

import (
	"encoding/json"
	"testing"
)

func TestServerProfile_Normalize_Comprehensive(t *testing.T) {
	// 1. Reality inference from PublicKey
	pReality := &ServerProfile{
		Protocol:  "  VLESS  ",
		Address:   "  1.2.3.4  ",
		Port:      443,
		PublicKey: "pubKey123",
	}
	pReality.Normalize()

	if pReality.Protocol != "vless" {
		t.Errorf("expected normalized protocol 'vless', got '%s'", pReality.Protocol)
	}
	if pReality.Address != "1.2.3.4" {
		t.Errorf("expected trimmed address '1.2.3.4', got '%s'", pReality.Address)
	}
	if pReality.Transport != TransportTCP {
		t.Errorf("expected default transport 'tcp', got '%s'", pReality.Transport)
	}
	if pReality.Security != SecurityReality {
		t.Errorf("expected inferred security 'reality', got '%s'", pReality.Security)
	}
	if pReality.Fingerprint != "chrome" {
		t.Errorf("expected default fingerprint 'chrome', got '%s'", pReality.Fingerprint)
	}

	// 2. TLS inference from SNI and Insecure
	pTLS := &ServerProfile{
		Protocol:  "trojan",
		Address:   "example.com",
		Port:      443,
		Transport: "  WS  ",
		SNI:       "example.com",
	}
	pTLS.Normalize()

	if pTLS.Transport != "ws" {
		t.Errorf("expected normalized transport 'ws', got '%s'", pTLS.Transport)
	}
	if pTLS.Security != SecurityTLS {
		t.Errorf("expected inferred security 'tls', got '%s'", pTLS.Security)
	}
	if pTLS.Fingerprint != "chrome" {
		t.Errorf("expected default fingerprint 'chrome', got '%s'", pTLS.Fingerprint)
	}

	// TLS from Insecure
	pInsecure := &ServerProfile{
		Protocol: "vmess",
		Address:  "example.com",
		Port:     443,
		Insecure: true,
	}
	pInsecure.Normalize()
	if pInsecure.Security != SecurityTLS {
		t.Errorf("expected inferred security 'tls' for insecure node, got '%s'", pInsecure.Security)
	}

	// 3. SecurityNone when no TLS/Reality parameters
	pNone := &ServerProfile{
		Protocol: "shadowsocks",
		Address:  "ss.example.com",
		Port:     8388,
	}
	pNone.Normalize()
	if pNone.Security != SecurityNone {
		t.Errorf("expected security 'none', got '%s'", pNone.Security)
	}
	if pNone.Fingerprint != "" {
		t.Errorf("expected empty fingerprint for security none, got '%s'", pNone.Fingerprint)
	}

	// 4. Custom security and custom fingerprint preserved
	pCustom := &ServerProfile{
		Protocol:    "vless",
		Address:     "custom.com",
		Port:        443,
		Security:    "  TLS  ",
		Fingerprint: "firefox",
	}
	pCustom.Normalize()
	if pCustom.Security != "tls" || pCustom.Fingerprint != "firefox" {
		t.Errorf("expected custom security 'tls' and custom fp 'firefox', got '%s'/'%s'", pCustom.Security, pCustom.Fingerprint)
	}
}

func TestServerProfile_Validate_Comprehensive(t *testing.T) {
	// Valid profile
	valid := &ServerProfile{
		Protocol: ProtoVLESS,
		Address:  "example.com",
		Port:     443,
	}
	if err := valid.Validate(); err != nil {
		t.Errorf("expected valid profile to pass: %v", err)
	}

	// Empty Address
	noAddr := &ServerProfile{
		Protocol: ProtoVLESS,
		Port:     443,
	}
	if err := noAddr.Validate(); err == nil {
		t.Errorf("expected error for empty address")
	}

	// Port <= 0
	portZero := &ServerProfile{
		Protocol: ProtoVLESS,
		Address:  "example.com",
		Port:     0,
	}
	if err := portZero.Validate(); err == nil {
		t.Errorf("expected error for port 0")
	}

	// Port > 65535
	portOverflow := &ServerProfile{
		Protocol: ProtoVLESS,
		Address:  "example.com",
		Port:     70000,
	}
	if err := portOverflow.Validate(); err == nil {
		t.Errorf("expected error for port > 65535")
	}

	// Empty Protocol
	noProto := &ServerProfile{
		Address: "example.com",
		Port:    443,
	}
	if err := noProto.Validate(); err == nil {
		t.Errorf("expected error for empty protocol")
	}
}

func TestServerProfile_ToJSON_Comprehensive(t *testing.T) {
	profile := &ServerProfile{
		ID:                "node-uuid-1234",
		Name:              "Test Node",
		Protocol:          ProtoVLESS,
		Address:           "1.2.3.4",
		Port:              443,
		Transport:         TransportTCP,
		Security:          SecurityReality,
		UUID:              "a6c8e874-a4ee-4c38-89c0-6d427d1421bf",
		Password:          "secret-pass",
		Username:          "user-1",
		SNI:               "example.com",
		ALPN:              []string{"h2", "http/1.1"},
		Fingerprint:       "chrome",
		Insecure:          true,
		PublicKey:         "pubKey123",
		ShortID:           "sid123",
		SpiderX:           "/path",
		PostQuantum:       true,
		Flow:              "xtls-rprx-vision",
		Mux:               true,
		Path:              "/ws",
		Host:              "example.com",
		ServiceName:       "grpc-service",
		Headers:           map[string]string{"Host": "example.com"},
		Cipher:            "2022-blake3-aes-128-gcm",
		ShadowTLSVersion:  3,
		ShadowTLSPassword: "shadowpass",
		ShadowTLSSNI:      "shadow.com",
		BandwidthUp:       "100mbps",
		BandwidthDown:     "200mbps",
		ObfsType:          "salamander",
		ObfsPassword:      "obfspass",
		PortHopping:       "20000-40000",
		CongestionControl: "bbr",
		UDPRelayMode:      "native",
		ZeroRTTHandshake:  true,
		PrivateKey:        "privKey123",
		PeerPublicKey:     "peerPubKey123",
		PreSharedKey:      "psk123",
		LocalAddress:      []string{"10.0.0.2/32"},
		MTU:               1420,
		ReservedBytes:     []int{0, 0, 0},
		Extra:             map[string]interface{}{"custom_key": "custom_val"},
	}

	jsonStr, err := profile.ToJSON()
	if err != nil || jsonStr == "" {
		t.Fatalf("failed to serialize profile to JSON: %v", err)
	}

	var parsed ServerProfile
	if err := json.Unmarshal([]byte(jsonStr), &parsed); err != nil {
		t.Fatalf("failed to unmarshal JSON back to ServerProfile: %v", err)
	}

	if parsed.Name != profile.Name || parsed.UUID != profile.UUID || parsed.Port != 443 {
		t.Errorf("parsed profile mismatch: %+v", parsed)
	}
	if !parsed.PostQuantum || !parsed.ZeroRTTHandshake || parsed.MTU != 1420 {
		t.Errorf("parsed profile fields mismatch: %+v", parsed)
	}
}

func TestDNSSpec_DefaultAndCustom(t *testing.T) {
	def := DefaultDNSSpec()
	if def.RemoteServer != "https://1.1.1.1/dns-query" {
		t.Errorf("unexpected default remote server: %s", def.RemoteServer)
	}
	if def.DirectServer != "8.8.8.8" {
		t.Errorf("unexpected default direct server: %s", def.DirectServer)
	}
	if def.Strategy != "ipv4_only" {
		t.Errorf("unexpected default strategy: %s", def.Strategy)
	}
	if def.FakeIP {
		t.Errorf("expected FakeIP false by default")
	}

	custom := DNSSpec{
		RemoteServer: "tcp://1.1.1.1:53",
		DirectServer: "local",
		Strategy:     "prefer_ipv4",
		FakeIP:       true,
		FakeIPRange:  "198.18.0.0/15",
	}
	bytes, err := json.Marshal(custom)
	if err != nil {
		t.Fatalf("failed to marshal DNSSpec: %v", err)
	}

	var parsed DNSSpec
	if err := json.Unmarshal(bytes, &parsed); err != nil {
		t.Fatalf("failed to unmarshal DNSSpec: %v", err)
	}
	if !parsed.FakeIP || parsed.FakeIPRange != "198.18.0.0/15" {
		t.Errorf("unexpected parsed custom DNSSpec: %+v", parsed)
	}
}

func TestConfigSpec_Comprehensive(t *testing.T) {
	spec := ConfigSpec{
		TargetCore:      CoreSingBox,
		CoreVersion:     "1.12.0",
		StrictMode:      true,
		LogLevel:        "debug",
		LogPath:         "/var/log/sentinel.log",
		ClashAPIAddress: "127.0.0.1:9090",
		ServerNode: &ServerProfile{
			Protocol: ProtoVLESS,
			Address:  "example.com",
			Port:     443,
		},
		ClientInbound: &ClientInboundSpec{
			Mode:             InboundModeDesktopTun,
			SocksPort:        10808,
			HTTPPort:         10809,
			ListenAddress:    "127.0.0.1",
			AuthEnabled:      true,
			AuthUsername:     "user1",
			AuthPassword:     "pass1",
			TunInterfaceName: "sentinel-tun",
			TunStack:         "gvisor",
			MTU:              1500,
			StrictRoute:      true,
			AutoRoute:        true,
			EndpointIP:       "172.19.0.1/30",
			Inet4Address:     "172.19.0.2/30",
			Inet6Address:     "fdfe:dcba:9876::2/126",
			IncludePackages:  []string{"com.app.vpn"},
			ExcludePackages:  []string{"com.app.direct"},
		},
		ServerInbounds: []ServerInboundSpec{
			{
				Tag:            "vless-in",
				Protocol:       ProtoVLESS,
				ListenAddress:  "0.0.0.0",
				Port:           443,
				Transport:      TransportTCP,
				Security:       SecurityReality,
				SNI:            "example.com",
				CertPath:       "/etc/ssl/cert.pem",
				KeyPath:        "/etc/ssl/key.pem",
				PublicKey:      "pubKey",
				PrivateKey:     "privKey",
				ShortIDs:       []string{"0123456789abcdef"},
				Multiplex:      true,
				PortHop:        "20000-40000",
				AdminPort:      8080,
				AuthURL:        "https://auth.panel.com/v2/auth",
				ObfsType:       "salamander",
				ObfsPassword:   "obfspass",
				BandwidthUp:    "100mbps",
				BandwidthDown:  "200mbps",
				MasqType:       "file",
				MasqValue:      "/var/www/html",
				MasqStatusCode: 200,
				SocksPort:      20808,
				SocksUsername:  "socksuser",
				SocksPassword:  "sockspass",
				Fallbacks:      []map[string]interface{}{{"dest": 80}},
				RawSettings:    map[string]interface{}{"key": "val"},
				StreamSettings: map[string]interface{}{"net": "tcp"},
				Sniffing:       map[string]interface{}{"enabled": true},
				Clients: []ServerInboundClient{
					{
						ID:       "client-1",
						UUID:     "uuid-1234",
						Password: "pass",
						Email:    "client1@example.com",
						Flow:     "xtls-rprx-vision",
					},
				},
			},
		},
		Routing: &RoutingSpec{
			DefaultAction:       ActionProxy,
			AutoDetectInterface: true,
			OverrideDNS:         true,
			RuleSets:            []string{"geosite-ads"},
			Outbounds:           []map[string]interface{}{{"tag": "direct", "type": "direct"}},
			Rules: []RoutingRule{
				{
					Action:           ActionBlock,
					OutboundTag:      "block",
					Domains:          []string{"geosite:category-ads-all"},
					IPs:              []string{"geoip:private"},
					Ports:            []string{"445"},
					Protocols:        []string{"bittorrent"},
					NetworkProtocols: []string{"tcp"},
					Users:            []string{"client1@example.com"},
					PackageUIDs:      []string{"10142"},
					ProcessNames:     []string{"malware.exe"},
					InboundTags:      []string{"vless-in"},
				},
			},
		},
		DNS: &DNSSpec{
			RemoteServer: "https://1.1.1.1/dns-query",
			DirectServer: "8.8.8.8",
			Strategy:     "ipv4_only",
			FakeIP:       false,
		},
	}

	data, err := json.Marshal(spec)
	if err != nil {
		t.Fatalf("failed to marshal full ConfigSpec: %v", err)
	}

	var parsed ConfigSpec
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to unmarshal full ConfigSpec: %v", err)
	}

	if parsed.TargetCore != CoreSingBox || parsed.CoreVersion != "1.12.0" || !parsed.StrictMode {
		t.Errorf("parsed core metadata mismatch: %+v", parsed)
	}
	if parsed.ClientInbound == nil || parsed.ClientInbound.Mode != InboundModeDesktopTun {
		t.Errorf("parsed client inbound mismatch: %+v", parsed.ClientInbound)
	}
	if len(parsed.ServerInbounds) != 1 || parsed.ServerInbounds[0].Port != 443 {
		t.Errorf("parsed server inbounds mismatch: %+v", parsed.ServerInbounds)
	}
	if parsed.Routing == nil || len(parsed.Routing.Rules) != 1 || parsed.Routing.Rules[0].Action != ActionBlock {
		t.Errorf("parsed routing mismatch: %+v", parsed.Routing)
	}
	if parsed.DNS == nil || parsed.DNS.DirectServer != "8.8.8.8" {
		t.Errorf("parsed DNS mismatch: %+v", parsed.DNS)
	}
}

func TestCoreConstants(t *testing.T) {
	if CoreSingBox != "singbox" || CoreXray != "xray" || CoreHysteria2 != "hysteria2" || CoreWireGuard != "wireguard" {
		t.Errorf("unexpected Core constants")
	}

	if InboundModeDesktopTun != "desktop_tun" || InboundModeMobileVpn != "mobile_vpn" || InboundModeSystemProxy != "system_proxy" || InboundModeServer != "server" {
		t.Errorf("unexpected InboundMode constants")
	}

	if ActionProxy != "proxy" || ActionDirect != "direct" || ActionBlock != "block" {
		t.Errorf("unexpected Action constants")
	}

	if ProtoVLESS != "vless" || ProtoVMess != "vmess" || ProtoTrojan != "trojan" || ProtoShadowsocks != "shadowsocks" || ProtoShadowTLS != "shadowtls" || ProtoHysteria2 != "hysteria2" || ProtoTUIC != "tuic" || ProtoWireGuard != "wireguard" || ProtoSocks != "socks" || ProtoHTTP != "http" || ProtoDirect != "direct" || ProtoBlock != "block" {
		t.Errorf("unexpected Protocol constants")
	}

	if TransportTCP != "tcp" || TransportGRPC != "grpc" || TransportWS != "ws" || TransportHTTP != "http" || TransportH2 != "h2" || TransportQUIC != "quic" || TransportKCP != "kcp" || TransportXHTTP != "xhttp" || TransportSplitHTTP != "splithttp" || TransportHTTPUpgrade != "httpupgrade" {
		t.Errorf("unexpected Transport constants")
	}

	if SecurityNone != "none" || SecurityTLS != "tls" || SecurityReality != "reality" || SecurityShadowTLS != "shadowtls" {
		t.Errorf("unexpected Security constants")
	}
}
