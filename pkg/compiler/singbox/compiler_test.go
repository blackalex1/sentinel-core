package singbox

import (
	"strings"
	"testing"

	"github.com/blackalex1/sentinel-core/pkg/ast"
)

func TestSingboxCompiler_NilSpec(t *testing.T) {
	c := NewCompiler()
	_, _, err := c.Compile(nil)
	if err == nil {
		t.Fatal("expected error when spec is nil, got nil")
	}
}

func TestSingboxCompiler_NegotiationError(t *testing.T) {
	c := NewCompiler()
	spec := &ast.ConfigSpec{
		TargetCore: ast.CoreSingBox,
		StrictMode: true,
		ServerNode: &ast.ServerProfile{
			Protocol:    ast.ProtoVLESS,
			Address:     "vless.example.com",
			Port:        443,
			PostQuantum: true, // Sing-box does not support Post-Quantum TLS in strict mode
		},
	}
	_, _, err := c.Compile(spec)
	if err == nil {
		t.Fatal("expected error on strict mode PQ for singbox, got nil")
	}
}

func TestSingboxCompiler_BuildSingBoxOutbound_Protocols(t *testing.T) {
	// Nil node
	_, err := BuildSingBoxOutbound(nil)
	if err == nil {
		t.Fatal("expected error for nil node in BuildSingBoxOutbound")
	}

	// Unsupported protocol
	_, err = BuildSingBoxOutbound(&ast.ServerProfile{Protocol: "unsupported_proto"})
	if err == nil {
		t.Fatal("expected error for unsupported protocol in BuildSingBoxOutbound")
	}

	// 1. VLESS Outbound with gRPC and Reality
	vlessNode := &ast.ServerProfile{
		Name:        "vless-node-1",
		Protocol:    ast.ProtoVLESS,
		Address:     "vless.example.com",
		Port:        443,
		UUID:        "e99dc462-8409-4e45-bf28-665544332211",
		Flow:        "xtls-rprx-vision",
		Transport:   ast.TransportGRPC,
		ServiceName: "my-grpc-service",
		Security:    ast.SecurityReality,
		PublicKey:   "pubkey123",
		ShortID:     "abcd1234",
		SNI:         "gateway.icloud.com",
		Fingerprint: "chrome",
	}
	obVless, err := BuildSingBoxOutbound(vlessNode)
	if err != nil {
		t.Fatalf("failed to build VLESS outbound: %v", err)
	}
	if obVless["type"] != "vless" || obVless["tag"] != "vless-node-1" {
		t.Errorf("unexpected vless outbound: %+v", obVless)
	}
	tlsMap := obVless["tls"].(map[string]interface{})
	realityMap := tlsMap["reality"].(map[string]interface{})
	if realityMap["public_key"] != "pubkey123" || realityMap["short_id"] != "abcd1234" {
		t.Errorf("unexpected reality map: %+v", realityMap)
	}
	transportMap := obVless["transport"].(map[string]interface{})
	if transportMap["service_name"] != "my-grpc-service" {
		t.Errorf("unexpected transport map: %+v", transportMap)
	}

	// 2. Hysteria 2 Outbound with PortHopping, Obfs, Bandwidth, Extra hop_interval
	hy2Node := &ast.ServerProfile{
		Protocol:      ast.ProtoHysteria2,
		Address:       "hy2.example.com",
		Port:          443,
		PortHopping:   "40000-50000, 60000-65000",
		Password:      "hy2password",
		BandwidthUp:   "100mbps",
		BandwidthDown: "200mb",
		ObfsType:      "salamander",
		ObfsPassword:  "obfspassword",
		SNI:           "hy2.example.com",
		Insecure:      true,
		ALPN:          []string{"h3"},
		Extra: map[string]interface{}{
			"hop_interval": "45s",
		},
	}
	obHy2, err := BuildSingBoxOutbound(hy2Node)
	if err != nil {
		t.Fatalf("failed to build Hysteria2 outbound: %v", err)
	}
	if obHy2["type"] != "hysteria2" {
		t.Errorf("expected hysteria2 type: %+v", obHy2)
	}
	serverPorts := obHy2["server_ports"].([]string)
	if len(serverPorts) != 2 || serverPorts[0] != "40000:50000" {
		t.Errorf("expected normalized server_ports 40000:50000, got: %+v", serverPorts)
	}
	if obHy2["hop_interval"] != "45s" || obHy2["up_mbps"] != 100 || obHy2["down_mbps"] != 200 {
		t.Errorf("unexpected hysteria2 parameters: %+v", obHy2)
	}

	// 3. Trojan Outbound with WS transport and Host header
	trojanNode := &ast.ServerProfile{
		Protocol:  ast.ProtoTrojan,
		Address:   "trojan.example.com",
		Port:      443,
		Password:  "trojanpass",
		Transport: ast.TransportWS,
		Path:      "/trojan-ws",
		Host:      "trojan.example.com",
		SNI:       "trojan.example.com",
	}
	obTrojan, err := BuildSingBoxOutbound(trojanNode)
	if err != nil {
		t.Fatalf("failed to build Trojan outbound: %v", err)
	}
	if obTrojan["type"] != "trojan" {
		t.Errorf("expected trojan type: %+v", obTrojan)
	}

	// 4. Shadowsocks Outbound (custom and default cipher)
	ssNode := &ast.ServerProfile{
		Protocol: ast.ProtoShadowsocks,
		Address:  "ss.example.com",
		Port:     8388,
		Password: "sspassword",
		Cipher:   "aes-128-gcm",
	}
	obSS, err := BuildSingBoxOutbound(ssNode)
	if err != nil || obSS["method"] != "aes-128-gcm" {
		t.Errorf("unexpected ss outbound: %+v", obSS)
	}

	// 5. ShadowTLS Outbound
	shadowTlsNode := &ast.ServerProfile{
		Protocol:          ast.ProtoShadowTLS,
		Address:           "stls.example.com",
		Port:              443,
		ShadowTLSVersion:  3,
		ShadowTLSPassword: "stls-password",
		ShadowTLSSNI:     "gateway.icloud.com",
	}
	obStls, err := BuildSingBoxOutbound(shadowTlsNode)
	if err != nil || obStls["type"] != "shadowtls" || obStls["version"] != 3 {
		t.Errorf("unexpected shadowtls outbound: %+v", obStls)
	}

	// 6. TUIC Outbound
	tuicNode := &ast.ServerProfile{
		Protocol:          ast.ProtoTUIC,
		Address:           "tuic.example.com",
		Port:              8443,
		UUID:              "uuid-tuic",
		Password:          "tuic-password",
		CongestionControl: "bbr",
		UDPRelayMode:      "native",
		ZeroRTTHandshake:  true,
		SNI:               "tuic.example.com",
	}
	obTuic, err := BuildSingBoxOutbound(tuicNode)
	if err != nil || obTuic["type"] != "tuic" || obTuic["congestion_control"] != "bbr" || obTuic["zero_rtt_handshake"] != true {
		t.Errorf("unexpected tuic outbound: %+v", obTuic)
	}

	// 7. VMess Outbound with HTTPUpgrade transport
	vmessNode := &ast.ServerProfile{
		Protocol:  ast.ProtoVMess,
		Address:   "vmess.example.com",
		Port:      443,
		UUID:      "uuid-vmess",
		Transport: ast.TransportHTTPUpgrade,
		Path:      "/httpupgrade-path",
		Host:      "vmess.example.com",
	}
	obVmess, err := BuildSingBoxOutbound(vmessNode)
	if err != nil || obVmess["type"] != "vmess" {
		t.Errorf("unexpected vmess outbound: %+v", obVmess)
	}
	trVmess := obVmess["transport"].(map[string]interface{})
	if trVmess["type"] != "httpupgrade" || trVmess["path"] != "/httpupgrade-path" {
		t.Errorf("unexpected httpupgrade transport: %+v", trVmess)
	}

	// 8. WireGuard Outbound
	wgNode := &ast.ServerProfile{
		Protocol:      ast.ProtoWireGuard,
		Address:       "wg.example.com",
		Port:          51820,
		PrivateKey:    "privkey",
		PeerPublicKey: "pubkey",
		PreSharedKey:  "psk",
		LocalAddress:  []string{"10.0.0.2/32"},
		MTU:           1420,
		ReservedBytes: []int{0, 0, 0},
	}
	obWg, err := BuildSingBoxOutbound(wgNode)
	if err != nil || obWg["type"] != "wireguard" || obWg["mtu"] != 1420 {
		t.Errorf("unexpected wireguard outbound: %+v", obWg)
	}

	// 9. Direct & Block
	obDirect, err := BuildSingBoxOutbound(&ast.ServerProfile{Protocol: ast.ProtoDirect})
	if err != nil || obDirect["type"] != "direct" {
		t.Errorf("unexpected direct outbound: %+v", obDirect)
	}
	obBlock, err := BuildSingBoxOutbound(&ast.ServerProfile{Protocol: ast.ProtoBlock})
	if err != nil || obBlock["type"] != "block" {
		t.Errorf("unexpected block outbound: %+v", obBlock)
	}
}

func TestSingboxCompiler_ClientInbounds(t *testing.T) {
	c := NewCompiler()

	// 1. SOCKS with auth, HTTP, and TUN Inbound
	spec := &ast.ConfigSpec{
		TargetCore: ast.CoreSingBox,
		ClientInbound: &ast.ClientInboundSpec{
			Mode:             ast.InboundModeDesktopTun,
			ListenAddress:    "127.0.0.1",
			SocksPort:        10808,
			HTTPPort:         10809,
			AuthEnabled:      true,
			AuthUsername:     "sentinel_user",
			AuthPassword:     "sentinel_pass",
			TunInterfaceName: "sentinel-wintun",
			TunStack:         "gvisor",
			MTU:              1500,
			EndpointIP:       "172.19.0.1/30",
			StrictRoute:      true,
			IncludePackages:  []string{"com.example.app"},
			ExcludePackages:  []string{"com.example.bypass"},
		},
	}

	cfg, _, err := c.Compile(spec)
	if err != nil {
		t.Fatalf("failed to compile client inbounds: %v", err)
	}

	expectedSnippets := []string{
		`"tag": "socks-in"`,
		`"username": "sentinel_user"`,
		`"password": "sentinel_pass"`,
		`"tag": "http-in"`,
		`"tag": "tun-in"`,
		`"interface_name": "sentinel-wintun"`,
		`"stack": "gvisor"`,
		`"mtu": 1500`,
		`"strict_route": true`,
		`"include_package": [`,
		`"exclude_package": [`,
		`"action": "hijack-dns"`,
	}

	for _, snippet := range expectedSnippets {
		if !strings.Contains(cfg, snippet) {
			t.Errorf("expected snippet %q in compiled singbox client config, got:\n%s", snippet, cfg)
		}
	}

	// 2. Default fallback inbound when ClientInbound is empty
	specEmpty := &ast.ConfigSpec{
		TargetCore: ast.CoreSingBox,
	}
	cfgEmpty, _, err := c.Compile(specEmpty)
	if err != nil {
		t.Fatalf("failed to compile empty spec: %v", err)
	}
	if !strings.Contains(cfgEmpty, `"tag": "socks-in"`) || !strings.Contains(cfgEmpty, `10808`) {
		t.Errorf("expected default socks-in 10808 inbound, got:\n%s", cfgEmpty)
	}
}

func TestSingboxCompiler_ServerInbounds(t *testing.T) {
	c := NewCompiler()

	spec := &ast.ConfigSpec{
		TargetCore: ast.CoreSingBox,
		ServerInbounds: []ast.ServerInboundSpec{
			// VLESS with Reality
			{
				Tag:           "vless-reality-in",
				Protocol:      "vless",
				Port:          443,
				ListenAddress: "0.0.0.0",
				Security:      "reality",
				SNI:           "gateway.icloud.com",
				PrivateKey:    "private-key-base64",
				ShortIDs:      []string{"12345678"},
				StreamSettings: map[string]interface{}{
					"realitySettings": map[string]interface{}{
						"dest": "gateway.icloud.com:443",
					},
				},
				Clients: []ast.ServerInboundClient{
					{UUID: "uuid-1", Email: "vless-user@test.com", Flow: "xtls-rprx-vision"},
				},
			},
			// Trojan with TLS
			{
				Tag:      "trojan-tls-in",
				Protocol: "trojan",
				Port:     8443,
				Security: "tls",
				CertPath: "/etc/ssl/cert.pem",
				KeyPath:  "/etc/ssl/key.pem",
				SNI:      "trojan.example.com",
				Clients: []ast.ServerInboundClient{
					{Password: "trojan-password", Email: "trojan-user@test.com"},
				},
			},
			// Hysteria 2 server inbound
			{
				Tag:           "hy2-server-in",
				Protocol:      "hysteria2",
				Port:          9443,
				ObfsType:      "salamander",
				ObfsPassword:  "salamander-secret",
				BandwidthUp:   "100mbps",
				BandwidthDown: "500mbps",
				Clients: []ast.ServerInboundClient{
					{Password: "hy2-password", Email: "hy2-user@test.com"},
				},
			},
			// VMess server inbound
			{
				Tag:      "vmess-server-in",
				Protocol: "vmess",
				Port:     10443,
				Clients: []ast.ServerInboundClient{
					{ID: "vmess-uuid", Email: "vmess-user@test.com"},
				},
			},
		},
	}

	cfg, _, err := c.Compile(spec)
	if err != nil {
		t.Fatalf("failed to compile server inbounds: %v", err)
	}

	expectedSnippets := []string{
		"vless-reality-in",
		"trojan-tls-in",
		"hy2-server-in",
		"vmess-server-in",
		`"server_name": "gateway.icloud.com"`,
		`"private_key": "private-key-base64"`,
		`"certificate_path": "/etc/ssl/cert.pem"`,
		`"key_path": "/etc/ssl/key.pem"`,
		`"salamander-secret"`,
		`"up_mbps": 100`,
		`"down_mbps": 500`,
	}

	for _, snippet := range expectedSnippets {
		if !strings.Contains(cfg, snippet) {
			t.Errorf("expected snippet %q in compiled server config, got:\n%s", snippet, cfg)
		}
	}
}

func TestSingboxCompiler_RoutingAndRuleSets(t *testing.T) {
	c := NewCompiler()

	spec := &ast.ConfigSpec{
		TargetCore:  ast.CoreSingBox,
		CoreVersion: "1.12.0",
		ClashAPIAddress: "127.0.0.1:9090",
		DNS: &ast.DNSSpec{
			RemoteServer: "https://1.1.1.1/dns-query",
			DirectServer: "8.8.8.8",
			Strategy:     "prefer_ipv4",
		},
		ServerNode: &ast.ServerProfile{
			Protocol: ast.ProtoVLESS,
			Address:  "vless.example.com",
			Port:     443,
			UUID:     "uuid-vless",
		},
		Routing: &ast.RoutingSpec{
			DefaultAction: ast.ActionProxy,
			Outbounds: []map[string]interface{}{
				{"tag": "direct", "protocol": "direct"},
				{"tag": "block", "protocol": "block"},
				{"tag": "custom-direct", "protocol": "freedom"},
				{"tag": "custom-block", "protocol": "blackhole"},
				{
					"tag":      "hy2-routing-out",
					"protocol": "hysteria2",
					"settings": map[string]interface{}{
						"address":       "hy2.example.com",
						"port":          float64(443),
						"password":      "secret",
						"obfs_type":     "salamander",
						"obfs_password": "obfspassword",
					},
					"stream_settings": map[string]interface{}{
						"tlsSettings": map[string]interface{}{
							"serverName":    "hy2.example.com",
							"allowInsecure": true,
						},
					},
				},
			},
			Rules: []ast.RoutingRule{
				{
					Action:       ast.ActionDirect,
					Domains:      []string{"geosite:ru", "regexp:.*\\.ru$", "regex:^test\\.", "domain:google.com", "full:exact.com", "suffix:example.org", "keyword:login", "plain.domain.com"},
					IPs:          []string{"geoip:private", "geoip:ru", "ip:192.168.1.0/24", "10.10.0.0/16"},
					Ports:        []string{"80", "443"},
					Protocols:    []string{"tcp", "udp", "quic", "http"},
					Users:        []string{"user1@test.com"},
					PackageUIDs:  []string{"10002"},
					ProcessNames: []string{"curl.exe", "discord.exe"},
					InboundTags:  []string{"socks-in"},
				},
				{
					Action:      ast.ActionProxy,
					OutboundTag: "hy2-routing-out",
					Domains:     []string{"openai.com"},
				},
				{
					Action:      ast.ActionBlock,
					OutboundTag: "blocked", // Should map to "block"
					Domains:     []string{"ads.example.com"},
				},
			},
		},
	}

	cfg, _, err := c.Compile(spec)
	if err != nil {
		t.Fatalf("failed to compile routing and rulesets config: %v", err)
	}

	expectedSnippets := []string{
		`"rule_set"`,
		`"geosite-ru"`,
		`"geoip-ru"`,
		`"domain_regex"`,
		`"domain_suffix"`,
		`"domain_keyword"`,
		`"ip_cidr"`,
		`"10.0.0.0/8"`,
		`"192.168.0.0/16"`,
		`"clash_mode": "Direct"`,
		`"external_controller": "127.0.0.1:9090"`,
		`"dns-remote"`,
		`"detour": "proxy"`,
		`"strategy": "prefer_ipv4"`,
	}

	for _, snippet := range expectedSnippets {
		if !strings.Contains(cfg, snippet) {
			t.Errorf("expected snippet %q in config, got:\n%s", snippet, cfg)
		}
	}
}

func TestSingboxCompiler_LogLevelsAndPaths(t *testing.T) {
	c := NewCompiler()

	levels := []string{"trace", "debug", "info", "warn", "error", "fatal", "panic"}
	for _, lvl := range levels {
		spec := &ast.ConfigSpec{
			TargetCore: ast.CoreSingBox,
			LogLevel:   lvl,
			LogPath:    "/var/log/singbox.log",
		}
		cfg, _, err := c.Compile(spec)
		if err != nil {
			t.Fatalf("failed to compile loglevel %s: %v", lvl, err)
		}
		if !strings.Contains(cfg, `"level": "`+lvl+`"`) || !strings.Contains(cfg, `"/var/log/singbox.log"`) {
			t.Errorf("expected loglevel %s and output path in config: %s", lvl, cfg)
		}
	}

	// Invalid loglevel fallback to "info"
	specInvalid := &ast.ConfigSpec{
		TargetCore: ast.CoreSingBox,
		LogLevel:   "unknown_level",
	}
	cfgInvalid, _, _ := c.Compile(specInvalid)
	if !strings.Contains(cfgInvalid, `"level": "info"`) {
		t.Errorf("expected fallback loglevel info: %s", cfgInvalid)
	}
}

func TestSingboxCompiler_AdditionalBranches(t *testing.T) {
	c := NewCompiler()

	// 1. JSON string settings and stream_settings in Routing.Outbounds
	// 2. User ID / Password fallbacks in Server Inbounds
	// 3. Fallback TLS server_name for Hysteria2 outbound
	// 4. Bandwidth parser fallback
	spec := &ast.ConfigSpec{
		TargetCore: ast.CoreSingBox,
		DNS: &ast.DNSSpec{
			RemoteServer: "tcp://1.0.0.1",
			DirectServer: "1.1.1.1",
			Strategy:     "ipv4_only",
		},
		ServerInbounds: []ast.ServerInboundSpec{
			{
				Tag:      "vless-fallback-users",
				Protocol: "vless",
				Port:     443,
				Clients: []ast.ServerInboundClient{
					{Password: "pwd-as-uuid"}, // fallback from ID/UUID to Password
				},
				StreamSettings: map[string]interface{}{
					"security": "reality",
					"realitySettings": map[string]interface{}{
						"privateKey":  "priv-key",
						"dest":        "customdest.com:8443",
						"serverNames": []interface{}{"customdest.com"},
						"shortIds":    []interface{}{"11223344"},
					},
				},
			},
			{
				Tag:      "trojan-fallback-users",
				Protocol: "trojan",
				Port:     8443,
				Clients: []ast.ServerInboundClient{
					{UUID: "uuid-as-pwd"}, // fallback from Password to UUID
					{ID: "id-as-pwd"},     // fallback from Password/UUID to ID
				},
				StreamSettings: map[string]interface{}{
					"security": "tls",
					"tlsSettings": map[string]interface{}{
						"serverName":      "trojan.custom.com",
						"certificateFile": "/path/to/cert.crt",
						"keyFile":         "/path/to/key.key",
					},
				},
			},
		},
		Routing: &ast.RoutingSpec{
			Outbounds: []map[string]interface{}{
				{
					"tag":             "hy2-json-settings",
					"protocol":        "hysteria",
					"settings":        `{"address": "hy2-server.com", "port": 443, "password": "pass"}`,
					"stream_settings": `{"tlsSettings": {"allowInsecure": true}}`,
				},
				{
					"tag":             "hy2-int-port",
					"protocol":        "hysteria2",
					"settings":        map[string]interface{}{"address": "hy2.org", "port": 443},
					"stream_settings": map[string]interface{}{"tlsSettings": map[string]interface{}{"allowInsecure": false}},
				},
			},
		},
	}

	cfg, _, err := c.Compile(spec)
	if err != nil {
		t.Fatalf("failed to compile additional branches spec: %v", err)
	}

	if !strings.Contains(cfg, `"uuid": "pwd-as-uuid"`) {
		t.Errorf("expected pwd-as-uuid: %s", cfg)
	}
	if !strings.Contains(cfg, `"password": "uuid-as-pwd"`) || !strings.Contains(cfg, `"password": "id-as-pwd"`) {
		t.Errorf("expected fallback passwords: %s", cfg)
	}
	if !strings.Contains(cfg, `"server_port": 8443`) {
		t.Errorf("expected parsed handshake server_port 8443: %s", cfg)
	}
}

func TestSingboxCompiler_ShadowsocksInbounds(t *testing.T) {
	c := NewCompiler()

	// 1. Legacy AEAD Shadowsocks (aes-256-gcm) with "tcp,udp" network
	spec := &ast.ConfigSpec{
		TargetCore: ast.CoreSingBox,
		ServerInbounds: []ast.ServerInboundSpec{
			{
				Tag:      "ss-legacy-in",
				Protocol: "shadowsocks",
				Port:     20136,
				RawSettings: map[string]interface{}{
					"method":   "aes-256-gcm",
					"password": "secret_password",
					"network":  "tcp,udp",
				},
				Clients: []ast.ServerInboundClient{
					{
						Email:    "bot",
						Password: "secret_password",
					},
				},
			},
			{
				Tag:      "ss-2022-in",
				Protocol: "shadowsocks",
				Port:     20137,
				RawSettings: map[string]interface{}{
					"method":   "2022-blake3-aes-128-gcm",
					"password": "server_psk_key",
					"network":  "tcp",
				},
				Clients: []ast.ServerInboundClient{
					{
						Email:    "user1",
						Password: "user1_key",
					},
				},
			},
		},
	}

	cfg, _, err := c.Compile(spec)
	if err != nil {
		t.Fatalf("failed to compile Shadowsocks inbounds: %v", err)
	}

	// For ss-legacy: "method": "aes-256-gcm", "password": "secret_password", NO "network": "tcp,udp"
	if strings.Contains(cfg, `"network": "tcp,udp"`) {
		t.Errorf("config must NOT contain 'network: tcp,udp', got:\n%s", cfg)
	}
	if !strings.Contains(cfg, `"method": "aes-256-gcm"`) {
		t.Errorf("expected method aes-256-gcm, got:\n%s", cfg)
	}
	if !strings.Contains(cfg, `"network": "tcp"`) {
		t.Errorf("expected network tcp for ss-2022, got:\n%s", cfg)
	}
}

func TestSingboxCompiler_Hysteria2PortHoppingOutbound(t *testing.T) {
	c := NewCompiler()
	spec := &ast.ConfigSpec{
		TargetCore: ast.CoreSingBox,
		Routing: &ast.RoutingSpec{
			Outbounds: []map[string]interface{}{
				{
					"tag":      "hy2-relay",
					"protocol": "hysteria2",
					"settings": map[string]interface{}{
						"address":  "example.com",
						"port":     "20000-30000",
						"password": "secret_password_123",
						"obfs": map[string]interface{}{
							"type": "salamander",
							"salamander": map[string]interface{}{
								"password": "salamander_secret",
							},
						},
					},
					"streamSettings": map[string]interface{}{
						"security": "tls",
						"tlsSettings": map[string]interface{}{
							"serverName":    "test.example.com",
							"allowInsecure": true,
						},
					},
				},
			},
		},
	}

	cfg, _, err := c.Compile(spec)
	if err != nil {
		t.Fatalf("failed to compile Hysteria 2 outbound: %v", err)
	}

	if !strings.Contains(cfg, `"20000:30000"`) {
		t.Errorf("expected server_ports with 20000:30000, got:\n%s", cfg)
	}
	if !strings.Contains(cfg, `"secret_password_123"`) {
		t.Errorf("expected password secret_password_123, got:\n%s", cfg)
	}
	if !strings.Contains(cfg, `"test.example.com"`) {
		t.Errorf("expected server_name, got:\n%s", cfg)
	}
	if !strings.Contains(cfg, `"salamander_secret"`) {
		t.Errorf("expected obfs password salamander_secret, got:\n%s", cfg)
	}
	if strings.Contains(cfg, `"salamander": {`) {
		t.Errorf("sing-box obfs should be flat and not contain nested salamander struct, got:\n%s", cfg)
	}
}

func TestSingboxCompiler_FallbackURLTestGroup(t *testing.T) {
	c := NewCompiler()
	spec := &ast.ConfigSpec{
		TargetCore: ast.CoreSingBox,
		Routing: &ast.RoutingSpec{
			Outbounds: []map[string]interface{}{
				{
					"tag":      "hy2-out",
					"protocol": "hysteria2",
					"settings": map[string]interface{}{
						"address":               "hy2.example.com",
						"port":                  443,
						"password":              "pass123",
						"fallback_outbound":     "vless-backup",
						"health_check_url":      "https://www.gstatic.com/generate_204",
						"health_check_interval": 15,
						"fallback_strategy":     "priority",
					},
					"streamSettings": map[string]interface{}{
						"security": "tls",
						"tlsSettings": map[string]interface{}{
							"serverName": "hy2.example.com",
						},
					},
				},
				{
					"tag":      "vless-backup",
					"protocol": "vless",
					"settings": map[string]interface{}{
						"vnext": []interface{}{
							map[string]interface{}{
								"address": "vless.example.com",
								"port":    443,
								"users": []interface{}{
									map[string]interface{}{
										"id": "e99dc462-8409-4e45-bf28-665544332211",
									},
								},
							},
						},
					},
				},
			},
		},
	}

	cfg, _, err := c.Compile(spec)
	if err != nil {
		t.Fatalf("failed to compile fallback config: %v", err)
	}

	if !strings.Contains(cfg, `"type": "urltest"`) {
		t.Errorf("expected urltest group in config, got:\n%s", cfg)
	}
	if !strings.Contains(cfg, `"tag": "hy2-out"`) {
		t.Errorf("expected urltest group with tag hy2-out, got:\n%s", cfg)
	}
	if !strings.Contains(cfg, `"hy2-out-primary"`) {
		t.Errorf("expected hy2-out-primary node tag, got:\n%s", cfg)
	}
	if !strings.Contains(cfg, `"vless-backup"`) {
		t.Errorf("expected vless-backup in outbounds list, got:\n%s", cfg)
	}
}


