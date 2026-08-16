package xray

import (
	"strings"
	"testing"

	"github.com/blackalex1/sentinel-core/pkg/ast"
)

func TestXrayCompiler_NilSpec(t *testing.T) {
	c := NewCompiler()
	_, _, err := c.Compile(nil)
	if err == nil {
		t.Fatal("expected error when spec is nil, got nil")
	}
}

func TestXrayCompiler_ServerNodeNegotiationFailure(t *testing.T) {
	c := NewCompiler()
	spec := &ast.ConfigSpec{
		TargetCore: ast.CoreXray,
		StrictMode: true,
		ServerNode: &ast.ServerProfile{
			Protocol: "unsupported_protocol_xyz",
			Address:  "1.2.3.4",
			Port:     443,
		},
	}
	_, _, err := c.Compile(spec)
	if err == nil {
		t.Fatal("expected error on unsupported protocol in strict mode, got nil")
	}
}

func TestXrayCompiler_BuildXrayOutbound_Protocols(t *testing.T) {
	// Nil node
	_, err := BuildXrayOutbound(nil)
	if err == nil {
		t.Fatal("expected error for nil node in BuildXrayOutbound")
	}

	// Unsupported protocol
	_, err = BuildXrayOutbound(&ast.ServerProfile{Protocol: "unknown_proto"})
	if err == nil {
		t.Fatal("expected error for unknown protocol in BuildXrayOutbound")
	}

	// 1. VLESS Outbound with TCP & TLS
	vlessNode := &ast.ServerProfile{
		Name:        "my-vless-node",
		Protocol:    ast.ProtoVLESS,
		Address:     "vless.example.com",
		Port:        443,
		UUID:        "e99dc462-8409-4e45-bf28-665544332211",
		Flow:        "xtls-rprx-vision",
		Transport:   ast.TransportTCP,
		Security:    ast.SecurityTLS,
		SNI:         "vless.example.com",
		ALPN:        []string{"h2", "http/1.1"},
		PostQuantum: true,
	}
	obVless, err := BuildXrayOutbound(vlessNode)
	if err != nil {
		t.Fatalf("failed to build VLESS outbound: %v", err)
	}
	if obVless["tag"] != "my-vless-node" || obVless["protocol"] != "vless" {
		t.Errorf("unexpected vless outbound: %+v", obVless)
	}

	// 2. VLESS Outbound with Reality & gRPC & PostQuantum
	vlessRealityGrpc := &ast.ServerProfile{
		Protocol:    ast.ProtoVLESS,
		Address:     "reality.example.com",
		Port:        443,
		UUID:        "e99dc462-8409-4e45-bf28-665544332211",
		Transport:   ast.TransportGRPC,
		ServiceName: "grpc-service-test",
		Security:    ast.SecurityReality,
		SNI:         "gateway.icloud.com",
		PublicKey:   "abcdef1234567890=",
		ShortID:     "12345678",
		SpiderX:     "/path",
		Fingerprint: "chrome",
		PostQuantum: true,
	}
	obReality, err := BuildXrayOutbound(vlessRealityGrpc)
	if err != nil {
		t.Fatalf("failed to build Reality gRPC outbound: %v", err)
	}
	ss := obReality["streamSettings"].(map[string]interface{})
	if ss["security"] != "reality" || ss["network"] != "grpc" {
		t.Errorf("expected reality security and grpc network: %+v", ss)
	}
	grpcSettings := ss["grpcSettings"].(map[string]interface{})
	if grpcSettings["serviceName"] != "grpc-service-test" {
		t.Errorf("expected grpc serviceName: %+v", grpcSettings)
	}

	// 3. VLESS Outbound with WS transport and Host header
	vlessWs := &ast.ServerProfile{
		Protocol:  ast.ProtoVLESS,
		Address:   "ws.example.com",
		Port:      443,
		UUID:      "e99dc462-8409-4e45-bf28-665544332211",
		Transport: ast.TransportWS,
		Path:      "/ws-path",
		Host:      "ws.example.com",
		Security:  ast.SecurityTLS,
		SNI:       "ws.example.com",
	}
	obWs, err := BuildXrayOutbound(vlessWs)
	if err != nil {
		t.Fatalf("failed to build WS outbound: %v", err)
	}
	wsSettings := obWs["streamSettings"].(map[string]interface{})["wsSettings"].(map[string]interface{})
	if wsSettings["path"] != "/ws-path" {
		t.Errorf("expected ws path /ws-path: %+v", wsSettings)
	}

	// 4. VLESS Outbound with xHTTP / splitHTTP transport
	vlessXhttp := &ast.ServerProfile{
		Protocol:  ast.ProtoVLESS,
		Address:   "xhttp.example.com",
		Port:      443,
		UUID:      "e99dc462-8409-4e45-bf28-665544332211",
		Transport: ast.TransportXHTTP,
		Path:      "/xhttp-path",
		Host:      "xhttp.example.com",
	}
	obXhttp, err := BuildXrayOutbound(vlessXhttp)
	if err != nil {
		t.Fatalf("failed to build xHTTP outbound: %v", err)
	}
	xhttpSettings := obXhttp["streamSettings"].(map[string]interface{})["xhttpSettings"].(map[string]interface{})
	if xhttpSettings["mode"] != "auto" || xhttpSettings["path"] != "/xhttp-path" {
		t.Errorf("expected xhttp mode auto: %+v", xhttpSettings)
	}

	// 5. VMess Outbound
	vmessNode := &ast.ServerProfile{
		Protocol: ast.ProtoVMess,
		Address:  "vmess.example.com",
		Port:     443,
		UUID:     "e99dc462-8409-4e45-bf28-665544332211",
	}
	obVmess, err := BuildXrayOutbound(vmessNode)
	if err != nil {
		t.Fatalf("failed to build VMess outbound: %v", err)
	}
	if obVmess["protocol"] != "vmess" {
		t.Errorf("expected vmess protocol: %+v", obVmess)
	}

	// 6. Trojan Outbound
	trojanNode := &ast.ServerProfile{
		Protocol: ast.ProtoTrojan,
		Address:  "trojan.example.com",
		Port:     443,
		Password: "trojan-password",
	}
	obTrojan, err := BuildXrayOutbound(trojanNode)
	if err != nil {
		t.Fatalf("failed to build Trojan outbound: %v", err)
	}
	if obTrojan["protocol"] != "trojan" {
		t.Errorf("expected trojan protocol: %+v", obTrojan)
	}

	// 7. Shadowsocks Outbound (custom cipher and default)
	ssNodeCustom := &ast.ServerProfile{
		Protocol: ast.ProtoShadowsocks,
		Address:  "ss.example.com",
		Port:     8388,
		Password: "ss-password",
		Cipher:   "aes-256-gcm",
	}
	obSSCustom, err := BuildXrayOutbound(ssNodeCustom)
	if err != nil {
		t.Fatalf("failed to build SS outbound: %v", err)
	}
	serversSS := obSSCustom["settings"].(map[string]interface{})["servers"].([]map[string]interface{})
	if serversSS[0]["method"] != "aes-256-gcm" {
		t.Errorf("expected aes-256-gcm method: %+v", serversSS)
	}

	ssNodeDefault := &ast.ServerProfile{
		Protocol: ast.ProtoShadowsocks,
		Address:  "ss.example.com",
		Port:     8388,
		Password: "ss-password",
	}
	obSSDef, _ := BuildXrayOutbound(ssNodeDefault)
	serversSSDef := obSSDef["settings"].(map[string]interface{})["servers"].([]map[string]interface{})
	if serversSSDef[0]["method"] != "2022-blake3-aes-128-gcm" {
		t.Errorf("expected default ss method: %+v", serversSSDef)
	}

	// 8. WireGuard Outbound
	wgNode := &ast.ServerProfile{
		Protocol:      ast.ProtoWireGuard,
		Address:       "wg.example.com",
		Port:          51820,
		PrivateKey:    "privkey123",
		PeerPublicKey: "pubkey123",
		PreSharedKey:  "psk123",
		LocalAddress:  []string{"10.0.0.2/32"},
		MTU:           1420,
	}
	obWg, err := BuildXrayOutbound(wgNode)
	if err != nil {
		t.Fatalf("failed to build WireGuard outbound: %v", err)
	}
	if obWg["protocol"] != "wireguard" {
		t.Errorf("expected wireguard protocol: %+v", obWg)
	}

	// 9. Hysteria 2 Outbound
	hy2Node := &ast.ServerProfile{
		Protocol: ast.ProtoHysteria2,
		Address:  "127.0.0.1",
		Port:     20808,
	}
	obHy2, err := BuildXrayOutbound(hy2Node)
	if err != nil {
		t.Fatalf("failed to build Hysteria2 outbound: %v", err)
	}
	if obHy2["protocol"] != "socks" {
		t.Errorf("expected socks protocol for hy2 outbound: %+v", obHy2)
	}

	// 10. Direct and Block
	obDirect, err := BuildXrayOutbound(&ast.ServerProfile{Protocol: ast.ProtoDirect})
	if err != nil || obDirect["protocol"] != "freedom" {
		t.Errorf("expected freedom outbound: %+v", obDirect)
	}
	obBlock, err := BuildXrayOutbound(&ast.ServerProfile{Protocol: ast.ProtoBlock})
	if err != nil || obBlock["protocol"] != "blackhole" {
		t.Errorf("expected blackhole outbound: %+v", obBlock)
	}
}

func TestXrayCompiler_ClientInbounds(t *testing.T) {
	c := NewCompiler()

	// 1. SOCKS with auth and HTTP inbound
	spec := &ast.ConfigSpec{
		TargetCore: ast.CoreXray,
		ClientInbound: &ast.ClientInboundSpec{
			ListenAddress: "127.0.0.1",
			SocksPort:     10808,
			HTTPPort:      10809,
			AuthEnabled:   true,
			AuthUsername:  "sentinel",
			AuthPassword:  "secret",
		},
	}

	cfg, _, err := c.Compile(spec)
	if err != nil {
		t.Fatalf("failed to compile client inbounds: %v", err)
	}

	if !strings.Contains(cfg, `"tag": "socks-in"`) || !strings.Contains(cfg, `"tag": "http-in"`) {
		t.Errorf("expected socks-in and http-in tags, got:\n%s", cfg)
	}
	if !strings.Contains(cfg, `"user": "sentinel"`) || !strings.Contains(cfg, `"pass": "secret"`) {
		t.Errorf("expected auth credentials in socks-in, got:\n%s", cfg)
	}

	// 2. Default fallback inbound when ClientInbound is nil
	specEmpty := &ast.ConfigSpec{
		TargetCore: ast.CoreXray,
	}
	cfgEmpty, _, err := c.Compile(specEmpty)
	if err != nil {
		t.Fatalf("failed to compile empty spec: %v", err)
	}
	if !strings.Contains(cfgEmpty, `"tag": "socks-in"`) || !strings.Contains(cfgEmpty, `10808`) {
		t.Errorf("expected default socks-in 10808 inbound, got:\n%s", cfgEmpty)
	}
}

func TestXrayCompiler_ServerInbounds_AllProtocols(t *testing.T) {
	c := NewCompiler()

	spec := &ast.ConfigSpec{
		TargetCore: ast.CoreXray,
		ServerInbounds: []ast.ServerInboundSpec{
			// VLESS with TLS and fallbacks
			{
				Tag:           "vless-tls-in",
				Protocol:      "vless",
				Port:          443,
				ListenAddress: "0.0.0.0",
				Security:      "tls",
				SNI:           "tls.example.com",
				CertPath:      "/etc/ssl/cert.pem",
				KeyPath:       "/etc/ssl/key.pem",
				Clients: []ast.ServerInboundClient{
					{UUID: "uuid-1", Email: "vless-user@test.com", Flow: "xtls-rprx-vision"},
				},
				Fallbacks: []map[string]interface{}{
					{"dest": 8080, "xver": 1},
				},
			},
			// VLESS with Reality
			{
				Tag:        "vless-reality-in",
				Protocol:   "vless",
				Port:       8443,
				Security:   "reality",
				SNI:        "gateway.icloud.com",
				PrivateKey: "private-key-base64",
				ShortIDs:   []string{"12345678", "abcdef12"},
				Clients: []ast.ServerInboundClient{
					{UUID: "uuid-2", Email: "reality-user@test.com"},
				},
			},
			// Trojan
			{
				Tag:      "trojan-in",
				Protocol: "trojan",
				Port:     9443,
				Clients: []ast.ServerInboundClient{
					{Password: "trojan-pass-1", Email: "trojan-user@test.com"},
				},
			},
			// VMess
			{
				Tag:      "vmess-in",
				Protocol: "vmess",
				Port:     10443,
				Clients: []ast.ServerInboundClient{
					{UUID: "uuid-3", Email: "vmess-user@test.com"},
				},
			},
			// Shadowsocks
			{
				Tag:      "ss-in",
				Protocol: "shadowsocks",
				Port:     11443,
				Clients: []ast.ServerInboundClient{
					{Password: "ss-password-123"},
				},
				RawSettings: map[string]interface{}{
					"method": "aes-128-gcm",
				},
			},
			// SOCKS
			{
				Tag:      "socks-server-in",
				Protocol: "socks",
				Port:     12443,
				Sniffing: map[string]interface{}{
					"enabled":      false,
					"destOverride": []string{"http"},
				},
			},
		},
	}

	cfg, _, err := c.Compile(spec)
	if err != nil {
		t.Fatalf("failed to compile server inbounds: %v", err)
	}

	expectedSnippets := []string{
		"vless-tls-in",
		"vless-reality-in",
		"trojan-in",
		"vmess-in",
		"ss-in",
		"socks-server-in",
		`"tag": "api"`,
		`"port": 10085`,
		`"statsUserUplink": true`,
		`"HandlerService"`,
		`"LoggerService"`,
		`"StatsService"`,
	}

	for _, snippet := range expectedSnippets {
		if !strings.Contains(cfg, snippet) {
			t.Errorf("expected snippet %q in compiled server config, got:\n%s", snippet, cfg)
		}
	}
}

func TestXrayCompiler_RoutingAndBalancers(t *testing.T) {
	c := NewCompiler()

	spec := &ast.ConfigSpec{
		TargetCore: ast.CoreXray,
		Routing: &ast.RoutingSpec{
			DefaultAction: ast.ActionProxy,
			Outbounds: []map[string]interface{}{
				{
					"tag":      "proxy-primary",
					"protocol": "socks",
					"settings": map[string]interface{}{
						"servers": []map[string]interface{}{
							{
								"address": "127.0.0.1",
								"port":    20808,
							},
						},
						"backup_outbounds": []string{
							"proxy-backup-1",
						},
						"health_check_url":      "https://www.google.com/generate_204",
						"health_check_interval": float64(15),
					},
				},
				{
					"tag":      "proxy-backup-1",
					"protocol": "socks",
					"settings": map[string]interface{}{
						"address": "127.0.0.1",
						"port":    10808,
					},
				},
				{
					"tag":      "proxy-vless-node",
					"protocol": "vless",
					"settings": `{"vnext": [{"address": "1.1.1.1", "port": 443}]}`,
					"stream_settings": `{"network": "tcp", "security": "tls"}`,
				},
			},
			Rules: []ast.RoutingRule{
				{
					Action:      ast.ActionDirect,
					Domains:     []string{"geosite:ru", "geosite:google", "example.com"},
					IPs:         []string{"geoip:private", "geoip:ru", "192.168.1.0/24"},
					Ports:       []string{"80", "443", "1000-2000"},
					Protocols:   []string{"tcp", "udp", "bittorrent", "quic"},
					Users:       []string{"user@test.com"},
					InboundTags: []string{"socks-in"},
				},
				{
					Action:      ast.ActionProxy,
					OutboundTag: "proxy-primary",
					Domains:     []string{"openai.com"},
				},
				{
					Action:      ast.ActionBlock,
					Domains:     []string{"ads.example.com"},
					PackageUIDs: []string{"10001"},
				},
			},
		},
	}

	cfg, _, err := c.Compile(spec)
	if err != nil {
		t.Fatalf("failed to compile routing and balancers config: %v", err)
	}

	expectedSnippets := []string{
		"geosite:category-ru",
		"geosite:google",
		"geoip:private",
		"geoip:ru",
		`"port": "80,443,1000-2000"`,
		`"network": "tcp,udp"`,
		`"protocol": [`,
		`"bittorrent"`,
		`"quic"`,
		`"balancerTag": "balancer-proxy-primary"`,
		`"observatory"`,
		`"probeUrl": "https://www.google.com/generate_204"`,
		`"probeInterval": "15s"`,
	}

	for _, snippet := range expectedSnippets {
		if !strings.Contains(cfg, snippet) {
			t.Errorf("expected snippet %q in config, got:\n%s", snippet, cfg)
		}
	}
}

func TestXrayCompiler_LogLevelAndLogPath(t *testing.T) {
	c := NewCompiler()

	// Test "warn" -> "warning"
	specWarn := &ast.ConfigSpec{
		TargetCore: ast.CoreXray,
		LogLevel:   "warn",
		LogPath:    "/var/log/xray.log",
	}
	cfgWarn, _, _ := c.Compile(specWarn)
	if !strings.Contains(cfgWarn, `"loglevel": "warning"`) || !strings.Contains(cfgWarn, `"/var/log/xray.log"`) {
		t.Errorf("expected loglevel warning and log path: %s", cfgWarn)
	}

	// Test valid "debug"
	specDebug := &ast.ConfigSpec{
		TargetCore: ast.CoreXray,
		LogLevel:   "debug",
	}
	cfgDebug, _, _ := c.Compile(specDebug)
	if !strings.Contains(cfgDebug, `"loglevel": "debug"`) {
		t.Errorf("expected loglevel debug: %s", cfgDebug)
	}
}

func TestXrayCompiler_AdditionalBranches(t *testing.T) {
	c := NewCompiler()

	// 1. Existing outbounds with direct, block, blocked, api tags
	// 2. Outbounds with backup_outbounds as []interface{}, int interval, int port
	// 3. VLESS/VMess with existing users in vnext
	// 4. Inbound defaults: empty protocol, empty listen address, vless empty clients, fallback from RawSettings, etc.
	spec := &ast.ConfigSpec{
		TargetCore: ast.CoreXray,
		LogLevel:   "error",
		ServerNode: &ast.ServerProfile{
			Protocol:    ast.ProtoVLESS,
			Address:     "node.example.com",
			Port:        443,
			UUID:        "uuid-test",
			Transport:   ast.TransportGRPC,
			Path:        "grpc-path-service",
			Fingerprint: "firefox",
		},
		ServerInbounds: []ast.ServerInboundSpec{
			{
				Tag:  "vless-default-in",
				Port: 443,
				RawSettings: map[string]interface{}{
					"fallbacks": []map[string]interface{}{
						{"dest": 80},
					},
				},
				StreamSettings: map[string]interface{}{
					"security": "tls",
					"tlsSettings": map[string]interface{}{
						"serverName": "custom-tls.com",
					},
				},
			},
			{
				Tag:      "ss-no-clients",
				Protocol: "shadowsocks",
				Port:     8388,
			},
		},
		Routing: &ast.RoutingSpec{
			Outbounds: []map[string]interface{}{
				{"tag": "direct", "protocol": "freedom"},
				{"tag": "block", "protocol": "blackhole"},
				{"tag": "blocked", "protocol": "blackhole"},
				{"tag": "api", "protocol": "blackhole"},
				{
					"tag":      "hy2-int-port",
					"protocol": "hysteria",
					"settings": map[string]interface{}{
						"port": 20809,
					},
				},
				{
					"tag":      "socks-int-port",
					"protocol": "socks",
					"settings": map[string]interface{}{
						"port": 10809,
						"backup_outbounds": []interface{}{
							"backup-1",
						},
						"health_check_interval": 30,
					},
				},
				{
					"tag":      "vless-existing-users",
					"protocol": "vmess",
					"settings": map[string]interface{}{
						"vnext": []interface{}{
							map[string]interface{}{
								"address": "2.2.2.2",
								"port":    443,
								"users": []interface{}{
									map[string]interface{}{"id": "my-user-id"},
								},
							},
						},
					},
				},
			},
			Rules: []ast.RoutingRule{
				{
					Action: ast.ActionProxy,
				},
				{
					Action: ast.ActionDirect,
				},
				{
					Action: ast.ActionBlock,
				},
			},
		},
	}

	cfg, _, err := c.Compile(spec)
	if err != nil {
		t.Fatalf("failed to compile additional branches spec: %v", err)
	}

	if !strings.Contains(cfg, `"loglevel": "error"`) {
		t.Errorf("expected loglevel error: %s", cfg)
	}
	if !strings.Contains(cfg, `"serviceName": "grpc-path-service"`) {
		t.Errorf("expected serviceName from Path: %s", cfg)
	}
	if !strings.Contains(cfg, `"my-user-id"`) {
		t.Errorf("expected my-user-id: %s", cfg)
	}
}

func TestXrayCompiler_FallbackBalancer(t *testing.T) {
	c := NewCompiler()
	spec := &ast.ConfigSpec{
		TargetCore: ast.CoreXray,
		Routing: &ast.RoutingSpec{
			Outbounds: []map[string]interface{}{
				{
					"tag":      "primary-out",
					"protocol": "vless",
					"settings": map[string]interface{}{
						"fallback_outbound":     "backup-out",
						"health_check_url":      "https://www.gstatic.com/generate_204",
						"health_check_interval": 15,
						"vnext": []interface{}{
							map[string]interface{}{
								"address": "1.1.1.1",
								"port":    443,
								"users": []interface{}{
									map[string]interface{}{"id": "e99dc462-8409-4e45-bf28-665544332211"},
								},
							},
						},
					},
				},
				{
					"tag":      "backup-out",
					"protocol": "vless",
					"settings": map[string]interface{}{
						"vnext": []interface{}{
							map[string]interface{}{
								"address": "2.2.2.2",
								"port":    443,
								"users": []interface{}{
									map[string]interface{}{"id": "e99dc462-8409-4e45-bf28-665544332222"},
								},
							},
						},
					},
				},
			},
			Rules: []ast.RoutingRule{
				{
					Action:      "primary-out",
					Domains:     []string{"domain:google.com"},
					InboundTags: []string{"inbound-1"},
				},
			},
		},
	}

	cfg, _, err := c.Compile(spec)
	if err != nil {
		t.Fatalf("failed to compile Xray fallback spec: %v", err)
	}

	if !strings.Contains(cfg, `"observatory"`) {
		t.Errorf("expected observatory in Xray config, got:\n%s", cfg)
	}
	if !strings.Contains(cfg, `"balancer-primary-out"`) {
		t.Errorf("expected balancer-primary-out in config, got:\n%s", cfg)
	}
	if !strings.Contains(cfg, `"fallbackTag": "backup-out"`) {
		t.Errorf("expected fallbackTag backup-out in balancer, got:\n%s", cfg)
	}
	if !strings.Contains(cfg, `"balancerTag": "balancer-primary-out"`) {
		t.Errorf("expected rule outboundTag replaced by balancerTag, got:\n%s", cfg)
	}
}
