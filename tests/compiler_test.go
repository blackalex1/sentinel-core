package tests

import (
	"encoding/json"
	"strings"
	"testing"
	"github.com/blackalex1/sentinel-core/pkg/ast"
	"github.com/blackalex1/sentinel-core/pkg/builder"
	"github.com/blackalex1/sentinel-core/pkg/compiler/wireguard"
)

func TestCompiler_SingBox_TunAndRoutes(t *testing.T) {
	node := &ast.ServerProfile{
		Name:      "DE-Server",
		Protocol:  ast.ProtoVLESS,
		Address:   "1.2.3.4",
		Port:      443,
		UUID:      "a6c8e874-5182-4916-9ea6-f7723933c091",
		Security:  ast.SecurityReality,
		PublicKey: "xM8v9Uj77U7D32q_YtQ5vA3B7X2_Z1y8K9w0O3P4Q5R",
		ShortID:   "0123456789abcdef",
		SNI:       "gateway.icloud.com",
		Flow:      "xtls-rprx-vision",
	}

	spec := &ast.ConfigSpec{
		TargetCore: ast.CoreSingBox,
		ServerNode: node,
		ClientInbound: &ast.ClientInboundSpec{
			Mode:             ast.InboundModeDesktopTun,
			TunInterfaceName: "wintun-sentinel",
			SocksPort:        10808,
			HTTPPort:         10809,
		},
		Routing: &ast.RoutingSpec{
			DefaultAction: ast.ActionProxy,
			Rules: []ast.RoutingRule{
				{
					Action:  ast.ActionDirect,
					Domains: []string{"geosite:category-ads-all", "domain:yandex.ru"},
					IPs:     []string{"geoip:ru", "geoip:private"},
				},
				{
					Action:       ast.ActionProxy,
					ProcessNames: []string{"discord.exe", "telegram.exe"},
				},
			},
		},
		ClashAPIAddress: "127.0.0.1:9090",
	}

	res, err := builder.BuildClientConfig(spec)
	if err != nil {
		t.Fatalf("failed to build sing-box config: %v", err)
	}

	// Validate it is valid JSON
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(res.ConfigJSON), &parsed); err != nil {
		t.Fatalf("generated config is not valid JSON: %v", err)
	}

	if !strings.Contains(res.ConfigJSON, "wintun-sentinel") {
		t.Errorf("expected TUN interface name in config")
	}
	if !strings.Contains(res.ConfigJSON, "127.0.0.1:9090") {
		t.Errorf("expected clash api in config")
	}
}

func TestCompiler_Hysteria2(t *testing.T) {
	node := &ast.ServerProfile{
		Name:         "Hy2-Server",
		Protocol:     ast.ProtoHysteria2,
		Address:      "45.67.89.10",
		Port:         8443,
		Password:     "mypassword123",
		SNI:          "cdn.cloudflare.com",
		BandwidthUp:  "50 mbps",
		BandwidthDown: "150 mbps",
		ObfsType:     "salamander",
		ObfsPassword: "secret-obfs",
		PortHopping:  "20000-40000",
	}

	spec := &ast.ConfigSpec{
		TargetCore: ast.CoreHysteria2,
		ServerNode: node,
		ClientInbound: &ast.ClientInboundSpec{
			SocksPort: 10808,
		},
		Routing: &ast.RoutingSpec{}, // Empty routing allows native Hysteria compiler
	}

	res, err := builder.BuildClientConfig(spec)
	if err != nil {
		t.Fatalf("failed to build hysteria2 config: %v", err)
	}

	if !strings.Contains(res.ConfigJSON, "45.67.89.10:20000-40000") {
		t.Errorf("expected port hopping endpoint in config, got:\n%s", res.ConfigJSON)
	}
	if !strings.Contains(res.ConfigJSON, "salamander") {
		t.Errorf("expected salamander obfs in config")
	}
}

func TestCompiler_Hysteria2_AutoSwitchToSingBoxWithRouting(t *testing.T) {
	node := &ast.ServerProfile{
		Name:     "Hy2-Server",
		Protocol: ast.ProtoHysteria2,
		Address:  "45.67.89.10",
		Port:     8443,
		Password: "mypassword123",
	}

	// Request Hysteria2 core with routing rules present
	spec := &ast.ConfigSpec{
		TargetCore: ast.CoreHysteria2,
		ServerNode: node,
		Routing: &ast.RoutingSpec{
			Rules: []ast.RoutingRule{
				{Action: ast.ActionDirect, Domains: []string{"yandex.ru"}},
			},
		},
	}

	res, err := builder.BuildClientConfig(spec)
	if err != nil {
		t.Fatalf("failed to build config: %v", err)
	}

	// Should have auto-switched to Sing-box to support routing
	if res.TargetCore != ast.CoreSingBox {
		t.Errorf("expected auto-switch to Sing-box, got %s", res.TargetCore)
	}
	if len(res.Warnings) == 0 {
		t.Errorf("expected negotiation warnings about auto-switch to Sing-box")
	}
}

func TestCompiler_SingBox_Hysteria2_PortHopping(t *testing.T) {
	node := &ast.ServerProfile{
		Name:        "Hy2-Server",
		Protocol:    ast.ProtoHysteria2,
		Address:     "45.67.89.10",
		Port:        8443,
		Password:    "mypassword123",
		SNI:         "cdn.cloudflare.com",
		PortHopping: "20000-40000, 443",
	}

	spec := &ast.ConfigSpec{
		TargetCore: ast.CoreSingBox,
		ServerNode: node,
		ClientInbound: &ast.ClientInboundSpec{
			SocksPort: 10808,
			HTTPPort:  10809,
		},
	}

	res, err := builder.BuildClientConfig(spec)
	if err != nil {
		t.Fatalf("failed to build sing-box hysteria2 config: %v", err)
	}

	if !strings.Contains(res.ConfigJSON, `"server_ports"`) || !strings.Contains(res.ConfigJSON, "20000:40000") {
		t.Errorf("expected server_ports with 20000:40000 in sing-box config:\n%s", res.ConfigJSON)
	}
}

func TestCompiler_Xray_Hysteria2_RoutingChain(t *testing.T) {
	node := &ast.ServerProfile{
		Name:     "Hy2-Webhook-Server",
		Protocol: ast.ProtoHysteria2,
		Address:  "45.67.89.10",
		Port:     8443,
		Password: "user-password",
	}

	spec := &ast.ConfigSpec{
		TargetCore: ast.CoreXray,
		ServerNode: node,
		ClientInbound: &ast.ClientInboundSpec{
			SocksPort: 20808,
			HTTPPort:  20809,
		},
		Routing: &ast.RoutingSpec{
			DefaultAction: ast.ActionProxy,
			Rules: []ast.RoutingRule{
				{
					Action:  ast.ActionDirect,
					Domains: []string{"geosite:ru"},
					IPs:     []string{"geoip:ru"},
				},
				{
					Action:  ast.ActionBlock,
					Domains: []string{"geosite:category-ads-all"},
				},
			},
		},
	}

	res, err := builder.BuildClientConfig(spec)
	if err != nil {
		t.Fatalf("failed to build Xray + Hysteria 2 chained config: %v", err)
	}

	if !strings.Contains(res.ConfigJSON, `"protocol": "socks"`) {
		t.Errorf("expected chained socks outbound in Xray config:\n%s", res.ConfigJSON)
	}
	if !strings.Contains(res.ConfigJSON, `"protocol": "freedom"`) || !strings.Contains(res.ConfigJSON, `"protocol": "blackhole"`) {
		t.Errorf("expected freedom and blackhole routing rules in Xray config:\n%s", res.ConfigJSON)
	}
}

func TestCompiler_WireGuard(t *testing.T) {
	node := &ast.ServerProfile{
		Protocol:      ast.ProtoWireGuard,
		Address:       "198.51.100.1",
		Port:          51820,
		PrivateKey:    "aGVsbG93b3JsZHByaXZhdGVrZXkxMjM0NTY3ODkwMTI=",
		PeerPublicKey: "cGVlcnB1YmxpY2tleTEyMzQ1Njc4OTAxMjM0NTY3ODk=",
		LocalAddress:  []string{"10.0.0.2/32"},
		MTU:           1420,
	}

	conf, err := wireguard.BuildWireGuardConf(node)
	if err != nil {
		t.Fatalf("failed to build wireguard config: %v", err)
	}

	if !strings.Contains(conf, "[Interface]") || !strings.Contains(conf, "198.51.100.1:51820") {
		t.Errorf("invalid wireguard conf output:\n%s", conf)
	}
}

func TestProtocolSwitching_InboundAndOutbound(t *testing.T) {
	// 1. Initial State: Inbound is VLESS on port 48423 with Sing-Box engine (as shown in modal screenshot)
	inbound := ast.ServerInboundSpec{
		Tag:           "double_v2",
		Protocol:      ast.ProtoVLESS,
		ListenAddress: "0.0.0.0",
		Port:          48423,
		Security:      ast.SecurityReality,
		SNI:           "gateway.icloud.com",
		PrivateKey:    "test-privkey",
		ShortIDs:      []string{"0123456789abcdef"},
		Clients: []ast.ServerInboundClient{
			{Email: "user1@sentinel", UUID: "a6c8e874-5182-4916-9ea6-f7723933c091", Flow: "xtls-rprx-vision"},
		},
	}

	serverRes1, err := builder.BuildServerConfig(ast.CoreSingBox, []ast.ServerInboundSpec{inbound}, nil, "")
	if err != nil {
		t.Fatalf("failed to build initial VLESS server config: %v", err)
	}
	if !strings.Contains(serverRes1, `"type": "vless"`) || !strings.Contains(serverRes1, "48423") {
		t.Errorf("expected vless inbound on 48423 in json")
	}

	// 2. User changes Protocol in modal dropdown from VLESS to Trojan
	inbound.Protocol = ast.ProtoTrojan
	inbound.Clients[0].Password = "trojan-secure-password"

	serverRes2, err := builder.BuildServerConfig(ast.CoreSingBox, []ast.ServerInboundSpec{inbound}, nil, "")
	if err != nil {
		t.Fatalf("failed to build changed Trojan server config: %v", err)
	}
	if !strings.Contains(serverRes2, `"type": "trojan"`) {
		t.Errorf("expected trojan inbound after protocol change")
	}

	// 3. User changes Engine in modal dropdown from sing-box to xray
	serverRes3, err := builder.BuildServerConfig(ast.CoreXray, []ast.ServerInboundSpec{inbound}, nil, "")
	if err != nil {
		t.Fatalf("failed to build Xray server config: %v", err)
	}
	if !strings.Contains(serverRes3, `"protocol": "trojan"`) {
		t.Errorf("expected Xray format with protocol: trojan")
	}
}
