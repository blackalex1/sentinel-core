package tests

import (
	"strings"
	"testing"
	"github.com/blackalex1/sentinel-core/pkg/ast"
	"github.com/blackalex1/sentinel-core/pkg/builder"
	"github.com/blackalex1/sentinel-core/pkg/routing"
)

func TestCascade_PhoneVLESS_Server1Relay_Server2Hysteria2_XrayRouting(t *testing.T) {
	// =========================================================================
	// 1. СЕРВЕР 2 (Exit Node):
	//    - Hysteria 2 сервер (официальное ядро) с HTTP Webhook Auth
	//    - Проксирует расшифрованный трафик в локальный Xray (порт 20808)
	//    - Xray применяет правила маршрутизации Сервера 2 (AdBlock, Block CN/US, Torrent Shield)
	// =========================================================================
	server2Inbound := ast.ServerInboundSpec{
		Tag:           "hy2-server-in",
		Protocol:      ast.ProtoHysteria2,
		ListenAddress: "0.0.0.0",
		Port:          443,
		SNI:           "exit.sentinel-node.net",
		CertPath:      "/etc/ssl/cert.pem",
		KeyPath:       "/etc/ssl/key.pem",
		ObfsType:      "salamander",
		ObfsPassword:  "ExitObfsPass123",
		Clients: []ast.ServerInboundClient{
			{
				Email:    "http_webhook",
				Password: "https://auth.sentinel-panel.com/v2/hysteria/auth", // HTTP Webhook Auth Backend
			},
		},
	}

	// Таблица маршрутизации Сервера 2 (AdBlock, Torrent Block, RU Bypass)
	server2Routing := &ast.RoutingSpec{
		DefaultAction: ast.ActionDirect,
		Rules: []ast.RoutingRule{
			{
				Action:    ast.ActionBlock,
				Protocols: []string{"bittorrent"},
			},
			{
				Action:  ast.ActionBlock,
				Domains: []string{"geosite:category-ads-all"},
			},
		},
	}

	// 1.1 Конфиг для официального Hysteria 2 сервера на Сервере 2
	server2Hy2JSON, err := builder.BuildServerConfig(ast.CoreHysteria2, []ast.ServerInboundSpec{server2Inbound}, server2Routing, "")
	if err != nil {
		t.Fatalf("failed to compile Hysteria 2 server config: %v", err)
	}

	if !strings.Contains(server2Hy2JSON, `"url": "https://auth.sentinel-panel.com/v2/hysteria/auth"`) {
		t.Errorf("expected HTTP Webhook Auth URL in Hysteria 2 server config:\n%s", server2Hy2JSON)
	}
	if !strings.Contains(server2Hy2JSON, `"addr": "127.0.0.1:20808"`) {
		t.Errorf("expected forwarding to local Xray port 20808 in Hysteria 2 server config:\n%s", server2Hy2JSON)
	}

	// 1.2 Конфиг для Xray на Сервере 2 (принимает SOCKS 20808 от Hysteria 2 и маршрутизирует)
	server2XrayInbound := ast.ServerInboundSpec{
		Tag:           "from-hy2-socks",
		Protocol:      ast.ProtoSocks,
		ListenAddress: "127.0.0.1",
		Port:          20808,
	}

	server2XrayJSON, err := builder.BuildServerConfig(ast.CoreXray, []ast.ServerInboundSpec{server2XrayInbound}, server2Routing, "")
	if err != nil {
		t.Fatalf("failed to compile Server 2 Xray routing config: %v", err)
	}

	if !strings.Contains(server2XrayJSON, `"protocol": "socks"`) || !strings.Contains(server2XrayJSON, `"protocol": "blackhole"`) {
		t.Errorf("expected SOCKS inbound and Blackhole routing in Server 2 Xray config:\n%s", server2XrayJSON)
	}

	// =========================================================================
	// 2. СЕРВЕР 1 (Relay / Мост):
	//    - Принимает VLESS Reality от телефона
	//    - Имеет правила маршрутизации Сервера 1 (RU Direct, Security Block)
	//    - Проксируемый трафик пересылает в Hysteria 2 (на Сервер 2)
	// =========================================================================
	server1VlessInbound := ast.ServerInboundSpec{
		Tag:           "vless-reality-in",
		Protocol:      ast.ProtoVLESS,
		ListenAddress: "0.0.0.0",
		Port:          48423,
		Security:      ast.SecurityReality,
		SNI:           "gateway.icloud.com",
		PrivateKey:    "mPrivKeyRealityTest123",
		ShortIDs:      []string{"0123456789abcdef"},
		Clients: []ast.ServerInboundClient{
			{Email: "phone-user@sentinel", UUID: "a6c8e874-5182-4916-9ea6-f7723933c091", Flow: "xtls-rprx-vision"},
		},
	}

	// Outbound из Сервера 1 в Сервер 2 по Hysteria 2
	toServer2Node := &ast.ServerProfile{
		Name:         "to-server2-hy2",
		Protocol:     ast.ProtoHysteria2,
		Address:      "SERVER2_IP",
		Port:         443,
		Password:     "ClientTokenUser1",
		SNI:          "exit.sentinel-node.net",
		ObfsType:     "salamander",
		ObfsPassword: "ExitObfsPass123",
		PortHopping:  "20000-50000",
	}

	// Таблица маршрутизации Сервера 1 (сайты РФ напрямую через freedom, прочее через Hysteria2)
	server1Table := routing.NewRoutingTable("to-server2-hy2")
	server1Table.AddRule(routing.RoutingRuleRow{
		Order:   1,
		Name:    "Bypass Russian Sites at Relay",
		Enabled: true,
		Target:  "direct",
		Domains: []string{"geosite:ru"},
		IPs:     []string{"geoip:ru"},
	})

	server1Spec := &ast.ConfigSpec{
		TargetCore:     ast.CoreXray,
		ServerInbounds: []ast.ServerInboundSpec{server1VlessInbound},
		ServerNode:     toServer2Node,
		Routing:        server1Table.CompileToAST(),
	}

	server1Res, err := builder.BuildClientConfig(server1Spec)
	if err != nil {
		t.Fatalf("failed to compile Server 1 Relay config: %v", err)
	}

	if !strings.Contains(server1Res.ConfigJSON, `"protocol": "vless"`) {
		t.Errorf("expected VLESS inbound in Server 1 config:\n%s", server1Res.ConfigJSON)
	}
	if !strings.Contains(server1Res.ConfigJSON, `"protocol": "socks"`) {
		t.Errorf("expected chained SOCKS outbound to Hysteria client in Server 1 config:\n%s", server1Res.ConfigJSON)
	}

	// =========================================================================
	// 3. ТЕЛЕФОН (Клиент):
	//    - Подключается по VLESS Reality к Серверу 1
	// =========================================================================
	phoneNode := &ast.ServerProfile{
		Name:        "Server1-VLESS-Reality",
		Protocol:    ast.ProtoVLESS,
		Address:     "SERVER1_IP",
		Port:        48423,
		UUID:        "a6c8e874-5182-4916-9ea6-f7723933c091",
		Security:    ast.SecurityReality,
		SNI:         "gateway.icloud.com",
		PublicKey:   "xM8v9Uj77U7D32q_YtQ5vA3B7X2_Z1y8K9w0O3P4Q5R",
		ShortID:     "0123456789abcdef",
		Flow:        "xtls-rprx-vision",
	}

	phoneSpec := &ast.ConfigSpec{
		TargetCore: ast.CoreSingBox,
		ServerNode: phoneNode,
		ClientInbound: &ast.ClientInboundSpec{
			Mode: ast.InboundModeMobileVpn, // Android VPN loopback
		},
	}

	phoneRes, err := builder.BuildClientConfig(phoneSpec)
	if err != nil {
		t.Fatalf("failed to compile Phone client config: %v", err)
	}

	if !strings.Contains(phoneRes.ConfigJSON, `"type": "vless"`) || !strings.Contains(phoneRes.ConfigJSON, "gateway.icloud.com") {
		t.Errorf("expected VLESS Reality in phone config:\n%s", phoneRes.ConfigJSON)
	}

	t.Log("SUCCESS: All 4 configuration layers (Phone, Server 1 Xray/Hy2, Server 2 Hy2 Webhook, Server 2 Xray Routing) compiled seamlessly!")
}
