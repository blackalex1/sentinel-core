package builder

import (
	"strings"
	"testing"
	"time"

	"github.com/blackalex1/sentinel-core/pkg/ast"
	"github.com/blackalex1/sentinel-core/pkg/events"
)

func TestBuildClientConfig_NilSpec(t *testing.T) {
	_, err := BuildClientConfig(nil)
	if err == nil {
		t.Fatal("expected error for nil spec in BuildClientConfig, got nil")
	}
}

func TestBuildClientConfig_DefaultSingBoxAndSmartPolicy(t *testing.T) {
	spec := &ast.ConfigSpec{
		// TargetCore left empty -> defaults to SingBox
		// Routing left nil -> auto-generates SmartPolicy
		ServerNode: &ast.ServerProfile{
			Protocol: ast.ProtoVLESS,
			Address:  "vless.example.com",
			Port:     443,
			UUID:     "uuid-1234",
		},
		ClientInbound: &ast.ClientInboundSpec{
			SocksPort: 10808,
		},
	}

	res, err := BuildClientConfig(spec)
	if err != nil {
		t.Fatalf("failed to build client config: %v", err)
	}

	if res.TargetCore != ast.CoreSingBox {
		t.Errorf("expected TargetCore SingBox, got: %s", res.TargetCore)
	}
	if !strings.Contains(res.ConfigJSON, "vless.example.com") {
		t.Errorf("expected server address in config, got:\n%s", res.ConfigJSON)
	}
	if !strings.Contains(res.ConfigJSON, "socks-in") {
		t.Errorf("expected socks-in tag in config, got:\n%s", res.ConfigJSON)
	}
}

func TestBuildClientConfig_Xray(t *testing.T) {
	spec := &ast.ConfigSpec{
		TargetCore: ast.CoreXray,
		ServerNode: &ast.ServerProfile{
			Protocol:  ast.ProtoVLESS,
			Address:   "xray.example.com",
			Port:      443,
			UUID:      "uuid-xray",
			Transport: ast.TransportGRPC,
		},
		ClientInbound: &ast.ClientInboundSpec{
			SocksPort: 10808,
			HTTPPort:  10809,
		},
	}

	res, err := BuildClientConfig(spec)
	if err != nil {
		t.Fatalf("failed to build Xray client config: %v", err)
	}

	if res.TargetCore != ast.CoreXray {
		t.Errorf("expected TargetCore Xray, got: %s", res.TargetCore)
	}
	if !strings.Contains(res.ConfigJSON, "xray.example.com") {
		t.Errorf("expected server address in config, got:\n%s", res.ConfigJSON)
	}
	if !strings.Contains(res.ConfigJSON, "grpcSettings") {
		t.Errorf("expected grpcSettings in Xray config, got:\n%s", res.ConfigJSON)
	}
}

func TestBuildClientConfig_Hysteria2_NativeAndAutoSwitch(t *testing.T) {
	// 1. Pure native Hysteria 2 client (no routing rules, no TUN, no server inbounds)
	specNative := &ast.ConfigSpec{
		TargetCore: ast.CoreHysteria2,
		ServerNode: &ast.ServerProfile{
			Protocol: ast.ProtoHysteria2,
			Address:  "hy2.example.com",
			Port:     443,
			Password: "hy2-password",
		},
		Routing: &ast.RoutingSpec{
			Rules: []ast.RoutingRule{}, // Empty rules
		},
	}

	resNative, err := BuildClientConfig(specNative)
	if err != nil {
		t.Fatalf("failed to build native Hysteria2 client config: %v", err)
	}
	if resNative.TargetCore != ast.CoreHysteria2 {
		t.Errorf("expected TargetCore Hysteria2, got: %s", resNative.TargetCore)
	}
	if !strings.Contains(resNative.ConfigJSON, "hy2.example.com:443") {
		t.Errorf("expected server in native hy2 config, got:\n%s", resNative.ConfigJSON)
	}

	// 2. Hysteria 2 with routing rules in Strict Mode -> Reject
	specStrictRouting := &ast.ConfigSpec{
		TargetCore: ast.CoreHysteria2,
		StrictMode: true,
		ServerNode: &ast.ServerProfile{
			Protocol: ast.ProtoHysteria2,
			Address:  "hy2.example.com",
			Port:     443,
			Password: "hy2-password",
		},
		Routing: &ast.RoutingSpec{
			Rules: []ast.RoutingRule{
				{Action: ast.ActionDirect, Domains: []string{"geosite:ru"}},
			},
		},
	}

	_, err = BuildClientConfig(specStrictRouting)
	if err == nil {
		t.Fatal("expected strict mode error for Hysteria2 with routing rules, got nil")
	}

	// 3. Hysteria 2 with TUN in Strict Mode -> Reject
	specStrictTun := &ast.ConfigSpec{
		TargetCore: ast.CoreHysteria2,
		StrictMode: true,
		ServerNode: &ast.ServerProfile{
			Protocol: ast.ProtoHysteria2,
			Address:  "hy2.example.com",
			Port:     443,
			Password: "hy2-password",
		},
		ClientInbound: &ast.ClientInboundSpec{
			Mode: ast.InboundModeDesktopTun,
		},
		Routing: &ast.RoutingSpec{
			Rules: []ast.RoutingRule{},
		},
	}

	_, err = BuildClientConfig(specStrictTun)
	if err == nil {
		t.Fatal("expected strict mode error for Hysteria2 with TUN, got nil")
	}

	// 4. Hysteria 2 with Server Inbounds in Strict Mode -> Reject
	specStrictServerInbounds := &ast.ConfigSpec{
		TargetCore: ast.CoreHysteria2,
		StrictMode: true,
		ServerNode: &ast.ServerProfile{
			Protocol: ast.ProtoHysteria2,
			Address:  "hy2.example.com",
			Port:     443,
			Password: "hy2-password",
		},
		ServerInbounds: []ast.ServerInboundSpec{
			{Port: 443, Protocol: "vless"},
		},
		Routing: &ast.RoutingSpec{
			Rules: []ast.RoutingRule{},
		},
	}

	_, err = BuildClientConfig(specStrictServerInbounds)
	if err == nil {
		t.Fatal("expected strict mode error for Hysteria2 with server inbounds, got nil")
	}

	// 5. Hysteria 2 with routing rules in Non-Strict Mode -> Auto-switch to SingBox
	specAutoSwitch := &ast.ConfigSpec{
		TargetCore: ast.CoreHysteria2,
		StrictMode: false,
		ServerNode: &ast.ServerProfile{
			Protocol: ast.ProtoHysteria2,
			Address:  "hy2.example.com",
			Port:     443,
			Password: "hy2-password",
		},
		Routing: &ast.RoutingSpec{
			Rules: []ast.RoutingRule{
				{Action: ast.ActionDirect, Domains: []string{"geosite:ru"}},
			},
		},
	}

	resAutoSwitch, err := BuildClientConfig(specAutoSwitch)
	if err != nil {
		t.Fatalf("failed to auto-switch Hysteria2 to SingBox: %v", err)
	}
	if resAutoSwitch.TargetCore != ast.CoreSingBox {
		t.Errorf("expected auto-switch to SingBox, got: %s", resAutoSwitch.TargetCore)
	}
	if len(resAutoSwitch.Warnings) == 0 {
		t.Errorf("expected negotiation warning for auto-switch, got none")
	}
}

func TestBuildClientConfig_UnsupportedTargetCore(t *testing.T) {
	spec := &ast.ConfigSpec{
		TargetCore: ast.TargetCore("unsupported_core"),
	}
	_, err := BuildClientConfig(spec)
	if err == nil {
		t.Fatal("expected error for unsupported target core, got nil")
	}
}

func TestBuildClientConfig_CompilationFailureEvent(t *testing.T) {
	// Register a listener on global bus to verify event publication
	eventChan := make(chan events.SentinelEvent, 1)
	events.GetGlobalBus().Subscribe(func(e events.SentinelEvent) {
		if e.Category == events.CategoryCompileWarning && e.Severity == events.SeverityError {
			select {
			case eventChan <- e:
			default:
			}
		}
	})

	spec := &ast.ConfigSpec{
		TargetCore: ast.CoreXray,
		StrictMode: true,
		ServerNode: &ast.ServerProfile{
			Protocol: "invalid_proto_strict",
			Address:  "1.2.3.4",
			Port:     443,
		},
	}

	_, err := BuildClientConfig(spec)
	if err == nil {
		t.Fatal("expected error during compilation failure, got nil")
	}

	select {
	case <-eventChan:
		// Event successfully received
	case <-time.After(1 * time.Second):
		t.Errorf("expected error event published to global bus, timed out")
	}
}

func TestBuildServerConfig_SingBox(t *testing.T) {
	inbounds := []ast.ServerInboundSpec{
		{
			Port:     443,
			Protocol: "vless",
			Tag:      "vless-in",
			Clients: []ast.ServerInboundClient{
				{ID: "uuid-1", Email: "u1@test.com"},
			},
		},
	}
	routing := &ast.RoutingSpec{
		DefaultAction: ast.ActionProxy,
		Rules: []ast.RoutingRule{
			{Action: ast.ActionDirect, OutboundTag: "direct", Domains: []string{"geosite:ru"}},
		},
	}

	// Default targetCore empty -> SingBox
	cfgDefault, err := BuildServerConfig("", inbounds, routing, "127.0.0.1:9090", "singbox.log", "info")
	if err != nil {
		t.Fatalf("failed to build SingBox server config with default core: %v", err)
	}
	if !strings.Contains(cfgDefault, "vless-in") || !strings.Contains(cfgDefault, "clash_api") {
		t.Errorf("unexpected SingBox server config: %s", cfgDefault)
	}

	// Explicit SingBox
	cfg, err := BuildServerConfig(ast.CoreSingBox, inbounds, routing, "127.0.0.1:9090", "singbox.log", "debug")
	if err != nil {
		t.Fatalf("failed to build SingBox server config: %v", err)
	}
	if !strings.Contains(cfg, "vless-in") || !strings.Contains(cfg, `"level": "debug"`) {
		t.Errorf("unexpected SingBox server config: %s", cfg)
	}
}

func TestBuildServerConfig_Xray(t *testing.T) {
	inbounds := []ast.ServerInboundSpec{
		{
			Port:     443,
			Protocol: "vless",
			Tag:      "vless-in",
			Clients: []ast.ServerInboundClient{
				{ID: "uuid-1", Email: "u1@test.com"},
			},
		},
	}
	routing := &ast.RoutingSpec{
		DefaultAction: ast.ActionProxy,
		Rules: []ast.RoutingRule{
			{Action: ast.ActionDirect, OutboundTag: "direct", Domains: []string{"geosite:ru"}},
		},
	}

	cfg, err := BuildServerConfig(ast.CoreXray, inbounds, routing, "", "xray.log", "warn")
	if err != nil {
		t.Fatalf("failed to build Xray server config: %v", err)
	}
	if !strings.Contains(cfg, "vless-in") || !strings.Contains(cfg, `"loglevel": "warning"`) {
		t.Errorf("unexpected Xray server config: %s", cfg)
	}
}

func TestBuildServerConfig_Hysteria2(t *testing.T) {
	// 1. Empty inbounds -> Error
	_, err := BuildServerConfig(ast.CoreHysteria2, nil, nil, "")
	if err == nil {
		t.Fatal("expected error for Hysteria2 server config with empty inbounds, got nil")
	}

	// 2. With routing rules -> forwardPort 20808
	inbounds := []ast.ServerInboundSpec{
		{
			Port:     443,
			Protocol: "hysteria2",
			Tag:      "hy2-in",
			Clients: []ast.ServerInboundClient{
				{Password: "secretpass", Email: "hy2user"},
			},
		},
	}
	routing := &ast.RoutingSpec{
		Rules: []ast.RoutingRule{
			{Action: ast.ActionDirect, Domains: []string{"geosite:ru"}},
		},
	}

	cfgWithRouting, err := BuildServerConfig(ast.CoreHysteria2, inbounds, routing, "", "/var/log/hy2.log", "debug")
	if err != nil {
		t.Fatalf("failed to build Hysteria2 server config with routing: %v", err)
	}
	if !strings.Contains(cfgWithRouting, `"addr": "127.0.0.1:20808"`) {
		t.Errorf("expected forwardPort 20808 in outbounds, got:\n%s", cfgWithRouting)
	}

	// 3. Without routing rules -> forwardPort 0 (no outbounds)
	cfgNoRouting, err := BuildServerConfig(ast.CoreHysteria2, inbounds, nil, "", "", "info")
	if err != nil {
		t.Fatalf("failed to build Hysteria2 server config without routing: %v", err)
	}
	if strings.Contains(cfgNoRouting, `"outbounds"`) {
		t.Errorf("outbounds should be omitted when routing is nil, got:\n%s", cfgNoRouting)
	}
}

func TestBuildFailoverClientConfig_RealBinaryVerification(t *testing.T) {
	profiles := []*ast.ServerProfile{
		{
			Protocol:    ast.ProtoVLESS,
			Name:        "Romania-VLESS",
			Address:     "185.199.109.133",
			Port:        443,
			UUID:        "e99dc462-8409-4e45-bf28-665544332211",
			Security:    ast.SecurityReality,
			SNI:         "gateway.icloud.com",
			Flow:        "xtls-rprx-vision",
			Fingerprint: "chrome",
			PublicKey:   "Zz7rR5o6eH_jU_aC_zE7xU2v8z1r9q4e3w2y1x0z9u8",
			ShortID:     "6ba7b810",
		},
		{
			Protocol: ast.ProtoHysteria2,
			Name:     "Finland-Hysteria2",
			Address:  "fi.example.com",
			Port:     8443,
			Password: "hy2password123",
			SNI:      "fi.example.com",
		},
		{
			Protocol: ast.ProtoTrojan,
			Name:     "Germany-Trojan",
			Address:  "de.example.com",
			Port:     443,
			Password: "trojanpassword",
			SNI:      "de.example.com",
		},
	}

	res, err := BuildFailoverClientConfig(profiles, ast.CoreSingBox, 10818, 10819, "https://api.telegram.org")
	if err != nil {
		t.Fatalf("BuildFailoverClientConfig failed: %v", err)
	}

	if res == nil || res.ConfigJSON == "" {
		t.Fatal("expected non-empty configJson in BuildResult")
	}

	// Verify no deprecated address_resolver
	if strings.Contains(res.ConfigJSON, "address_resolver") {
		t.Fatalf("Config contains deprecated 'address_resolver' field:\n%s", res.ConfigJSON)
	}
}
