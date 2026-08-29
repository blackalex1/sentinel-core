package singbox_test

import (
	"encoding/json"
	"testing"

	"github.com/blackalex1/sentinel-core/pkg/ast"
	"github.com/blackalex1/sentinel-core/pkg/builder"
	"github.com/blackalex1/sentinel-core/pkg/routing"
)

// 1. Smart Routing Engine with Rule Sets, GeoIP, and GeoSite in Sing-box
func TestSingbox_Routing_RuleSets_GeoIP_GeoSite(t *testing.T) {
	node := &ast.ServerProfile{
		Protocol:  ast.ProtoVLESS,
		Address:   "198.51.100.1",
		Port:      443,
		UUID:      "b9f3857a-ce20-4e1e-b5e0-6f3d141fa2b2",
		Transport: "tcp",
		Security:  "reality",
		PublicKey: "1pxvjj6jjhkkN40PM83ViQTJeC9VMDVe7oceMZuWNQY",
		SNI:       "www.microsoft.com",
		Flow:      "xtls-rprx-vision",
		Name:      "VLESS-Proxy-Node",
	}

	engine := routing.NewEngine()
	policy := routing.DefaultSmartPolicy()

	spec := &ast.ConfigSpec{
		TargetCore: ast.CoreSingBox,
		LogLevel:   "warn",
		ClientInbound: &ast.ClientInboundSpec{
			Mode:      ast.InboundModeSystemProxy,
			SocksPort: 10818,
			HTTPPort:  10819,
		},
		ServerNode: node,
		Routing:    engine.CompilePolicy(policy),
	}

	res, err := builder.BuildClientConfig(spec)
	if err != nil {
		t.Fatalf("BuildClientConfig failed: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(res.ConfigJSON), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	routingMap, ok := parsed["route"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected route object in sing-box config: %v", parsed)
	}

	rules, ok := routingMap["rules"].([]interface{})
	if !ok || len(rules) == 0 {
		t.Fatalf("expected routing rules, got: %v", routingMap["rules"])
	}

	runSingboxSyntaxCheck(t, "Smart Routing Rules in Sing-box", res.ConfigJSON)
	t.Logf("✅ Sing-box Smart Routing Engine verified")
}

// 2. DNS Engine with DoH, Direct Resolver, and Rules in Sing-box
func TestSingbox_DNS_Engine_DoH_And_Rules(t *testing.T) {
	node := &ast.ServerProfile{
		Protocol:  ast.ProtoVLESS,
		Address:   "198.51.100.1",
		Port:      443,
		UUID:      "b9f3857a-ce20-4e1e-b5e0-6f3d141fa2b2",
		Transport: "tcp",
		Security:  "reality",
		PublicKey: "1pxvjj6jjhkkN40PM83ViQTJeC9VMDVe7oceMZuWNQY",
		SNI:       "www.apple.com",
		Flow:      "xtls-rprx-vision",
		Name:      "VLESS-DNS-Node",
	}

	spec := buildClientTestSpec(node)
	spec.DNS = &ast.DNSSpec{
		RemoteServer: "https://1.1.1.1/dns-query",
		DirectServer: "8.8.8.8",
		Strategy:     "ipv4_only",
	}

	res, err := builder.BuildClientConfig(spec)
	if err != nil {
		t.Fatalf("BuildClientConfig failed: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(res.ConfigJSON), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	dnsMap, ok := parsed["dns"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected dns object in config: %v", parsed)
	}

	servers, ok := dnsMap["servers"].([]interface{})
	if !ok || len(servers) < 2 {
		t.Fatalf("expected at least 2 dns servers in sing-box config, got: %v", dnsMap["servers"])
	}

	runSingboxSyntaxCheck(t, "DNS Engine DoH & Rules in Sing-box", res.ConfigJSON)
	t.Logf("✅ Sing-box DNS Engine verified")
}

// 3. Inbounds TUN Mode (Desktop / Mobile) & Mixed Port in Sing-box
func TestSingbox_Inbounds_TUN_And_Mixed(t *testing.T) {
	node := &ast.ServerProfile{
		Protocol:  ast.ProtoVLESS,
		Address:   "198.51.100.1",
		Port:      443,
		UUID:      "b9f3857a-ce20-4e1e-b5e0-6f3d141fa2b2",
		Transport: "tcp",
		Security:  "reality",
		PublicKey: "1pxvjj6jjhkkN40PM83ViQTJeC9VMDVe7oceMZuWNQY",
		SNI:       "www.google.com",
		Flow:      "xtls-rprx-vision",
		Name:      "VLESS-TUN-Node",
	}

	spec := buildClientTestSpec(node)
	spec.ClientInbound.Mode = ast.InboundModeDesktopTun
	spec.ClientInbound.TunInterfaceName = "Sentinel-Tun"
	spec.ClientInbound.AutoRoute = true
	spec.ClientInbound.StrictRoute = true
	spec.ClientInbound.TunStack = "gvisor"
	spec.ClientInbound.MTU = 9000

	res, err := builder.BuildClientConfig(spec)
	if err != nil {
		t.Fatalf("BuildClientConfig failed: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(res.ConfigJSON), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	inbounds := parsed["inbounds"].([]interface{})
	hasTun := false
	for _, in := range inbounds {
		inMap := in.(map[string]interface{})
		if inMap["type"] == "tun" {
			hasTun = true
			if inMap["interface_name"] != "Sentinel-Tun" {
				t.Fatalf("expected interface_name Sentinel-Tun, got %v", inMap["interface_name"])
			}
			break
		}
	}
	if !hasTun {
		t.Fatalf("expected tun inbound in config: %v", inbounds)
	}

	runSingboxSyntaxCheck(t, "Inbound TUN Mode in Sing-box", res.ConfigJSON)
	t.Logf("✅ Sing-box TUN & Mixed Inbounds verified")
}

// 4. Clash API & Experimental Controller in Sing-box
func TestSingbox_ClashAPI_Controller(t *testing.T) {
	node := &ast.ServerProfile{
		Protocol:  ast.ProtoVLESS,
		Address:   "198.51.100.1",
		Port:      443,
		UUID:      "b9f3857a-ce20-4e1e-b5e0-6f3d141fa2b2",
		Transport: "tcp",
		Security:  "reality",
		PublicKey: "1pxvjj6jjhkkN40PM83ViQTJeC9VMDVe7oceMZuWNQY",
		SNI:       "www.cloudflare.com",
		Flow:      "xtls-rprx-vision",
		Name:      "VLESS-Clash-Node",
	}

	spec := buildClientTestSpec(node)
	spec.ClashAPIAddress = "127.0.0.1:9090"

	res, err := builder.BuildClientConfig(spec)
	if err != nil {
		t.Fatalf("BuildClientConfig failed: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(res.ConfigJSON), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	exp, ok := parsed["experimental"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected experimental block in config: %v", parsed)
	}

	clashAPI, ok := exp["clash_api"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected clash_api in experimental block: %v", exp)
	}

	if clashAPI["external_controller"] != "127.0.0.1:9090" {
		t.Fatalf("expected external_controller 127.0.0.1:9090, got: %v", clashAPI["external_controller"])
	}

	runSingboxSyntaxCheck(t, "Clash API Controller in Sing-box", res.ConfigJSON)
	t.Logf("✅ Sing-box Clash API & Experimental Controller verified")
}
