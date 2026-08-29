package xray_test

import (
	"encoding/json"
	"testing"

	"github.com/blackalex1/sentinel-core/pkg/ast"
	"github.com/blackalex1/sentinel-core/pkg/builder"
	"github.com/blackalex1/sentinel-core/pkg/routing"
)

// 1. Xray Smart Routing: GeoIP, GeoSite, Regexp, IPs, Domain Rules
func TestXray_Routing_SmartRules_GeoIP_GeoSite(t *testing.T) {
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
		Name:      "vless-out",
	}

	engine := routing.NewEngine()
	policy := routing.DefaultSmartPolicy()

	spec := &ast.ConfigSpec{
		TargetCore: ast.CoreXray,
		LogLevel:   "warning",
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

	routingMap, ok := parsed["routing"].(map[string]interface{})
	if !ok {
		t.Fatalf("routing section missing")
	}
	rules := routingMap["rules"].([]interface{})
	if len(rules) < 3 {
		t.Errorf("expected at least 3 routing rules, got %d", len(rules))
	}

	runXraySyntaxCheck(t, "Xray Smart Routing Rules", res.ConfigJSON)
	t.Logf("✅ Xray Smart Routing Rules passed live verification")
}

// 2. Xray Observatory + Balancer (leastPing / failover) with Multiple Outbounds
func TestXray_Observatory_And_Balancers_LeastPing(t *testing.T) {
	node1 := &ast.ServerProfile{
		Protocol:  ast.ProtoVLESS,
		Address:   "198.51.100.1",
		Port:      443,
		UUID:      "b9f3857a-ce20-4e1e-b5e0-6f3d141fa2b2",
		Transport: "tcp",
		Security:  "reality",
		PublicKey: "1pxvjj6jjhkkN40PM83ViQTJeC9VMDVe7oceMZuWNQY",
		SNI:       "www.apple.com",
		Flow:      "xtls-rprx-vision",
		Name:      "vless-primary",
	}

	node2 := &ast.ServerProfile{
		Protocol:  ast.ProtoTrojan,
		Address:   "198.51.100.2",
		Port:      443,
		Password:  "TrojanPassword123!",
		Security:  "tls",
		SNI:       "node2.trojan.org",
		Name:      "trojan-backup",
	}

	profiles := []*ast.ServerProfile{node1, node2}

	res, err := builder.BuildFailoverClientConfig(profiles, ast.CoreXray, 10818, 10819, "https://1.1.1.1/dns-query")
	if err != nil {
		t.Fatalf("BuildFailoverClientConfig failed for Xray: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(res.ConfigJSON), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	runXraySyntaxCheck(t, "Xray Failover & Balancer", res.ConfigJSON)
	t.Logf("✅ Xray Observatory & Balancers passed live verification")
}

// 3. Xray Inbounds with Full Sniffing & Transparent Proxying
func TestXray_Inbounds_Socks_HTTP_Sniffing(t *testing.T) {
	node := &ast.ServerProfile{
		Protocol: ast.ProtoShadowsocks,
		Address:  "198.51.100.70",
		Port:     8388,
		Cipher:   "aes-256-gcm",
		Password: "SecretPassword_123!",
		Name:     "ss-node",
	}

	spec := buildClientTestSpec(node)
	res, err := builder.BuildClientConfig(spec)
	if err != nil {
		t.Fatalf("BuildClientConfig failed: %v", err)
	}

	var parsed map[string]interface{}
	json.Unmarshal([]byte(res.ConfigJSON), &parsed)

	inbounds := parsed["inbounds"].([]interface{})
	if len(inbounds) < 2 {
		t.Fatalf("expected at least 2 inbounds, got %d", len(inbounds))
	}

	socksIn := inbounds[0].(map[string]interface{})
	sniffing := socksIn["sniffing"].(map[string]interface{})
	if sniffing["enabled"] != true {
		t.Errorf("expected sniffing enabled, got %v", sniffing["enabled"])
	}

	runXraySyntaxCheck(t, "Xray Inbounds Sniffing", res.ConfigJSON)
	t.Logf("✅ Xray Inbounds with Sniffing verified")
}
