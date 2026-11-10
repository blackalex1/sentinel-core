package tests

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/blackalex1/sentinel-core/pkg/ast"
	"github.com/blackalex1/sentinel-core/pkg/builder"
	"github.com/blackalex1/sentinel-core/pkg/compiler/singbox"
	"github.com/blackalex1/sentinel-core/pkg/compiler/xray"
)

// 1. Sing-box: 2-Hop Chain (Entry = Hysteria 2, Exit = VLESS)
func TestE2E_SingBox_2HopChain_Hy2_To_VLESS(t *testing.T) {
	c := singbox.NewCompiler()
	spec := &ast.ConfigSpec{
		TargetCore: ast.CoreSingBox,
		ChainNodes: []*ast.ServerProfile{
			{
				Name:        "EntryHy2",
				Protocol:    ast.ProtoHysteria2,
				Address:     "hy2.entry.node",
				Port:        443,
				Password:    "secret-hy2-pass",
				PortHopping: "20000-30000",
			},
			{
				Name:     "ExitVLESS",
				Protocol: ast.ProtoVLESS,
				Address:  "vless.exit.node",
				Port:     443,
				UUID:     "11111111-2222-3333-4444-555555555555",
			},
		},
		Routing: &ast.RoutingSpec{
			DefaultAction: ast.ActionProxy,
			Rules: []ast.RoutingRule{
				{
					Action:  ast.ActionProxy,
					Domains: []string{"domain:openai.com"},
				},
				{
					Action:  ast.ActionDirect,
					Domains: []string{"geosite:ru"},
				},
			},
		},
	}

	cfg, _, err := c.Compile(spec)
	if err != nil {
		t.Fatalf("failed to compile Sing-box Hy2 -> VLESS chain: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(cfg), &parsed); err != nil {
		t.Fatalf("compiled config is not valid JSON: %v\n%s", err, cfg)
	}

	// Verify outbounds
	outbounds, ok := parsed["outbounds"].([]interface{})
	if !ok || len(outbounds) < 2 {
		t.Fatalf("expected at least 2 outbounds, got: %v", len(outbounds))
	}

	var ob1, ob2 map[string]interface{}
	for _, o := range outbounds {
		oMap, _ := o.(map[string]interface{})
		tag, _ := oMap["tag"].(string)
		if strings.Contains(tag, "EntryHy2") {
			ob1 = oMap
		} else if strings.Contains(tag, "ExitVLESS") {
			ob2 = oMap
		}
	}

	if ob1 == nil {
		t.Fatalf("entry node EntryHy2 not found in outbounds:\n%s", cfg)
	}
	if ob2 == nil {
		t.Fatalf("exit node ExitVLESS not found in outbounds:\n%s", cfg)
	}

	// Entry node must NOT have detour (connects directly to entry IP)
	if detour, exists := ob1["detour"]; exists && detour != "" {
		t.Errorf("entry node should not have detour, got: %v", detour)
	}

	// Exit node must detour through Entry node
	ob1Tag := ob1["tag"].(string)
	if ob2["detour"] != ob1Tag {
		t.Errorf("exit node detour must be %s, got: %v", ob1Tag, ob2["detour"])
	}

	// Route final must point to Exit node
	route, ok := parsed["route"].(map[string]interface{})
	if !ok {
		t.Fatalf("route section missing in config")
	}
	ob2Tag := ob2["tag"].(string)
	if route["final"] != ob2Tag {
		t.Errorf("expected route.final to be %s, got: %v", ob2Tag, route["final"])
	}

	// Proxy rule for openai.com must route to Exit node
	rules, _ := route["rules"].([]interface{})
	var proxyRuleTarget string
	for _, r := range rules {
		rMap, _ := r.(map[string]interface{})
		if dList, ok := rMap["domain"].([]interface{}); ok {
			for _, d := range dList {
				if d == "openai.com" || d == "domain:openai.com" {
					proxyRuleTarget, _ = rMap["outbound"].(string)
				}
			}
		}
	}
	if proxyRuleTarget != ob2Tag {
		t.Errorf("expected openai.com rule to target %s, got: %s", ob2Tag, proxyRuleTarget)
	}
}

// 2. Sing-box: 3-Hop Cascade Chain (Entry VLESS Reality -> Relay Trojan -> Exit Shadowsocks)
func TestE2E_SingBox_3HopChain_Cascade(t *testing.T) {
	c := singbox.NewCompiler()
	spec := &ast.ConfigSpec{
		TargetCore: ast.CoreSingBox,
		ChainNodes: []*ast.ServerProfile{
			{
				Name:      "Hop1Reality",
				Protocol:  ast.ProtoVLESS,
				Address:   "reality.entry.com",
				Port:      443,
				UUID:      "a0000000-0000-0000-0000-000000000001",
				Security:  ast.SecurityReality,
				PublicKey: "realpubkey123",
				ShortID:   "abcd",
			},
			{
				Name:     "Hop2Trojan",
				Protocol: ast.ProtoTrojan,
				Address:  "trojan.relay.com",
				Port:     443,
				Password: "trojan-pass-456",
			},
			{
				Name:     "Hop3Shadowsocks",
				Protocol: ast.ProtoShadowsocks,
				Address:  "ss.exit.com",
				Port:     8388,
				Password: "ss-pass-789",
				Cipher:   "aes-128-gcm",
			},
		},
		Routing: &ast.RoutingSpec{
			DefaultAction: ast.ActionProxy,
		},
	}

	cfg, _, err := c.Compile(spec)
	if err != nil {
		t.Fatalf("failed to compile Sing-box 3-hop cascade: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(cfg), &parsed); err != nil {
		t.Fatalf("compiled config is not valid JSON: %v", err)
	}

	outbounds := parsed["outbounds"].([]interface{})
	var h1, h2, h3 map[string]interface{}
	for _, o := range outbounds {
		oMap := o.(map[string]interface{})
		tag, _ := oMap["tag"].(string)
		if strings.Contains(tag, "Hop1Reality") {
			h1 = oMap
		} else if strings.Contains(tag, "Hop2Trojan") {
			h2 = oMap
		} else if strings.Contains(tag, "Hop3Shadowsocks") {
			h3 = oMap
		}
	}

	if h1 == nil || h2 == nil || h3 == nil {
		t.Fatalf("one or more chain hops missing from outbounds:\n%s", cfg)
	}

	// Hop 1 has no detour
	if d, ok := h1["detour"]; ok && d != "" {
		t.Errorf("hop 1 should have no detour, got: %v", d)
	}
	// Hop 2 detours to Hop 1
	if h2["detour"] != h1["tag"] {
		t.Errorf("hop 2 detour should be %v, got: %v", h1["tag"], h2["detour"])
	}
	// Hop 3 detours to Hop 2
	if h3["detour"] != h2["tag"] {
		t.Errorf("hop 3 detour should be %v, got: %v", h2["tag"], h3["detour"])
	}

	// Final route must be Hop 3
	route := parsed["route"].(map[string]interface{})
	if route["final"] != h3["tag"] {
		t.Errorf("final route should be %v, got: %v", h3["tag"], route["final"])
	}
}

// 3. Builder Auto-Switch: Hysteria 2 requested with ChainNodes -> Must auto-switch to Sing-box
func TestE2E_BuildClientConfig_AutoSwitch_Hysteria2_To_SingBox_OnChain(t *testing.T) {
	spec := &ast.ConfigSpec{
		TargetCore: ast.CoreHysteria2, // User or UI asked for Hysteria 2
		ChainNodes: []*ast.ServerProfile{
			{
				Name:     "EntryHy2",
				Protocol: ast.ProtoHysteria2,
				Address:  "hy2.fast.com",
				Port:     443,
				Password: "fast-hy2-pass",
			},
			{
				Name:     "ExitTrojan",
				Protocol: ast.ProtoTrojan,
				Address:  "trojan.clean.com",
				Port:     443,
				Password: "clean-trojan-pass",
			},
		},
	}

	res, err := builder.BuildClientConfig(spec)
	if err != nil {
		t.Fatalf("failed to build client config: %v", err)
	}

	// Must auto-switch to SingBox because native Hy2 client does not support multi-hop chaining
	if res.TargetCore != ast.CoreSingBox {
		t.Errorf("expected TargetCore to be auto-switched to SingBox, got: %s", res.TargetCore)
	}

	// Warning must indicate auto switch
	hasSwitchWarning := false
	for _, w := range res.Warnings {
		if w.Action == "AUTO_SWITCH_TO_SINGBOX" {
			hasSwitchWarning = true
			break
		}
	}
	if !hasSwitchWarning {
		t.Errorf("expected AUTO_SWITCH_TO_SINGBOX warning in build result")
	}

	// Verify the compiled Sing-box JSON has proper detour
	if !strings.Contains(res.ConfigJSON, `"type": "hysteria2"`) {
		t.Errorf("expected hysteria2 outbound in compiled JSON, got:\n%s", res.ConfigJSON)
	}
	if !strings.Contains(res.ConfigJSON, `"detour": "chain-1-EntryHy2"`) {
		t.Errorf("expected detour: chain-1-EntryHy2 in compiled JSON, got:\n%s", res.ConfigJSON)
	}
}

// 4. Xray: 2-Hop Chain with VLESS Reality + Vision on Entry and stripping on Inner Hops
func TestE2E_Xray_2HopChain_Reality_With_Inner_Vision_Stripped(t *testing.T) {
	c := xray.NewCompiler()
	spec := &ast.ConfigSpec{
		TargetCore: ast.CoreXray,
		ChainNodes: []*ast.ServerProfile{
			{
				Name:        "EntryReality",
				Protocol:    ast.ProtoVLESS,
				Address:     "198.51.100.1",
				Port:        443,
				UUID:        "e0000000-0000-0000-0000-000000000001",
				Flow:        "xtls-rprx-vision",
				Security:    ast.SecurityReality,
				PublicKey:   "entryrealitypubkey",
				ShortID:     "1234",
			},
			{
				Name:        "ExitReality",
				Protocol:    ast.ProtoVLESS,
				Address:     "203.0.113.5",
				Port:        443,
				UUID:        "e0000000-0000-0000-0000-000000000002",
				Flow:        "xtls-rprx-vision", // Should be stripped on inner hop!
				Security:    ast.SecurityReality,
				PublicKey:   "exitrealitypubkey",
				ShortID:     "5678",
			},
		},
		Routing: &ast.RoutingSpec{
			DefaultAction: ast.ActionProxy,
			Rules: []ast.RoutingRule{
				{
					Action:  ast.ActionProxy,
					Domains: []string{"domain:twitter.com"},
				},
			},
		},
	}

	cfg, _, err := c.Compile(spec)
	if err != nil {
		t.Fatalf("failed to compile multi-hop Xray config: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(cfg), &parsed); err != nil {
		t.Fatalf("compiled Xray config is not valid JSON: %v", err)
	}

	outbounds := parsed["outbounds"].([]interface{})
	var entryOb, exitOb map[string]interface{}
	for _, o := range outbounds {
		oMap := o.(map[string]interface{})
		tag, _ := oMap["tag"].(string)
		if strings.Contains(tag, "EntryReality") {
			entryOb = oMap
		} else if strings.Contains(tag, "ExitReality") {
			exitOb = oMap
		}
	}

	if entryOb == nil || exitOb == nil {
		t.Fatalf("entry or exit outbound not found in Xray config:\n%s", cfg)
	}

	// 1. Entry node must KEEP xtls-rprx-vision
	entrySettings := entryOb["settings"].(map[string]interface{})
	entryVnext := entrySettings["vnext"].([]interface{})[0].(map[string]interface{})
	entryUsers := entryVnext["users"].([]interface{})[0].(map[string]interface{})
	if entryUsers["flow"] != "xtls-rprx-vision" {
		t.Errorf("entry node must keep flow xtls-rprx-vision, got: %v", entryUsers["flow"])
	}

	// 2. Exit node must have xtls-rprx-vision STRIPPED (must be empty)
	exitSettings := exitOb["settings"].(map[string]interface{})
	exitVnext := exitSettings["vnext"].([]interface{})[0].(map[string]interface{})
	exitUsers := exitVnext["users"].([]interface{})[0].(map[string]interface{})
	if flow, ok := exitUsers["flow"]; ok && flow != "" {
		t.Errorf("exit node in proxy chain must have flow stripped, got: %v", flow)
	}

	// 3. Exit node must have streamSettings.sockopt.dialerProxy pointing to Entry node
	exitStreamSettings, ok := exitOb["streamSettings"].(map[string]interface{})
	if !ok {
		t.Fatalf("exit node missing streamSettings in Xray config:\n%s", cfg)
	}
	exitSockopt, ok := exitStreamSettings["sockopt"].(map[string]interface{})
	if !ok {
		t.Fatalf("exit node missing streamSettings.sockopt in Xray config:\n%s", cfg)
	}
	if exitSockopt["dialerProxy"] != entryOb["tag"] {
		t.Errorf("exit node sockopt.dialerProxy must be %v, got: %v", entryOb["tag"], exitSockopt["dialerProxy"])
	}

	// 4. Default outbound (outbounds[0]) must be the Exit node
	firstOb := outbounds[0].(map[string]interface{})
	if firstOb["tag"] != exitOb["tag"] {
		t.Errorf("first outbound in Xray config must be exit node %v, got: %v", exitOb["tag"], firstOb["tag"])
	}

	// 5. Direct routing rule must ONLY cover entry IP (198.51.100.1), NEVER exit IP (203.0.113.5)
	routing := parsed["routing"].(map[string]interface{})
	routingRules := routing["rules"].([]interface{})
	hasEntryDirect := false
	hasExitDirect := false

	for _, r := range routingRules {
		rMap := r.(map[string]interface{})
		tag, _ := rMap["outboundTag"].(string)
		if tag == "direct" {
			if ips, ok := rMap["ip"].([]interface{}); ok {
				for _, ip := range ips {
					if ip == "198.51.100.1" {
						hasEntryDirect = true
					}
					if ip == "203.0.113.5" {
						hasExitDirect = true
					}
				}
			}
		}
	}

	if !hasEntryDirect {
		t.Errorf("expected direct rule for entry IP 198.51.100.1 to prevent loopback")
	}
	if hasExitDirect {
		t.Errorf("exit IP 203.0.113.5 must NEVER have direct rule, it must tunnel through entry node!")
	}
}

// 5. Backward Compatibility: Single ServerNode configuration produces standard single-hop config
func TestE2E_BackwardCompatibility_SingleNode(t *testing.T) {
	singleNode := &ast.ServerProfile{
		Name:     "SingleNode",
		Protocol: ast.ProtoVLESS,
		Address:  "single.server.com",
		Port:     443,
		UUID:     "99999999-9999-9999-9999-999999999999",
	}

	// A. Sing-box
	sbSpec := &ast.ConfigSpec{
		TargetCore: ast.CoreSingBox,
		ServerNode: singleNode,
		ClientInbound: &ast.ClientInboundSpec{
			SocksPort: 10808,
		},
	}
	sbCfg, _, err := singbox.NewCompiler().Compile(sbSpec)
	if err != nil {
		t.Fatalf("singbox single node compile failed: %v", err)
	}
	if strings.Contains(sbCfg, "chain-hop-") {
		t.Errorf("singbox single node should not have chain-hop- tags")
	}
	var sbObj map[string]interface{}
	if err := json.Unmarshal([]byte(sbCfg), &sbObj); err != nil {
		t.Fatalf("failed to unmarshal singbox single node: %v", err)
	}
	if outbounds, ok := sbObj["outbounds"].([]interface{}); ok && len(outbounds) > 0 {
		firstOb := outbounds[0].(map[string]interface{})
		if _, hasDetour := firstOb["detour"]; hasDetour {
			t.Errorf("singbox single node primary outbound should not have detour: %v", firstOb)
		}
	}

	// B. Xray
	xraySpec := &ast.ConfigSpec{
		TargetCore: ast.CoreXray,
		ServerNode: singleNode,
		ClientInbound: &ast.ClientInboundSpec{
			SocksPort: 10808,
		},
	}
	xrayCfg, _, err := xray.NewCompiler().Compile(xraySpec)
	if err != nil {
		t.Fatalf("xray single node compile failed: %v", err)
	}
	if strings.Contains(xrayCfg, "chain-hop-") {
		t.Errorf("xray single node should not have chain-hop- tags")
	}
	if strings.Contains(xrayCfg, `"dialerProxy":`) {
		t.Errorf("xray single node should not have dialerProxy on primary outbound")
	}
}
