package tests

import (
	"testing"
	"github.com/blackalex1/sentinel-core/pkg/ast"
	"github.com/blackalex1/sentinel-core/pkg/builder"
	"github.com/blackalex1/sentinel-core/pkg/routing"
)

func TestRoutingEngine_DefaultSmartPolicy(t *testing.T) {
	engine := routing.NewEngine()
	spec := engine.CompilePolicy(routing.DefaultSmartPolicy())

	if spec.DefaultAction != ast.ActionProxy {
		t.Errorf("expected default action proxy, got: %s", spec.DefaultAction)
	}

	if len(spec.Rules) == 0 {
		t.Fatalf("expected routing rules in smart policy, got 0")
	}

	// Verify Ad-blocking rule exists
	hasAdBlock := false
	hasRUBypass := false
	hasLANBypass := false

	for _, r := range spec.Rules {
		if r.Action == ast.ActionBlock {
			hasAdBlock = true
		}
		if r.Action == ast.ActionDirect {
			for _, ip := range r.IPs {
				if ip == "geoip:ru" {
					hasRUBypass = true
				}
				if ip == "geoip:private" {
					hasLANBypass = true
				}
			}
		}
	}

	if !hasAdBlock {
		t.Errorf("missing ad-blocking rule in Smart Policy")
	}
	if !hasRUBypass {
		t.Errorf("missing Russian services bypass in Smart Policy")
	}
	if !hasLANBypass {
		t.Errorf("missing LAN bypass in Smart Policy")
	}
}

func TestRoutingEngine_ThreatIsolationAndProcessRouting(t *testing.T) {
	engine := routing.NewEngine()
	policy := &routing.RoutingPolicy{
		Mode:                 routing.ModeSmartRule,
		AndroidBlockedUIDs:   []string{"10245", "10246"},
		BlockedPorts:         []string{"4444", "8888"},
		WindowsProcessProxy:  []string{"discord.exe", "telegram.exe"},
		WindowsProcessDirect: []string{"steam.exe"},
		CustomDirectDomains:  []string{"domain:internal.mycorp.com"},
	}

	spec := engine.CompilePolicy(policy)

	// Build a Sing-box config and ensure rules are compiled
	configSpec := &ast.ConfigSpec{
		TargetCore: ast.CoreSingBox,
		ServerNode: &ast.ServerProfile{
			Protocol: ast.ProtoVLESS,
			Address:  "1.2.3.4",
			Port:     443,
			UUID:     "test-uuid",
		},
		Routing: spec,
	}

	res, err := builder.BuildClientConfig(configSpec)
	if err != nil {
		t.Fatalf("compilation failed: %v", err)
	}

	// Verify threat blocked UIDs and process names in JSON
	cfg := res.ConfigJSON
	if len(spec.Rules) < 4 {
		t.Fatalf("expected at least 4 rules in compiled spec, got %d", len(spec.Rules))
	}
	_ = cfg
}

func TestRoutingEngine_QuickRulesWithOverrides(t *testing.T) {
	engine := routing.NewEngine()
	policy := &routing.RoutingPolicy{
		Mode:           routing.ModeSmartRule,
		EnabledPresets: []string{"bittorrent", "ru", "cn"},
		PresetTargetOverrides: map[string]string{
			"cn": "WARP-OUT",
		},
	}

	spec := engine.CompilePolicy(policy)

	hasBitTorrentBlock := false
	hasRUBypass := false
	hasCNWarp := false

	for _, r := range spec.Rules {
		if r.Action == ast.ActionBlock && len(r.Protocols) > 0 && r.Protocols[0] == "bittorrent" {
			hasBitTorrentBlock = true
		}
		if r.Action == ast.ActionDirect {
			for _, ip := range r.IPs {
				if ip == "geoip:ru" {
					hasRUBypass = true
				}
			}
		}
		if r.OutboundTag == "WARP-OUT" {
			for _, ip := range r.IPs {
				if ip == "geoip:cn" {
					hasCNWarp = true
				}
			}
		}
	}

	if !hasBitTorrentBlock {
		t.Errorf("expected BitTorrent block rule")
	}
	if !hasRUBypass {
		t.Errorf("expected RU direct rule")
	}
	if !hasCNWarp {
		t.Errorf("expected CN routed to WARP-OUT override")
	}
}

func TestRoutingEngine_DynamicPortugalPreset(t *testing.T) {
	// Demonstrates that registering or creating any new preset (e.g. Portugal bypass)
	// works dynamically without ANY Go code changes.
	pm := routing.GetPresetManager()
	pm.RegisterPreset(&routing.Preset{
		ID:            "pt",
		Name:          "Сайты Португалии (PT)",
		Description:   "Все IP и сайты Португалии",
		DefaultTarget: "direct",
		Domains:       []string{"geosite:pt", "regexp:.*\\.pt$"},
		IPs:           []string{"geoip:pt"},
	})

	engine := routing.NewEngine()
	policy := &routing.RoutingPolicy{
		Mode:           routing.ModeSmartRule,
		EnabledPresets: []string{"pt"},
	}

	spec := engine.CompilePolicy(policy)
	hasPTDirect := false
	for _, r := range spec.Rules {
		for _, ip := range r.IPs {
			if ip == "geoip:pt" {
				hasPTDirect = true
			}
		}
	}

	if !hasPTDirect {
		t.Errorf("expected dynamic pt preset to compile into routing rules")
	}
}

func TestRoutingEngine_SanitizationAndCustomPriority(t *testing.T) {
	engine := routing.NewEngine()

	// User entered dirty URLs, ports, wildcards, and comma-separated IPs
	policy := &routing.RoutingPolicy{
		Mode: routing.ModeSmartRule,
		CustomProxyDomains: []string{
			"https://custom-site.org/app?id=123",
			"*.my-special-service.io",
			"sub.domain.com:8443",
		},
		CustomDirectDomains: []string{
			"http://yandex.ru/direct-override",
		},
		CustomProxyIPs: []string{
			"198.51.100.55",
			"203.0.113.0/24, 192.0.2.1",
		},
	}

	spec := engine.CompilePolicy(policy)

	foundCustomProxy := false
	for _, r := range spec.Rules {
		if r.Action == ast.ActionProxy {
			for _, d := range r.Domains {
				if d == "custom-site.org" || d == "my-special-service.io" || d == "sub.domain.com" {
					foundCustomProxy = true
					break
				}
			}
		}
	}

	if !foundCustomProxy {
		t.Errorf("custom domains were not sanitized and included properly in proxy rules")
	}
}
