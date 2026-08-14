package tests

import (
	"testing"
	"github.com/blackalex1/sentinel-core/pkg/ast"
	"github.com/blackalex1/sentinel-core/pkg/routing"
)

func TestPresetManager_BuiltinAndCompile(t *testing.T) {
	pm := routing.GetPresetManager()

	presets := pm.ListPresets()
	if len(presets) < 6 {
		t.Fatalf("expected at least 6 builtin presets, got %d", len(presets))
	}

	// 1. Compile ru preset
	specRU, err := pm.CompilePreset("ru")
	if err != nil {
		t.Fatalf("failed to compile ru preset: %v", err)
	}

	if specRU.DefaultAction != ast.ActionProxy {
		t.Errorf("expected default action proxy, got: %s", specRU.DefaultAction)
	}
	if len(specRU.Rules) != 2 { // Private LAN (rule 1) + Russian Matchers (rule 2)
		t.Errorf("expected 2 rules in ru preset compilation, got %d", len(specRU.Rules))
	}

	// 2. Compile bittorrent preset
	specTorrent, err := pm.CompilePreset("bittorrent")
	if err != nil {
		t.Fatalf("failed to compile bittorrent preset: %v", err)
	}
	if len(specTorrent.Rules) != 2 {
		t.Errorf("expected 2 rules in bittorrent preset, got %d", len(specTorrent.Rules))
	}

	// 3. Export to JSON
	jsonStr, err := pm.ExportPresetJSON("ru")
	if err != nil || jsonStr == "" {
		t.Fatalf("failed to export preset to JSON: %v", err)
	}
}

func TestPresetManager_LoadDirectory(t *testing.T) {
	pm := routing.GetPresetManager()

	loaded, err := pm.LoadPresetsDirectory("../presets")
	if err != nil {
		t.Fatalf("failed to load presets directory: %v", err)
	}

	if len(loaded) < 6 {
		t.Errorf("expected at least 6 presets loaded from directory, got %d", len(loaded))
	}
}

func TestPresetManager_RegexCompilation(t *testing.T) {
	pm := routing.GetPresetManager()
	spec, err := pm.CompilePreset("ru")
	if err != nil {
		t.Fatalf("failed to compile ru preset: %v", err)
	}

	hasRegexRU := false
	hasGeositeRU := false
	hasGeoIPRU := false

	for _, r := range spec.Rules {
		for _, d := range r.Domains {
			if d == "regexp:.*\\.ru$" {
				hasRegexRU = true
			}
			if d == "geosite:ru" {
				hasGeositeRU = true
			}
		}
		for _, ip := range r.IPs {
			if ip == "geoip:ru" {
				hasGeoIPRU = true
			}
		}
	}

	if !hasRegexRU {
		t.Errorf("expected regexp:.*\\.ru$ in compiled ru rules")
	}
	if !hasGeositeRU {
		t.Errorf("expected geosite:ru in compiled ru rules")
	}
	if !hasGeoIPRU {
		t.Errorf("expected geoip:ru in compiled ru rules")
	}
}

func TestPresetManager_QuickRulesDashboardMatching(t *testing.T) {
	// Replicate the exact UI state from the dashboard screenshot:
	// 1. BitTorrent (bittorrent): ENABLED -> BLOCKED
	// 2. Russia (ru): ENABLED -> DIRECT
	// 3. IP Checkers (ip_checkers): ENABLED -> DIRECT
	enabledPresetIDs := []string{"bittorrent", "ru", "ip_checkers"}

	targets := map[string]string{
		"bittorrent":  "BLOCKED",
		"ru":          "DIRECT",
		"ip_checkers": "DIRECT",
	}

	table := routing.BuildTableFromPresets(enabledPresetIDs, targets)
	spec := table.CompileToAST()

	if len(spec.Rules) == 0 {
		t.Fatalf("expected compiled rules from quick dashboard table, got 0")
	}

	hasLANBypass := false
	hasTorrentBlock := false
	hasRUDirect := false
	hasIPCheckerDirect := false

	for _, r := range spec.Rules {
		if r.Action == ast.ActionDirect {
			for _, ip := range r.IPs {
				if ip == "geoip:private" {
					hasLANBypass = true
				}
				if ip == "geoip:ru" {
					hasRUDirect = true
				}
			}
			for _, d := range r.Domains {
				if d == "domain:ipify.org" {
					hasIPCheckerDirect = true
				}
			}
		}
		if r.Action == ast.ActionBlock && len(r.Protocols) > 0 && r.Protocols[0] == "bittorrent" {
			hasTorrentBlock = true
		}
	}

	if !hasLANBypass {
		t.Errorf("expected Private LAN direct rule in compiled AST")
	}
	if !hasTorrentBlock {
		t.Errorf("expected BitTorrent block rule in compiled AST")
	}
	if !hasRUDirect {
		t.Errorf("expected RU direct rule in compiled AST")
	}
	if !hasIPCheckerDirect {
		t.Errorf("expected IP Checkers direct rule in compiled AST")
	}
}
