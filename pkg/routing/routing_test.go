package routing

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blackalex1/sentinel-core/pkg/ast"
)

func TestSanitizeDomain_Comprehensive(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"", ""},
		{"   ", ""},
		{"geosite:category-ads-all", "geosite:category-ads-all"},
		{"regexp:.*\\.google\\.com", "regexp:.*\\.google\\.com"},
		{"regex:.*\\.ru", "regex:.*\\.ru"},
		{"keyword:tracker", "keyword:tracker"},
		{"domain:example.com", "domain:example.com"},
		{"full:api.example.com", "full:api.example.com"},
		{"https://sub.domain.com/path/to/resource?query=1", "sub.domain.com"},
		{"http://test.org:8080/index.html", "test.org"},
		{"example.com/some/path", "example.com"},
		{"api.server.net:8443", "api.server.net"},
		{"*.wildcard.org", "wildcard.org"},
		{".dotted.org", "dotted.org"},
		{"  UPPERCASE.COM  ", "uppercase.com"},
		{"[2001:db8::1]:8080", "[2001:db8::1]:8080"},
	}

	for _, tc := range tests {
		got := SanitizeDomain(tc.input)
		if got != tc.expected {
			t.Errorf("SanitizeDomain(%q) = %q, expected %q", tc.input, got, tc.expected)
		}
	}
}

func TestCleanDomainList_Comprehensive(t *testing.T) {
	input := []string{
		"google.com, https://youtube.com/watch?v=123",
		"*.twitter.com; instagram.com\nfacebook.com",
		"google.com", // duplicate
		"",
		"   ",
	}

	cleaned := CleanDomainList(input)
	expected := []string{"google.com", "youtube.com", "twitter.com", "instagram.com", "facebook.com"}

	if len(cleaned) != len(expected) {
		t.Fatalf("expected %d domains, got %d: %+v", len(expected), len(cleaned), cleaned)
	}

	for i, exp := range expected {
		if cleaned[i] != exp {
			t.Errorf("at index %d: expected %s, got %s", i, exp, cleaned[i])
		}
	}
}

func TestSanitizeIP_Comprehensive(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"", ""},
		{"   ", ""},
		{"geoip:ru", "geoip:ru"},
		{"geoip:private", "geoip:private"},
		{"ip:1.1.1.1", "1.1.1.1/32"},
		{"8.8.8.8", "8.8.8.8/32"},
		{"192.168.1.1:8080", "192.168.1.1/32"},
		{"10.0.0.0/8", "10.0.0.0/8"},
		{"172.16.0.0/12", "172.16.0.0/12"},
		{"2001:db8::1", "2001:db8::1/128"},
		{"2001:db8::/32", "2001:db8::/32"},
		{"invalid-ip-string", "invalid-ip-string"},
	}

	for _, tc := range tests {
		got := SanitizeIP(tc.input)
		if got != tc.expected {
			t.Errorf("SanitizeIP(%q) = %q, expected %q", tc.input, got, tc.expected)
		}
	}
}

func TestCleanIPList_Comprehensive(t *testing.T) {
	input := []string{
		"1.1.1.1, 8.8.8.8/32; 10.0.0.0/8\ngeoip:ru",
		"1.1.1.1", // duplicate
		"",
	}

	cleaned := CleanIPList(input)
	expected := []string{"1.1.1.1/32", "8.8.8.8/32", "10.0.0.0/8", "geoip:ru"}

	if len(cleaned) != len(expected) {
		t.Fatalf("expected %d IPs, got %d: %+v", len(expected), len(cleaned), cleaned)
	}

	for i, exp := range expected {
		if cleaned[i] != exp {
			t.Errorf("at index %d: expected %s, got %s", i, exp, cleaned[i])
		}
	}
}

func TestSanitizePort_Comprehensive(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"", ""},
		{"   ", ""},
		{"80", "80"},
		{"443", "443"},
		{"65535", "65535"},
		{"1", "1"},
		{"0", ""},
		{"-5", ""},
		{"70000", ""},
		{"not-a-port", ""},
		{"1000-2000", "1000-2000"},
		{"1000:2000", "1000-2000"},
		{"2000-1000", ""}, // start > end
		{"0-100", ""},     // start <= 0
		{"100-70000", ""}, // end > 65535
		{"abc-def", ""},
	}

	for _, tc := range tests {
		got := SanitizePort(tc.input)
		if got != tc.expected {
			t.Errorf("SanitizePort(%q) = %q, expected %q", tc.input, got, tc.expected)
		}
	}
}

func TestCleanPortList_Comprehensive(t *testing.T) {
	input := []string{
		"80, 443; 8080-8090\n53 853",
		"80",       // duplicate
		"invalid",  // bad
		"70000",    // out of bounds
		"",
	}

	cleaned := CleanPortList(input)
	expected := []string{"80", "443", "8080-8090", "53", "853"}

	if len(cleaned) != len(expected) {
		t.Fatalf("expected %d ports, got %d: %+v", len(expected), len(cleaned), cleaned)
	}

	for i, exp := range expected {
		if cleaned[i] != exp {
			t.Errorf("at index %d: expected %s, got %s", i, exp, cleaned[i])
		}
	}
}

func TestRoutingTable_Comprehensive(t *testing.T) {
	table := NewRoutingTable("")
	if table.DefaultTarget != "proxy" {
		t.Errorf("expected default target 'proxy', got %s", table.DefaultTarget)
	}

	tableDirect := NewRoutingTable("DIRECT")
	if tableDirect.DefaultTarget != "DIRECT" {
		t.Errorf("expected DIRECT target, got %s", tableDirect.DefaultTarget)
	}

	// Add rules with different priorities and targets
	table.AddRule(RoutingRuleRow{
		Order:        3,
		Name:         "Rule 3 - Custom Proxy",
		Enabled:      true,
		Target:       "proxy",
		Domains:      []string{"google.com"},
		IPs:          []string{"1.1.1.1"},
		Ports:        []string{"443"},
		Protocols:    []string{"tcp"},
		ProcessNames: []string{"chrome.exe"},
		PackageUIDs:  []string{"10001"},
		Inbounds:     []string{"tun-in"},
	})
	table.AddRule(RoutingRuleRow{
		Order:   1,
		Name:    "Rule 1 - Blocked",
		Enabled: true,
		Target:  "block",
		Domains: []string{"geosite:category-ads-all"},
	})
	table.AddRule(RoutingRuleRow{
		Order:   2,
		Name:    "Rule 2 - Direct",
		Enabled: true,
		Target:  "direct",
		IPs:     []string{"geoip:private"},
	})
	table.AddRule(RoutingRuleRow{
		Order:   4,
		Name:    "Rule 4 - Custom Outbound Tag",
		Enabled: true,
		Target:  "warp-out",
		Domains: []string{"cloudflare.com"},
	})
	table.AddRule(RoutingRuleRow{
		Order:   5,
		Name:    "Disabled Rule",
		Enabled: false,
		Target:  "direct",
	})
	table.AddRule(RoutingRuleRow{
		Order:   6,
		Name:    "Empty Target Rule",
		Enabled: true,
		Target:  "", // Defaults to direct
		Domains: []string{"empty-target.com"},
	})

	spec := table.CompileToAST()
	if len(spec.Rules) != 5 {
		t.Fatalf("expected 5 compiled AST rules (1 disabled skipped), got %d", len(spec.Rules))
	}

	// Verify order sorting
	if spec.Rules[0].Action != ast.ActionBlock || spec.Rules[0].OutboundTag != "block" {
		t.Errorf("rule 0 mismatch: %+v", spec.Rules[0])
	}
	if spec.Rules[1].Action != ast.ActionDirect || spec.Rules[1].OutboundTag != "direct" {
		t.Errorf("rule 1 mismatch: %+v", spec.Rules[1])
	}
	if spec.Rules[2].Action != ast.ActionProxy || spec.Rules[2].OutboundTag != "proxy" {
		t.Errorf("rule 2 mismatch: %+v", spec.Rules[2])
	}
	if spec.Rules[3].Action != ast.ActionProxy || spec.Rules[3].OutboundTag != "warp-out" {
		t.Errorf("rule 3 mismatch: %+v", spec.Rules[3])
	}
	if spec.Rules[4].Action != ast.ActionDirect || spec.Rules[4].OutboundTag != "direct" {
		t.Errorf("rule 4 mismatch: %+v", spec.Rules[4])
	}

	// Verify JSON Export and Import
	jsonStr, err := table.ExportJSON()
	if err != nil || jsonStr == "" {
		t.Fatalf("failed to export routing table to JSON: %v", err)
	}

	imported, err := ImportRoutingTableJSON(jsonStr)
	if err != nil {
		t.Fatalf("failed to import routing table JSON: %v", err)
	}
	if len(imported.Rules) != len(table.Rules) {
		t.Errorf("imported rules length mismatch: %d vs %d", len(imported.Rules), len(table.Rules))
	}

	// Import error test
	_, err = ImportRoutingTableJSON("invalid json syntax {{{")
	if err == nil {
		t.Errorf("expected error on invalid JSON import")
	}
}

func TestPresetManager_Comprehensive(t *testing.T) {
	pm := GetPresetManager()
	if pm == nil {
		t.Fatalf("expected non-nil PresetManager singleton")
	}

	presets := pm.ListPresets()
	if len(presets) == 0 {
		t.Fatalf("expected built-in presets to be loaded")
	}

	// Test aliases
	aliasTests := map[string]string{
		"bypass_ru":      "ru",
		"block_ru":       "ru",
		"smart_ru":       "ru",
		"torrent_shield": "bittorrent",
		"block_torrent":  "bittorrent",
		"block_ads":      "ads",
		"block_cn":       "cn",
		"block_us":       "us",
	}

	for alias, expectedID := range aliasTests {
		p, err := pm.GetPreset(alias)
		if err != nil {
			t.Errorf("failed to get preset for alias '%s': %v", alias, err)
		} else if p.ID != expectedID {
			t.Errorf("alias '%s' returned preset ID '%s', expected '%s'", alias, p.ID, expectedID)
		}
	}

	// Test unknown preset
	_, err := pm.GetPreset("non_existent_preset_xyz")
	if err == nil {
		t.Errorf("expected error for non existent preset")
	}

	// Test CompilePreset
	spec, err := pm.CompilePreset("ads")
	if err != nil || spec == nil || len(spec.Rules) == 0 {
		t.Fatalf("failed to compile ads preset: %v", err)
	}

	_, err = pm.CompilePreset("non_existent_preset_xyz")
	if err == nil {
		t.Errorf("expected error when compiling non existent preset")
	}

	// Test ExportPresetJSON
	exportedJSON, err := pm.ExportPresetJSON("ru")
	if err != nil || exportedJSON == "" {
		t.Fatalf("failed to export preset to JSON: %v", err)
	}

	_, err = pm.ExportPresetJSON("non_existent_preset_xyz")
	if err == nil {
		t.Errorf("expected error when exporting non existent preset JSON")
	}

	// Test RegisterPreset with nil or empty
	pm.RegisterPreset(nil)
	pm.RegisterPreset(&Preset{ID: ""})
}

func TestPresetManager_FileAndDirectoryLoading(t *testing.T) {
	pm := GetPresetManager()
	tempDir := t.TempDir()

	// 1. Write a valid preset file
	customPreset := Preset{
		ID:            "custom_temp_preset",
		Name:          "Custom Temp Preset",
		Description:   "Temporary test preset",
		DefaultTarget: "proxy",
		Domains:       []string{"temp.custom.org"},
	}
	presetData, _ := json.Marshal(customPreset)
	filePath := filepath.Join(tempDir, "custom_temp_preset.json")
	if err := os.WriteFile(filePath, presetData, 0644); err != nil {
		t.Fatalf("failed to write temp preset file: %v", err)
	}

	// 2. Write a preset file without explicit ID (should infer from filename)
	noIDPreset := Preset{
		Name:          "No ID Preset",
		Description:   "Inferred ID preset",
		DefaultTarget: "direct",
		Domains:       []string{"noid.org"},
	}
	noIDData, _ := json.Marshal(noIDPreset)
	noIDFilePath := filepath.Join(tempDir, "inferred_preset.json")
	if err := os.WriteFile(noIDFilePath, noIDData, 0644); err != nil {
		t.Fatalf("failed to write inferred preset file: %v", err)
	}

	// 3. Write an invalid JSON file
	badFilePath := filepath.Join(tempDir, "corrupt.json")
	_ = os.WriteFile(badFilePath, []byte("bad-json{"), 0644)

	// Test LoadPresetFile
	p, err := pm.LoadPresetFile(filePath)
	if err != nil || p.ID != "custom_temp_preset" {
		t.Fatalf("failed to load preset file: %v", err)
	}

	pInferred, err := pm.LoadPresetFile(noIDFilePath)
	if err != nil || pInferred.ID != "inferred_preset" {
		t.Fatalf("failed to load inferred preset file: %v", err)
	}

	_, err = pm.LoadPresetFile(badFilePath)
	if err == nil {
		t.Errorf("expected error loading corrupt preset file")
	}

	_, err = pm.LoadPresetFile(filepath.Join(tempDir, "does_not_exist.json"))
	if err == nil {
		t.Errorf("expected error loading non existent preset file")
	}

	// Test LoadPresetsDirectory
	loaded, err := pm.LoadPresetsDirectory(tempDir)
	if err != nil || len(loaded) < 2 {
		t.Fatalf("failed to load presets directory: %v, loaded count: %d", err, len(loaded))
	}

	_, err = pm.LoadPresetsDirectory(filepath.Join(tempDir, "does_not_exist_dir"))
	if err == nil {
		t.Errorf("expected error loading non existent directory")
	}
}

func TestPreset_MultiRuleAndTargetOverrides(t *testing.T) {
	// 1. Single rule preset
	single := Preset{
		ID:            "single_p",
		Name:          "Single Rule",
		DefaultTarget: "proxy",
		Domains:       []string{"single.org"},
	}
	rules1 := single.GetRules("")
	if len(rules1) != 1 || rules1[0].Target != "proxy" {
		t.Errorf("unexpected single rule target: %+v", rules1)
	}

	rules1Override := single.GetRules("block")
	if len(rules1Override) != 1 || rules1Override[0].Target != "block" {
		t.Errorf("unexpected overridden target: %+v", rules1Override)
	}

	// Single rule with empty default target
	singleEmptyTarget := Preset{ID: "empty_target", Domains: []string{"a.com"}}
	rulesEmptyTarget := singleEmptyTarget.GetRules("")
	if len(rulesEmptyTarget) != 1 || rulesEmptyTarget[0].Target != "direct" {
		t.Errorf("expected fallback direct target: %+v", rulesEmptyTarget)
	}

	// 2. Multi-rule preset
	multi := Preset{
		ID:   "multi_p",
		Name: "Multi Rule",
		Rules: []RoutingRuleRow{
			{Name: "Sub Rule 1", Enabled: true, Target: "direct", Domains: []string{"sub1.com"}},
			{Name: "Sub Rule 2", Enabled: true, Target: "proxy", Domains: []string{"sub2.com"}},
		},
	}
	rulesMulti := multi.GetRules("")
	if len(rulesMulti) != 2 || rulesMulti[0].Target != "direct" || rulesMulti[1].Target != "proxy" {
		t.Errorf("unexpected multi rule target without override: %+v", rulesMulti)
	}

	rulesMultiOverride := multi.GetRules("warp")
	if len(rulesMultiOverride) != 2 || rulesMultiOverride[0].Target != "warp" || rulesMultiOverride[1].Target != "warp" {
		t.Errorf("unexpected multi rule target with override: %+v", rulesMultiOverride)
	}
}

func TestAllBuiltinPresetsInDirectory(t *testing.T) {
	summaries := GetAvailablePresets()
	if len(summaries) == 0 {
		t.Fatalf("expected available presets list to be non-empty")
	}

	pm := GetPresetManager()

	for _, s := range summaries {
		if s.ID == "" || s.Name == "" || s.Description == "" {
			t.Errorf("preset summary missing fields: %+v", s)
		}

		p, err := pm.GetPreset(s.ID)
		if err != nil || p == nil {
			t.Fatalf("failed to retrieve preset '%s': %v", s.ID, err)
		}

		rules := p.GetRules("")
		if len(rules) == 0 {
			t.Errorf("preset '%s' returned 0 rules", s.ID)
		}

		// Test target override on each builtin preset
		overrideRules := p.GetRules("custom_tag")
		for _, r := range overrideRules {
			if r.Target != "custom_tag" {
				t.Errorf("preset '%s' failed target override: expected 'custom_tag', got '%s'", s.ID, r.Target)
			}
		}

		// Test AST compilation
		astSpec, err := pm.CompilePreset(s.ID)
		if err != nil || astSpec == nil || len(astSpec.Rules) == 0 {
			t.Errorf("failed to compile preset '%s' to AST: %v", s.ID, err)
		}
	}
}

func TestBuildTableFromPresets_Comprehensive(t *testing.T) {
	enabled := []string{"ads", "ru", "non_existent_preset"}
	overrides := map[string]string{
		"ru": "block",
	}

	table := BuildTableFromPresets(enabled, overrides)
	if table == nil {
		t.Fatalf("expected non-nil RoutingTable")
	}

	if len(table.Rules) < 2 {
		t.Fatalf("expected at least 2 rules (LAN + presets), got %d", len(table.Rules))
	}

	// First rule should always be Private LAN
	if table.Rules[0].Name != "Private LAN" || table.Rules[0].Target != "direct" {
		t.Errorf("unexpected rule 0: %+v", table.Rules[0])
	}

	// Verify order increment
	for i, r := range table.Rules {
		if r.Order != i+1 {
			t.Errorf("rule index %d has order %d, expected %d", i, r.Order, i+1)
		}
	}
}

func TestEngine_CompilePolicy_Comprehensive(t *testing.T) {
	engine := NewEngine()

	// 1. Nil policy -> defaults to DefaultSmartPolicy
	specNil := engine.CompilePolicy(nil)
	if specNil == nil || len(specNil.Rules) == 0 {
		t.Fatalf("expected valid AST from nil policy")
	}

	// 2. DirectAll and WhitelistOnly modes
	policyDirect := &RoutingPolicy{Mode: ModeDirectAll}
	specDirect := engine.CompilePolicy(policyDirect)
	if specDirect.DefaultAction != ast.ActionDirect {
		t.Errorf("expected default action direct for ModeDirectAll, got %s", specDirect.DefaultAction)
	}

	policyWhitelist := &RoutingPolicy{Mode: ModeWhitelistOnly}
	specWhitelist := engine.CompilePolicy(policyWhitelist)
	if specWhitelist.DefaultAction != ast.ActionDirect {
		t.Errorf("expected default action direct for ModeWhitelistOnly, got %s", specWhitelist.DefaultAction)
	}

	// 3. Full Policy with all options populated
	fullPolicy := &RoutingPolicy{
		Mode:                   ModeSmartRule,
		AndroidBlockedUIDs:     []string{"10142"},
		BlockedPorts:           []string{"25", "445", "1000-1010"},
		CustomBlockDomains:     []string{"malware.com"},
		CustomBlockIPs:         []string{"198.51.100.1"},
		CustomDirectDomains:    []string{"direct.com"},
		CustomDirectIPs:        []string{"198.51.100.2"},
		WindowsProcessDirect:   []string{"game.exe"},
		CustomProxyDomains:     []string{"proxy.com"},
		CustomProxyIPs:         []string{"198.51.100.3"},
		WindowsProcessProxy:    []string{"discord.exe"},
		AndroidIncludePackages: []string{"com.example.app"},
		AndroidExcludePackages: []string{"com.example.direct"},
		CustomRules: []RoutingRuleRow{
			{
				Name:    "Custom User Row",
				Enabled: true,
				Target:  "custom-outbound",
				Domains: []string{"special.com"},
			},
		},
		EnabledPresets: []string{"ads", "ru", "ads"}, // with duplicate preset
		PresetTargetOverrides: map[string]string{
			"ru": "direct",
		},
	}

	specFull := engine.CompilePolicy(fullPolicy)
	if specFull == nil {
		t.Fatalf("expected non-nil compiled AST spec")
	}

	if len(specFull.Rules) < 8 {
		t.Fatalf("expected at least 8 rules in full policy spec, got %d", len(specFull.Rules))
	}

	// Verify Android Blocked UIDs at highest priority
	if specFull.Rules[0].Action != ast.ActionBlock || len(specFull.Rules[0].PackageUIDs) != 1 {
		t.Errorf("expected rule 0 to be Android Blocked UIDs: %+v", specFull.Rules[0])
	}

	// Verify Blocked Ports rule
	if specFull.Rules[1].Action != ast.ActionBlock || len(specFull.Rules[1].Ports) != 3 {
		t.Errorf("expected rule 1 to be Blocked Ports: %+v", specFull.Rules[1])
	}

	// Verify Private LAN rule
	if specFull.Rules[2].Action != ast.ActionDirect || len(specFull.Rules[2].IPs) != 1 || specFull.Rules[2].IPs[0] != "geoip:private" {
		t.Errorf("expected rule 2 to be Private LAN: %+v", specFull.Rules[2])
	}

	// 4. DefaultGlobalPolicy
	globalPolicy := DefaultGlobalPolicy()
	specGlobal := engine.CompilePolicy(globalPolicy)
	if specGlobal.DefaultAction != ast.ActionProxy {
		t.Errorf("expected default action proxy for GlobalProxy, got %s", specGlobal.DefaultAction)
	}
}

func TestRoutingCascadeRelayScenario(t *testing.T) {
	// Scenario: Edge Relay node routing rules
	// LAN traffic -> direct
	// Russian domain/IP -> direct
	// Security ports -> block
	// Everything else -> to-exit-node relay outbound
	relayTable := NewRoutingTable("to-exit-node")
	relayTable.AddRule(RoutingRuleRow{
		Order:   1,
		Name:    "Block Malware Ports",
		Enabled: true,
		Target:  "block",
		Ports:   []string{"25", "445"},
	})
	relayTable.AddRule(RoutingRuleRow{
		Order:   2,
		Name:    "Direct LAN",
		Enabled: true,
		Target:  "direct",
		IPs:     []string{"geoip:private"},
	})
	relayTable.AddRule(RoutingRuleRow{
		Order:   3,
		Name:    "Direct RU Infrastructure",
		Enabled: true,
		Target:  "direct",
		Domains: []string{"geosite:ru"},
		IPs:     []string{"geoip:ru"},
	})

	spec := relayTable.CompileToAST()
	if len(spec.Rules) != 3 {
		t.Fatalf("expected 3 cascade relay rules, got %d", len(spec.Rules))
	}
	if spec.DefaultAction != ast.ActionProxy {
		t.Errorf("expected default proxy action, got %s", spec.DefaultAction)
	}

	// Verify serialization roundtrip
	exported, err := relayTable.ExportJSON()
	if err != nil {
		t.Fatalf("failed to export cascade relay table: %v", err)
	}
	if !strings.Contains(exported, "to-exit-node") {
		t.Errorf("exported JSON missing defaultTarget 'to-exit-node':\n%s", exported)
	}
}
