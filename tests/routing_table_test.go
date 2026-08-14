package tests

import (
	"encoding/json"
	"strings"
	"testing"
	"github.com/blackalex1/sentinel-core/pkg/ast"
	"github.com/blackalex1/sentinel-core/pkg/builder"
	"github.com/blackalex1/sentinel-core/pkg/routing"
)

func TestRoutingTable_PanelScreenshotExactMatch(t *testing.T) {
	// Recreate the exact 7 rules from the panel screenshot
	table := routing.NewRoutingTable("direct")

	table.AddRule(routing.RoutingRuleRow{
		Order:     1,
		Name:      "Block BitTorrent",
		Enabled:   true,
		Target:    "BLOCKED",
		Domains:   []string{"torrentz.com", "thepiratebay.org", "rutracker.org", "rutor.info"},
		Protocols: []string{"bittorrent"},
	})

	table.AddRule(routing.RoutingRuleRow{
		Order:    2,
		Name:     "local",
		Enabled:  true,
		Target:   "VLESS-CYBERGRID-SERVEQUAKE-COM",
		Inbounds: []string{"inbound-11"},
	})

	table.AddRule(routing.RoutingRuleRow{
		Order:   3,
		Name:    "Сервисы определения IP",
		Enabled: true,
		Target:  "DIRECT",
		Domains: []string{"2ip.ru", "ipinfo.io", "ifconfig.me", "api.ipify.org"},
	})

	table.AddRule(routing.RoutingRuleRow{
		Order:   4,
		Name:    "ru sites",
		Enabled: true,
		Target:  "DIRECT",
		Domains: []string{"yandex.ru", "vk.com", "gosuslugi.ru", "sberbank.ru"},
		IPs:     []string{"geoip:ru"},
	})

	table.AddRule(routing.RoutingRuleRow{
		Order:   5,
		Name:    "local",
		Enabled: true,
		Target:  "DIRECT",
		Domains: []string{"localhost"},
		IPs:     []string{"geoip:private"},
	})

	table.AddRule(routing.RoutingRuleRow{
		Order:    6,
		Name:     "double",
		Enabled:  true,
		Target:   "HYSTERIA2-CYBERGRID-SERVEQUAKE-COM",
		Inbounds: []string{"inbound-8"},
	})

	table.AddRule(routing.RoutingRuleRow{
		Order:    7,
		Name:     "botik",
		Enabled:  true,
		Target:   "HY_BOT_V2",
		Inbounds: []string{"inbound-4"},
	})

	// Compile table to AST
	routingSpec := table.CompileToAST()

	if len(routingSpec.Rules) != 7 {
		t.Fatalf("expected 7 compiled rules, got %d", len(routingSpec.Rules))
	}

	// 1. Check Rule 1 (Block BitTorrent)
	if routingSpec.Rules[0].Action != ast.ActionBlock || routingSpec.Rules[0].OutboundTag != "block" {
		t.Errorf("Rule 1 expected ActionBlock/block, got %s / %s", routingSpec.Rules[0].Action, routingSpec.Rules[0].OutboundTag)
	}

	// 2. Check Rule 2 (local -> VLESS-CYBERGRID-SERVEQUAKE-COM)
	if routingSpec.Rules[1].OutboundTag != "VLESS-CYBERGRID-SERVEQUAKE-COM" {
		t.Errorf("Rule 2 expected outbound tag VLESS-CYBERGRID-SERVEQUAKE-COM, got: %s", routingSpec.Rules[1].OutboundTag)
	}
	if len(routingSpec.Rules[1].InboundTags) != 1 || routingSpec.Rules[1].InboundTags[0] != "inbound-11" {
		t.Errorf("Rule 2 expected inbound-11 tag, got: %v", routingSpec.Rules[1].InboundTags)
	}

	// 3. Check Rule 6 & 7 custom chained outbound targets
	if routingSpec.Rules[5].OutboundTag != "HYSTERIA2-CYBERGRID-SERVEQUAKE-COM" {
		t.Errorf("Rule 6 target mismatch: %s", routingSpec.Rules[5].OutboundTag)
	}
	if routingSpec.Rules[6].OutboundTag != "HY_BOT_V2" {
		t.Errorf("Rule 7 target mismatch: %s", routingSpec.Rules[6].OutboundTag)
	}

	// 4. Test compilation into Sing-box JSON
	spec := &ast.ConfigSpec{
		TargetCore: ast.CoreSingBox,
		Routing:    routingSpec,
	}

	res, err := builder.BuildClientConfig(spec)
	if err != nil {
		t.Fatalf("failed to build Sing-box config from routing table: %v", err)
	}

	// Verify Sing-box config JSON contains the exact chained outbound tags
	if !strings.Contains(res.ConfigJSON, "VLESS-CYBERGRID-SERVEQUAKE-COM") {
		t.Errorf("Sing-box JSON missing VLESS-CYBERGRID-SERVEQUAKE-COM")
	}
	if !strings.Contains(res.ConfigJSON, "HYSTERIA2-CYBERGRID-SERVEQUAKE-COM") {
		t.Errorf("Sing-box JSON missing HYSTERIA2-CYBERGRID-SERVEQUAKE-COM")
	}
	if !strings.Contains(res.ConfigJSON, "HY_BOT_V2") {
		t.Errorf("Sing-box JSON missing HY_BOT_V2")
	}

	// 5. Test JSON Export and Import
	jsonPreset, err := table.ExportJSON()
	if err != nil {
		t.Fatalf("failed to export routing table preset: %v", err)
	}

	importedTable, err := routing.ImportRoutingTableJSON(jsonPreset)
	if err != nil {
		t.Fatalf("failed to import routing table preset: %v", err)
	}

	if len(importedTable.Rules) != 7 {
		t.Errorf("expected 7 rules after import, got %d", len(importedTable.Rules))
	}
}

// Suppress unused imports
var _ = json.Marshal
