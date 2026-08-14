package routing

import (
	"strings"
	"github.com/blackalex1/sentinel-core/pkg/ast"
)

// Engine evaluates high-level RoutingPolicy and compiles it into an ast.RoutingSpec
type Engine struct {
	pm *PresetManager
}

// NewEngine creates a new Routing Engine instance
func NewEngine() *Engine {
	return &Engine{
		pm: GetPresetManager(),
	}
}

// CompilePolicy transforms a user-friendly RoutingPolicy into strict AST routing rules
// using dynamic presets directly from presets/*.json.
func (e *Engine) CompilePolicy(policy *RoutingPolicy) *ast.RoutingSpec {
	if policy == nil {
		policy = DefaultSmartPolicy()
	}

	defaultTarget := "proxy"
	if policy.Mode == ModeDirectAll || policy.Mode == ModeWhitelistOnly {
		defaultTarget = "direct"
	}

	table := NewRoutingTable(defaultTarget)
	currentOrder := 1

	// 1. HIGHEST PRIORITY: Security isolation & threat port blocks
	if len(policy.AndroidBlockedUIDs) > 0 {
		table.AddRule(RoutingRuleRow{
			Order:       currentOrder,
			Name:        "Android Blocked UIDs",
			Enabled:     true,
			Target:      "block",
			PackageUIDs: policy.AndroidBlockedUIDs,
		})
		currentOrder++
	}

	if len(policy.BlockedPorts) > 0 {
		table.AddRule(RoutingRuleRow{
			Order:   currentOrder,
			Name:    "Blocked Security Ports",
			Enabled: true,
			Target:  "block",
			Ports:   policy.BlockedPorts,
		})
		currentOrder++
	}

	// 2. Base System Rule: Private LAN Direct (no need to duplicate in each JSON preset)
	table.AddRule(RoutingRuleRow{
		Order:   currentOrder,
		Name:    "Private LAN",
		Enabled: true,
		Target:  "direct",
		IPs:     []string{"geoip:private"},
	})
	currentOrder++

	// 3. Custom User Explicit Overrides (Block, Direct, Proxy)
	if len(policy.CustomBlockDomains) > 0 || len(policy.CustomBlockIPs) > 0 {
		table.AddRule(RoutingRuleRow{
			Order:   currentOrder,
			Name:    "Custom Block Overrides",
			Enabled: true,
			Target:  "block",
			Domains: policy.CustomBlockDomains,
			IPs:     policy.CustomBlockIPs,
		})
		currentOrder++
	}

	if len(policy.CustomDirectDomains) > 0 || len(policy.CustomDirectIPs) > 0 || len(policy.WindowsProcessDirect) > 0 {
		table.AddRule(RoutingRuleRow{
			Order:        currentOrder,
			Name:         "Custom Direct Overrides",
			Enabled:      true,
			Target:       "direct",
			Domains:      policy.CustomDirectDomains,
			IPs:          policy.CustomDirectIPs,
			ProcessNames: policy.WindowsProcessDirect,
		})
		currentOrder++
	}

	if len(policy.CustomProxyDomains) > 0 || len(policy.CustomProxyIPs) > 0 || len(policy.WindowsProcessProxy) > 0 {
		table.AddRule(RoutingRuleRow{
			Order:        currentOrder,
			Name:         "Custom Proxy Overrides",
			Enabled:      true,
			Target:       "proxy",
			Domains:      policy.CustomProxyDomains,
			IPs:          policy.CustomProxyIPs,
			ProcessNames: policy.WindowsProcessProxy,
		})
		currentOrder++
	}

	// 4. User Custom Rule Rows
	for _, customRow := range policy.CustomRules {
		rowCopy := customRow
		rowCopy.Order = currentOrder
		table.AddRule(rowCopy)
		currentOrder++
	}

	// 5. Resolve Active Presets
	activePresetIDs := make([]string, 0, len(policy.EnabledPresets))
	seenPresets := make(map[string]bool)

	for _, pid := range policy.EnabledPresets {
		if !seenPresets[pid] {
			seenPresets[pid] = true
			activePresetIDs = append(activePresetIDs, pid)
		}
	}

	// Default fallback if no presets specified in smart mode
	if len(activePresetIDs) == 0 && policy.Mode == ModeSmartRule {
		activePresetIDs = append(activePresetIDs, "ads", "ru")
	}

	// 6. Append rules from dynamic presets with target override applied
	for _, presetID := range activePresetIDs {
		p, err := e.pm.GetPreset(presetID)
		if err != nil || p == nil {
			continue
		}

		targetOverride := ""
		if policy.PresetTargetOverrides != nil {
			targetOverride = policy.PresetTargetOverrides[presetID]
		}

		rules := p.GetRules(targetOverride)
		for _, r := range rules {
			if !r.Enabled {
				continue
			}
			ruleCopy := r
			ruleCopy.Order = currentOrder
			table.AddRule(ruleCopy)
			currentOrder++
		}
	}

	astSpec := table.CompileToAST()
	if strings.ToUpper(defaultTarget) == "DIRECT" {
		astSpec.DefaultAction = ast.ActionDirect
	}

	return astSpec
}
