package routing

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"github.com/blackalex1/sentinel-core/pkg/ast"
)

// RoutingRuleRow represents an individual row from the Routing Table UI (as shown in the panel/client screenshot).
type RoutingRuleRow struct {
	ID          string   `json:"id,omitempty"`
	Order       int      `json:"order"`       // Execution order priority (1, 2, 3...)
	Name        string   `json:"name"`        // Description ("Block BitTorrent", "ru sites", etc.)
	Enabled     bool     `json:"enabled"`     // Status (active / disabled)
	Target      string   `json:"target"`      // Destination: "block", "direct", "proxy" or custom outbound tag
	
	// Condition matchers
	Inbounds     []string `json:"inbounds,omitempty"`     // Inbound tags: ["inbound-11", "inbound-8", "tun-in"]
	Domains      []string `json:"domains,omitempty"`      // Domains & geosites: ["geosite:category-ads-all", "gosuslugi.ru"]
	IPs          []string `json:"ips,omitempty"`          // IP addresses & geoip: ["geoip:ru", "geoip:private", "1.2.3.4/32"]
	Protocols    []string `json:"protocols,omitempty"`    // Application and transport protocols: ["bittorrent", "quic", "dns"]
	Ports        []string `json:"ports,omitempty"`        // Port ranges: ["80", "443", "1000-2000"]
	ProcessNames []string `json:"processNames,omitempty"` // Process names for Windows: ["discord.exe", "telegram.exe"]
	PackageUIDs  []string `json:"packageUids,omitempty"`  // Package UIDs for Android: ["10142"]
}

// RoutingTable manages a collection of prioritized routing rules with import/export capabilities.
type RoutingTable struct {
	DefaultTarget string           `json:"defaultTarget"` // Default target action: "proxy" or "direct"
	Rules         []RoutingRuleRow `json:"rules"`
}

// NewRoutingTable creates an empty routing table
func NewRoutingTable(defaultTarget string) *RoutingTable {
	if defaultTarget == "" {
		defaultTarget = "proxy"
	}
	return &RoutingTable{
		DefaultTarget: defaultTarget,
		Rules:         make([]RoutingRuleRow, 0),
	}
}

// AddRule adds a new rule row to the table
func (t *RoutingTable) AddRule(rule RoutingRuleRow) {
	t.Rules = append(t.Rules, rule)
}

// CompileToAST compiles the table rows (in strict top-to-bottom order) into an ast.RoutingSpec
func (t *RoutingTable) CompileToAST() *ast.RoutingSpec {
	// 1. Sort rules by Order (1, 2, 3...)
	sortedRules := make([]RoutingRuleRow, len(t.Rules))
	copy(sortedRules, t.Rules)
	sort.SliceStable(sortedRules, func(i, j int) bool {
		return sortedRules[i].Order < sortedRules[j].Order
	})

	astRules := make([]ast.RoutingRule, 0)

	// 2. Translate each enabled rule row into an AST RoutingRule
	for _, row := range sortedRules {
		if !row.Enabled {
			continue // Skip disabled rules
		}

		target := strings.TrimSpace(row.Target)
		if target == "" {
			target = "direct"
		}

		// Resolve action and target outbound tag
		action := ast.ActionProxy
		outboundTag := target

		targetUpper := strings.ToUpper(target)
		if targetUpper == "BLOCK" || targetUpper == "BLOCKED" {
			action = ast.ActionBlock
			outboundTag = "block"
		} else if targetUpper == "DIRECT" {
			action = ast.ActionDirect
			outboundTag = "direct"
		} else if targetUpper == "PROXY" {
			action = ast.ActionProxy
			outboundTag = "proxy"
		}

		// Sanitize domain, IP, and port lists
		cleanDomains := CleanDomainList(row.Domains)
		cleanIPs := CleanIPList(row.IPs)
		cleanPorts := CleanPortList(row.Ports)

		astRule := ast.RoutingRule{
			Action:       action,
			OutboundTag:  outboundTag,
			InboundTags:  row.Inbounds,
			Domains:      cleanDomains,
			IPs:          cleanIPs,
			Protocols:    row.Protocols,
			Ports:        cleanPorts,
			ProcessNames: row.ProcessNames,
			PackageUIDs:  row.PackageUIDs,
		}

		astRules = append(astRules, astRule)
	}

	defaultAction := ast.ActionProxy
	if strings.ToUpper(t.DefaultTarget) == "DIRECT" {
		defaultAction = ast.ActionDirect
	}

	return &ast.RoutingSpec{
		DefaultAction:       defaultAction,
		Rules:               astRules,
		AutoDetectInterface: true,
		OverrideDNS:         true,
	}
}

// ExportJSON serializes the table to a portable JSON preset
func (t *RoutingTable) ExportJSON() (string, error) {
	bytes, err := json.MarshalIndent(t, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to export routing table to JSON: %w", err)
	}
	return string(bytes), nil
}

// ImportJSON parses a JSON preset into a RoutingTable
func ImportRoutingTableJSON(jsonStr string) (*RoutingTable, error) {
	var table RoutingTable
	if err := json.Unmarshal([]byte(jsonStr), &table); err != nil {
		return nil, fmt.Errorf("failed to parse routing table JSON: %w", err)
	}
	return &table, nil
}
