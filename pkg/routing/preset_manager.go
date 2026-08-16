package routing

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"github.com/blackalex1/sentinel-core/pkg/ast"
	"github.com/blackalex1/sentinel-core/presets"
)

// Preset represents a self-contained routing rule set loaded dynamically from JSON
type Preset struct {
	ID            string           `json:"id"`
	Type          string           `json:"type,omitempty"` // "quick_rule" (atomic filter) or "template" (full preset configuration)
	Name          string           `json:"name"`
	Description   string           `json:"description"`
	DefaultTarget string           `json:"defaultTarget"` // Default target action: "direct", "block", "proxy"

	// Matchers for single-rule presets (e.g. ru.json, ads.json, bittorrent.json)
	Domains      []string `json:"domains,omitempty"`
	IPs          []string `json:"ips,omitempty"`
	Protocols    []string `json:"protocols,omitempty"`
	Ports        []string `json:"ports,omitempty"`
	ProcessNames []string `json:"processNames,omitempty"`
	PackageUIDs  []string `json:"packageUids,omitempty"`

	// Optional multi-rule composite rows
	Rules []RoutingRuleRow `json:"rules,omitempty"`
}

// GetRules returns the list of rule rows for this preset, applying an optional target override
func (p *Preset) GetRules(targetOverride string) []RoutingRuleRow {
	target := p.DefaultTarget
	if targetOverride != "" {
		target = targetOverride
	}
	if target == "" {
		target = "direct"
	}

	// If multi-rule rows are explicitly defined, return them with target applied
	if len(p.Rules) > 0 {
		result := make([]RoutingRuleRow, len(p.Rules))
		for i, r := range p.Rules {
			row := r
			if targetOverride != "" {
				row.Target = targetOverride
			}
			result[i] = row
		}
		return result
	}

	// Single rule preset: wrap matchers directly
	return []RoutingRuleRow{
		{
			Name:         p.Name,
			Enabled:      true,
			Target:       target,
			Domains:      p.Domains,
			IPs:          p.IPs,
			Protocols:    p.Protocols,
			Ports:        p.Ports,
			ProcessNames: p.ProcessNames,
			PackageUIDs:  p.PackageUIDs,
		},
	}
}

// PresetManager provides thread-safe access, loading, and management of routing presets
type PresetManager struct {
	mu      sync.RWMutex
	presets map[string]*Preset
}

var (
	globalPresetManager *PresetManager
	presetOnce          sync.Once
)

// GetPresetManager returns the global singleton PresetManager
func GetPresetManager() *PresetManager {
	presetOnce.Do(func() {
		globalPresetManager = &PresetManager{
			presets: make(map[string]*Preset),
		}
		globalPresetManager.registerBuiltinPresets()
	})
	return globalPresetManager
}

// registerBuiltinPresets loads all built-in presets dynamically from the single source of truth (presets.BuiltinFS)
func (pm *PresetManager) registerBuiltinPresets() {
	entries, err := presets.BuiltinFS.ReadDir(".")
	if err != nil {
		return
	}

	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".json") {
			data, err := presets.BuiltinFS.ReadFile(entry.Name())
			if err == nil {
				var p Preset
				if err := json.Unmarshal(data, &p); err == nil && p.ID != "" {
					pm.RegisterPreset(&p)
				}
			}
		}
	}
}

// RegisterPreset adds or updates a preset in memory
func (pm *PresetManager) RegisterPreset(p *Preset) {
	if p == nil || p.ID == "" {
		return
	}
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.presets[p.ID] = p
}

// GetPreset retrieves a preset by its identifier (supports common aliases like bypass_ru -> ru)
func (pm *PresetManager) GetPreset(id string) (*Preset, error) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	// Direct lookup
	if p, exists := pm.presets[id]; exists {
		return p, nil
	}

	// Canonical alias fallback
	aliasMap := map[string]string{
		"bypass_ru":      "ru",
		"block_ru":       "ru",
		"smart_ru":       "ru",
		"torrent_shield": "bittorrent",
		"block_torrent":  "bittorrent",
		"block_ads":      "ads",
		"block_cn":       "cn",
		"block_us":       "us",
	}

	if canonical, ok := aliasMap[id]; ok {
		if p, exists := pm.presets[canonical]; exists {
			return p, nil
		}
	}

	return nil, fmt.Errorf("preset '%s' not found", id)
}

// ListPresets returns a list of all registered presets sorted deterministically by ID
func (pm *PresetManager) ListPresets() []*Preset {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	list := make([]*Preset, 0, len(pm.presets))
	for _, p := range pm.presets {
		list = append(list, p)
	}
	sort.Slice(list, func(i, j int) bool {
		return list[i].ID < list[j].ID
	})
	return list
}

// CompilePreset compiles the given preset ID into an ast.RoutingSpec
func (pm *PresetManager) CompilePreset(id string) (*ast.RoutingSpec, error) {
	p, err := pm.GetPreset(id)
	if err != nil {
		return nil, err
	}

	table := &RoutingTable{
		DefaultTarget: "proxy",
		Rules:         append([]RoutingRuleRow{{Order: 1, Name: "Private LAN", Enabled: true, Target: "direct", IPs: []string{"geoip:private"}}}, p.GetRules("")...),
	}

	return table.CompileToAST(), nil
}

// LoadPresetFile loads and registers a single preset JSON file from filesystem
func (pm *PresetManager) LoadPresetFile(filePath string) (*Preset, error) {
	bytes, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read preset file: %w", err)
	}

	var p Preset
	if err := json.Unmarshal(bytes, &p); err != nil {
		return nil, fmt.Errorf("failed to parse preset JSON: %w", err)
	}

	if p.ID == "" {
		base := filepath.Base(filePath)
		p.ID = strings.TrimSuffix(base, filepath.Ext(base))
	}

	pm.RegisterPreset(&p)
	return &p, nil
}

// LoadPresetsDirectory scans a directory and loads all .json preset files
func (pm *PresetManager) LoadPresetsDirectory(dirPath string) ([]*Preset, error) {
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read presets directory: %w", err)
	}

	var loaded []*Preset
	for _, entry := range entries {
		if !entry.IsDir() && filepath.Ext(entry.Name()) == ".json" {
			p, err := pm.LoadPresetFile(filepath.Join(dirPath, entry.Name()))
			if err == nil && p != nil {
				loaded = append(loaded, p)
			}
		}
	}
	return loaded, nil
}

// ExportPresetJSON exports a preset to formatted JSON string
func (pm *PresetManager) ExportPresetJSON(id string) (string, error) {
	p, err := pm.GetPreset(id)
	if err != nil {
		return "", err
	}
	bytes, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}
