package routing

// PresetSummary represents metadata of a routing preset loaded dynamically from JSON
type PresetSummary struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Description   string `json:"description"`
	DefaultTarget string `json:"defaultTarget"`
	RulesCount    int    `json:"rulesCount"`
}

// GetAvailablePresets returns the list of all dynamically loaded presets directly from the JSON files (single source of truth)
func GetAvailablePresets() []PresetSummary {
	pm := GetPresetManager()
	presets := pm.ListPresets()
	list := make([]PresetSummary, 0, len(presets))
	for _, p := range presets {
		count := len(p.Rules)
		if count == 0 {
			count = 1
		}
		list = append(list, PresetSummary{
			ID:            p.ID,
			Name:          p.Name,
			Description:   p.Description,
			DefaultTarget: p.DefaultTarget,
			RulesCount:    count,
		})
	}
	return list
}

// BuildTableFromPresets constructs a prioritized RoutingTable from an active list of preset IDs and optional target overrides.
// All rule definitions, domains, IPs and protocols are fetched directly from the JSON presets.
func BuildTableFromPresets(enabledPresetIDs []string, targetOverrides map[string]string) *RoutingTable {
	pm := GetPresetManager()
	table := NewRoutingTable("proxy")

	// Base rule: Private LAN is always direct
	table.AddRule(RoutingRuleRow{
		Order:   1,
		Name:    "Private LAN",
		Enabled: true,
		Target:  "direct",
		IPs:     []string{"geoip:private"},
	})

	order := 2

	for _, presetID := range enabledPresetIDs {
		p, err := pm.GetPreset(presetID)
		if err != nil || p == nil {
			continue
		}

		targetOverride := ""
		if targetOverrides != nil {
			targetOverride = targetOverrides[presetID]
		}

		rules := p.GetRules(targetOverride)
		for _, r := range rules {
			if !r.Enabled {
				continue
			}
			row := r
			row.Order = order
			table.AddRule(row)
			order++
		}
	}

	return table
}
