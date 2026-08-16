package routing

import (
	"strings"
	"github.com/blackalex1/sentinel-core/pkg/i18n"
)

// PresetSummary represents metadata of a routing preset loaded dynamically from JSON
type PresetSummary struct {
	ID            string `json:"id"`
	Type          string `json:"type,omitempty"` // "quick_rule" or "template"
	Name          string `json:"name"`
	Description   string `json:"description"`
	DefaultTarget string `json:"defaultTarget"`
	RulesCount    int    `json:"rulesCount"`
}

// GetAvailablePresetsLocalized returns the list of all dynamically loaded presets localized for the specified language ("ru", "en")
func GetAvailablePresetsLocalized(lang string) []PresetSummary {
	pm := GetPresetManager()
	presets := pm.ListPresets()
	loc := i18n.Locale(strings.ToLower(lang))
	if loc != i18n.LocaleEN && loc != i18n.LocaleRU {
		loc = i18n.GetLocale()
	}

	list := make([]PresetSummary, 0, len(presets))
	for _, p := range presets {
		count := len(p.Rules)
		if count == 0 {
			count = 1
		}

		pType := p.Type
		if pType == "" {
			if p.ID == "global_proxy" || p.ID == "direct_all" {
				pType = "template"
			} else {
				pType = "quick_rule"
			}
		}

		nameKey := "PRESET_" + strings.ToUpper(p.ID) + "_NAME"
		descKey := "PRESET_" + strings.ToUpper(p.ID) + "_DESC"

		localizedName := i18n.T(loc, nameKey)
		if localizedName == nameKey {
			localizedName = p.Name
		}

		localizedDesc := i18n.T(loc, descKey)
		if localizedDesc == descKey {
			localizedDesc = p.Description
		}

		list = append(list, PresetSummary{
			ID:            p.ID,
			Type:          pType,
			Name:          localizedName,
			Description:   localizedDesc,
			DefaultTarget: p.DefaultTarget,
			RulesCount:    count,
		})
	}
	return list
}

// GetAvailablePresets returns the list of all dynamically loaded presets directly using the current global locale
func GetAvailablePresets() []PresetSummary {
	return GetAvailablePresetsLocalized(string(i18n.GetLocale()))
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
