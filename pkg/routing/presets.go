package routing

// Presets provides helper functions and aliases for routing preset operations.

// ListAvailablePresets returns all available presets using the global locale.
func ListAvailablePresets() []PresetSummary {
	return GetAvailablePresets()
}

// ListAvailablePresetsLocalized returns all available presets localized for the specified language ("ru", "en").
func ListAvailablePresetsLocalized(lang string) []PresetSummary {
	return GetAvailablePresetsLocalized(lang)
}
