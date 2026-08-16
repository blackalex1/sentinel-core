package i18n

// dictRU and dictEN provide package-level alias access to the Russian and English translation maps.
var (
	DictRU = ruTranslations
	DictEN = enTranslations
	dictRU = ruTranslations
	dictEN = enTranslations
)

// GetDictionary returns the translation map for the specified locale.
func GetDictionary(loc Locale) map[string]string {
	if dict, ok := translations[loc]; ok {
		return dict
	}
	return translations[LocaleEN]
}

// GetAllKeys returns all unique keys across all loaded dictionaries.
func GetAllKeys() []string {
	keySet := make(map[string]bool)
	for _, dict := range translations {
		for k := range dict {
			keySet[k] = true
		}
	}
	keys := make([]string, 0, len(keySet))
	for k := range keySet {
		keys = append(keys, k)
	}
	return keys
}
