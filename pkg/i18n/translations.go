package i18n

// translations aggregates dictionaries from separate language files (ru.go, en.go)
var translations = map[Locale]map[string]string{
	LocaleRU: ruTranslations,
	LocaleEN: enTranslations,
}
