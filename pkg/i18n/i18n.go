package i18n

import (
	"fmt"
	"sync"
)

// Locale represents a language code (e.g., "ru", "en")
type Locale string

const (
	LocaleRU Locale = "ru"
	LocaleEN Locale = "en"
)

var (
	currentLocale = LocaleRU
	localeMutex   sync.RWMutex
)

// SetLocale sets the global default locale for the core
func SetLocale(loc Locale) {
	localeMutex.Lock()
	defer localeMutex.Unlock()
	switch loc {
	case LocaleEN:
		currentLocale = LocaleEN
	default:
		currentLocale = LocaleRU
	}
}

// GetLocale returns the current global locale
func GetLocale() Locale {
	localeMutex.RLock()
	defer localeMutex.RUnlock()
	return currentLocale
}

// T translates a key using the given locale (or falls back to RU/EN)
func T(loc Locale, key string, args ...interface{}) string {
	if loc == "" {
		loc = GetLocale()
	}

	dict, ok := translations[loc]
	if !ok {
		dict = translations[LocaleEN]
	}

	template, ok := dict[key]
	if !ok {
		// Fallback to English
		if fallbackDict, hasEn := translations[LocaleEN]; hasEn {
			if fb, hasKey := fallbackDict[key]; hasKey {
				template = fb
			}
		}
	}

	if template == "" {
		return key // Fallback to raw key if not found
	}

	if len(args) > 0 {
		return fmt.Sprintf(template, args...)
	}
	return template
}

// TGlobal translates a key using the current global locale
func TGlobal(key string, args ...interface{}) string {
	return T(GetLocale(), key, args...)
}
