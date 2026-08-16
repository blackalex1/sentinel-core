package i18n

import (
	"regexp"
	"strings"
	"testing"
)

func TestSetAndGetLocale(t *testing.T) {
	SetLocale(LocaleEN)
	if GetLocale() != LocaleEN {
		t.Errorf("expected LocaleEN, got: %s", GetLocale())
	}

	SetLocale(LocaleRU)
	if GetLocale() != LocaleRU {
		t.Errorf("expected LocaleRU, got: %s", GetLocale())
	}

	// Unknown locale defaults to RU
	SetLocale(Locale("unknown"))
	if GetLocale() != LocaleRU {
		t.Errorf("expected unknown locale to default to LocaleRU, got: %s", GetLocale())
	}
}

func TestT_Translations_And_Formatting(t *testing.T) {
	// 1. Russian
	resRu := T(LocaleRU, "HEALTH_CHECK_PASSED")
	if resRu == "" || resRu == "HEALTH_CHECK_PASSED" {
		t.Fatalf("expected translation for HEALTH_CHECK_PASSED in RU, got: %s", resRu)
	}

	// 2. English
	resEn := T(LocaleEN, "HEALTH_CHECK_PASSED")
	if resEn == "" || resEn == "HEALTH_CHECK_PASSED" {
		t.Fatalf("expected translation for HEALTH_CHECK_PASSED in EN, got: %s", resEn)
	}

	// 3. Formatted arguments
	resFormatted := T(LocaleRU, "HEALTH_PORT_OCCUPIED_SIMPLE", 10808)
	if !strings.Contains(resFormatted, "10808") {
		t.Errorf("expected formatted string to contain port 10808, got: %s", resFormatted)
	}

	resFormattedEn := T(LocaleEN, "HEALTH_PORT_OCCUPIED_SIMPLE", 8080)
	if !strings.Contains(resFormattedEn, "8080") {
		t.Errorf("expected formatted string to contain port 8080, got: %s", resFormattedEn)
	}
}

func TestT_Fallbacks(t *testing.T) {
	SetLocale(LocaleRU)

	// Empty locale defaults to global (RU)
	resEmptyLoc := T("", "HEALTH_CHECK_PASSED")
	if resEmptyLoc == "" || resEmptyLoc == "HEALTH_CHECK_PASSED" {
		t.Errorf("expected translation with empty locale, got: %s", resEmptyLoc)
	}

	// Unknown locale falls back to EN
	resUnknownLoc := T("de", "HEALTH_CHECK_PASSED")
	if resUnknownLoc == "" || resUnknownLoc == "HEALTH_CHECK_PASSED" {
		t.Errorf("expected translation with unknown locale, got: %s", resUnknownLoc)
	}

	// Key missing completely returns raw key
	rawKey := T(LocaleRU, "TOTALLY_NON_EXISTENT_KEY_12345")
	if rawKey != "TOTALLY_NON_EXISTENT_KEY_12345" {
		t.Errorf("expected raw key fallback, got: %s", rawKey)
	}
}

func TestTGlobal(t *testing.T) {
	SetLocale(LocaleEN)
	msgEn := TGlobal("HEALTH_CHECK_PASSED")

	SetLocale(LocaleRU)
	msgRu := TGlobal("HEALTH_CHECK_PASSED")

	if msgEn == msgRu {
		t.Errorf("expected different translations for EN and RU, got en=%s ru=%s", msgEn, msgRu)
	}
}

func TestDictionaries_StrictParity(t *testing.T) {
	if len(ruTranslations) == 0 {
		t.Fatalf("expected non-empty ruTranslations")
	}
	if len(enTranslations) == 0 {
		t.Fatalf("expected non-empty enTranslations")
	}

	if len(ruTranslations) != len(enTranslations) {
		t.Errorf("translation map size mismatch: RU has %d keys, EN has %d keys", len(ruTranslations), len(enTranslations))
	}

	// Format specifier extraction regex (%s, %d, %v, %f, etc.)
	specifierRegex := regexp.MustCompile(`%[-+0-9.]*[a-zA-Z]`)

	// Check every key in RU exists in EN
	for k, ruVal := range ruTranslations {
		if strings.TrimSpace(ruVal) == "" {
			t.Errorf("empty translation in RU for key: %s", k)
		}
		enVal, exists := enTranslations[k]
		if !exists {
			t.Errorf("key '%s' present in RU but missing in EN", k)
			continue
		}
		if strings.TrimSpace(enVal) == "" {
			t.Errorf("empty translation in EN for key: %s", k)
		}

		// Verify matching format specifier counts
		ruSpecs := specifierRegex.FindAllString(ruVal, -1)
		enSpecs := specifierRegex.FindAllString(enVal, -1)
		if len(ruSpecs) != len(enSpecs) {
			t.Errorf("format specifiers count mismatch for key '%s': RU has %v, EN has %v", k, ruSpecs, enSpecs)
		}
	}

	// Check every key in EN exists in RU
	for k := range enTranslations {
		if _, exists := ruTranslations[k]; !exists {
			t.Errorf("key '%s' present in EN but missing in RU", k)
		}
	}
}

func TestDictionaries_AliasesAndHelpers(t *testing.T) {
	if len(DictRU) != len(ruTranslations) || len(dictRU) != len(ruTranslations) {
		t.Errorf("DictRU / dictRU alias mismatch")
	}
	if len(DictEN) != len(enTranslations) || len(dictEN) != len(enTranslations) {
		t.Errorf("DictEN / dictEN alias mismatch")
	}

	dictFromHelperRU := GetDictionary(LocaleRU)
	if len(dictFromHelperRU) != len(ruTranslations) {
		t.Errorf("GetDictionary(LocaleRU) failed")
	}

	dictFromHelperEN := GetDictionary(LocaleEN)
	if len(dictFromHelperEN) != len(enTranslations) {
		t.Errorf("GetDictionary(LocaleEN) failed")
	}

	keys := GetAllKeys()
	if len(keys) != len(ruTranslations) {
		t.Errorf("GetAllKeys() expected %d keys, got %d", len(ruTranslations), len(keys))
	}
}
