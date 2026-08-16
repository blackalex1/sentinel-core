package tests

import (
	"testing"
	"github.com/blackalex1/sentinel-core/pkg/i18n"
	"github.com/blackalex1/sentinel-core/pkg/matrix"
	"github.com/blackalex1/sentinel-core/pkg/routing"
)

func TestI18n_RussianAndEnglish(t *testing.T) {
	// Test RU
	ruMsg := i18n.T(i18n.LocaleRU, "HEALTH_PORT_OCCUPIED", 10808, "SOCKS5")
	expectedRu := "Порт 10808 (SOCKS5) уже занят другим приложением в системе"
	if ruMsg != expectedRu {
		t.Errorf("RU translation mismatch:\nGot:  %s\nWant: %s", ruMsg, expectedRu)
	}

	// Test EN
	enMsg := i18n.T(i18n.LocaleEN, "HEALTH_PORT_OCCUPIED", 10808, "SOCKS5")
	expectedEn := "Port 10808 (SOCKS5) is already occupied by another application"
	if enMsg != expectedEn {
		t.Errorf("EN translation mismatch:\nGot:  %s\nWant: %s", enMsg, expectedEn)
	}
}

func TestI18n_PresetTranslations(t *testing.T) {
	presetsEn := routing.GetAvailablePresetsLocalized("en")
	if len(presetsEn) == 0 {
		t.Fatalf("expected non-empty presets list in EN")
	}

	foundRuPresetInEn := false
	foundAdsPresetInEn := false
	for _, p := range presetsEn {
		if p.ID == "ru" {
			foundRuPresetInEn = true
			if p.Name != "Russian Websites (RU)" {
				t.Errorf("expected localized RU preset name in English, got: %s", p.Name)
			}
		}
		if p.ID == "ads" {
			foundAdsPresetInEn = true
			if p.Name != "Ads and Trackers" {
				t.Errorf("expected localized Ads preset name in English, got: %s", p.Name)
			}
		}
	}

	if !foundRuPresetInEn || !foundAdsPresetInEn {
		t.Errorf("missing expected presets in localized EN list")
	}

	presetsRu := routing.GetAvailablePresetsLocalized("ru")
	for _, p := range presetsRu {
		if p.ID == "ru" && p.Name != "Сайты России (RU)" {
			t.Errorf("expected localized RU preset name in Russian, got: %s", p.Name)
		}
		if p.ID == "ads" && p.Name != "Реклама и трекеры" {
			t.Errorf("expected localized Ads preset name in Russian, got: %s", p.Name)
		}
	}
}

func TestI18n_SchemaLocalization(t *testing.T) {
	schemaEn := matrix.GetConfigurationSchema("en")
	if schemaEn.Language != "en" {
		t.Errorf("expected language 'en', got: %s", schemaEn.Language)
	}
	if len(schemaEn.Presets) == 0 {
		t.Fatalf("expected non-empty presets in EN schema")
	}
	for _, p := range schemaEn.Presets {
		if p.ID == "ru" && p.Name != "Russian Websites (RU)" {
			t.Errorf("expected English preset name in schema, got: %s", p.Name)
		}
	}

	schemaRu := matrix.GetConfigurationSchema("ru")
	if schemaRu.Language != "ru" {
		t.Errorf("expected language 'ru', got: %s", schemaRu.Language)
	}
	for _, p := range schemaRu.Presets {
		if p.ID == "ru" && p.Name != "Сайты России (RU)" {
			t.Errorf("expected Russian preset name in schema, got: %s", p.Name)
		}
	}
}

func TestI18n_Fallback(t *testing.T) {
	// Test missing key fallback to raw key
	missing := i18n.T(i18n.LocaleRU, "NON_EXISTENT_KEY")
	if missing != "NON_EXISTENT_KEY" {
		t.Errorf("Expected raw key on missing translation, got: %s", missing)
	}

	// Test Global Locale switch
	i18n.SetLocale(i18n.LocaleEN)
	msgGlobalEn := i18n.TGlobal("CATEGORY_ADS")
	if msgGlobalEn != "Ads and Trackers" {
		t.Errorf("Global EN translation failed, got: %s", msgGlobalEn)
	}

	i18n.SetLocale(i18n.LocaleRU)
	msgGlobalRu := i18n.TGlobal("CATEGORY_ADS")
	if msgGlobalRu != "Реклама и трекеры" {
		t.Errorf("Global RU translation failed, got: %s", msgGlobalRu)
	}

	// Test Action Translation
	actionBlockRu := i18n.T(i18n.LocaleRU, "ACTION_BLOCK")
	if actionBlockRu != "Блокировка (BLOCKED)" {
		t.Errorf("Action translation mismatch, got: %s", actionBlockRu)
	}
}
