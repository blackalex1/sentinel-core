package tests

import (
	"testing"
	"github.com/blackalex1/sentinel-core/pkg/i18n"
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
