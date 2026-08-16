package fields

import (
	"testing"
)

func TestFields_BasicTab(t *testing.T) {
	tabRU := BuildBasicTab("ru", "vless", 443)
	if tabRU.ID != "basic" || tabRU.Title == "" {
		t.Fatalf("expected valid basic tab for RU, got: %+v", tabRU)
	}

	tabEN := BuildBasicTab("en", "vless", 443)
	if tabEN.ID != "basic" || tabEN.Title == "" {
		t.Fatalf("expected valid basic tab for EN, got: %+v", tabEN)
	}
}

func TestFields_VLESSTabs(t *testing.T) {
	tabs := BuildVLESSTabDefinitions("ru", true)
	if len(tabs) < 5 {
		t.Fatalf("expected at least 5 tabs for VLESS Xray, got: %d", len(tabs))
	}
}

func TestFields_Hysteria2Tabs(t *testing.T) {
	tabs := BuildHysteria2TabDefinitions("ru")
	if len(tabs) < 4 {
		t.Fatalf("expected at least 4 tabs for Hysteria 2, got: %d", len(tabs))
	}
}
