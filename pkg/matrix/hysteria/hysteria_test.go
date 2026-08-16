package hysteria

import (
	"testing"

	"github.com/blackalex1/sentinel-core/pkg/ast"
)

func TestHysteria_EngineOption(t *testing.T) {
	langs := []string{"ru", "en", ""}
	for _, lang := range langs {
		opt := GetEngineOption(lang)
		if opt.ID != "hysteria2" {
			t.Errorf("expected engine ID 'hysteria2', got '%s'", opt.ID)
		}
		if opt.Name == "" || opt.Description == "" {
			t.Errorf("expected non-empty name and description for lang '%s'", lang)
		}
		if len(opt.Protocols) != 1 || opt.Protocols[0] != ast.ProtoHysteria2 {
			t.Errorf("expected single protocol hysteria2, got %+v", opt.Protocols)
		}
	}
}

func TestHysteria_ProtocolCapabilities(t *testing.T) {
	langs := []string{"ru", "en"}
	for _, lang := range langs {
		hy2 := GetHysteria2Capability(lang)
		if hy2.Protocol != ast.ProtoHysteria2 || hy2.DisplayName != "Hysteria 2" {
			t.Errorf("invalid Hysteria 2 capability: %+v", hy2)
		}
		if hy2.DefaultPort != 443 {
			t.Errorf("expected default port 443, got %d", hy2.DefaultPort)
		}
		if len(hy2.SupportedTransports) != 1 || hy2.SupportedTransports[0] != "quic" {
			t.Errorf("expected quic transport, got %+v", hy2.SupportedTransports)
		}
		if len(hy2.SupportedSecurity) != 1 || hy2.SupportedSecurity[0] != "tls" {
			t.Errorf("expected tls security, got %+v", hy2.SupportedSecurity)
		}
		if len(hy2.Features) < 4 {
			t.Errorf("expected at least 4 features for Hysteria 2, got %d", len(hy2.Features))
		}
	}
}
