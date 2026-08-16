package xray

import (
	"testing"

	"github.com/blackalex1/sentinel-core/pkg/ast"
)

func TestXray_EngineOption(t *testing.T) {
	langs := []string{"ru", "en", ""}
	for _, lang := range langs {
		opt := GetEngineOption(lang)
		if opt.ID != "xray-core" {
			t.Errorf("expected engine ID 'xray-core', got '%s'", opt.ID)
		}
		if opt.Name == "" {
			t.Errorf("expected non-empty engine name for lang '%s'", lang)
		}
		if opt.Description == "" {
			t.Errorf("expected non-empty engine description for lang '%s'", lang)
		}
		if len(opt.Protocols) == 0 {
			t.Errorf("expected supported protocols for xray-core")
		}
	}
}

func TestXray_ProtocolCapabilities(t *testing.T) {
	langs := []string{"ru", "en"}
	for _, lang := range langs {
		// VLESS
		vless := GetVLESSCapability(lang)
		if vless.Protocol != ast.ProtoVLESS || vless.DisplayName != "VLESS" {
			t.Errorf("invalid VLESS capability: %+v", vless)
		}
		if vless.DefaultPort != 443 || len(vless.SupportedTransports) == 0 || len(vless.SupportedSecurity) == 0 {
			t.Errorf("invalid VLESS settings: %+v", vless)
		}
		if len(vless.Features) == 0 {
			t.Errorf("expected VLESS features")
		}

		// Trojan
		trojan := GetTrojanCapability(lang)
		if trojan.Protocol != ast.ProtoTrojan || trojan.DefaultPort != 443 {
			t.Errorf("invalid Trojan capability: %+v", trojan)
		}

		// Shadowsocks
		ss := GetShadowsocksCapability(lang)
		if ss.Protocol != ast.ProtoShadowsocks || ss.DefaultPort != 8388 || len(ss.SupportedCiphers) == 0 {
			t.Errorf("invalid Shadowsocks capability: %+v", ss)
		}

		// VMess
		vmess := GetVMessCapability(lang)
		if vmess.Protocol != ast.ProtoVMess || vmess.DefaultPort != 443 {
			t.Errorf("invalid VMess capability: %+v", vmess)
		}

		// WireGuard
		wg := GetWireGuardCapability(lang)
		if wg.Protocol != ast.ProtoWireGuard || wg.DefaultPort != 51820 {
			t.Errorf("invalid WireGuard capability: %+v", wg)
		}
	}
}
