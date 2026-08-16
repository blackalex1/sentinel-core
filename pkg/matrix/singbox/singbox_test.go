package singbox

import (
	"testing"

	"github.com/blackalex1/sentinel-core/pkg/ast"
)

func TestSingbox_EngineOption(t *testing.T) {
	langs := []string{"ru", "en", ""}
	for _, lang := range langs {
		opt := GetEngineOption(lang)
		if opt.ID != "sing-box" {
			t.Errorf("expected engine ID 'sing-box', got '%s'", opt.ID)
		}
		if opt.Name == "" || opt.Description == "" {
			t.Errorf("expected non-empty name and description for lang '%s'", lang)
		}
		if len(opt.Protocols) == 0 {
			t.Errorf("expected supported protocols for sing-box")
		}
	}
}

func TestSingbox_ProtocolCapabilities(t *testing.T) {
	langs := []string{"ru", "en"}
	for _, lang := range langs {
		// VLESS
		vless := GetVLESSCapability(lang)
		if vless.Protocol != ast.ProtoVLESS || vless.DefaultPort != 443 {
			t.Errorf("invalid VLESS capability: %+v", vless)
		}

		// Hysteria2
		hy2 := GetHysteria2Capability(lang)
		if hy2.Protocol != ast.ProtoHysteria2 || hy2.DefaultPort != 443 || len(hy2.Features) == 0 {
			t.Errorf("invalid Hysteria2 capability: %+v", hy2)
		}

		// TUIC
		tuic := GetTUICCapability(lang)
		if tuic.Protocol != ast.ProtoTUIC || tuic.DefaultPort != 8443 || len(tuic.Features) == 0 {
			t.Errorf("invalid TUIC capability: %+v", tuic)
		}

		// ShadowTLS
		stls := GetShadowTLSCapability(lang)
		if stls.Protocol != ast.ProtoShadowTLS || stls.DefaultPort != 443 || len(stls.Features) == 0 {
			t.Errorf("invalid ShadowTLS capability: %+v", stls)
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

		// WireGuard
		wg := GetWireGuardCapability(lang)
		if wg.Protocol != ast.ProtoWireGuard || wg.DefaultPort != 51820 {
			t.Errorf("invalid WireGuard capability: %+v", wg)
		}

		// VMess
		vmess := GetVMessCapability(lang)
		if vmess.Protocol != ast.ProtoVMess || vmess.DefaultPort != 443 {
			t.Errorf("invalid VMess capability: %+v", vmess)
		}
	}
}
