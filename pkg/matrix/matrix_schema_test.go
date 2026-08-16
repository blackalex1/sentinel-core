package matrix

import (
	"strings"
	"testing"

	"github.com/blackalex1/sentinel-core/pkg/ast"
	"github.com/blackalex1/sentinel-core/pkg/matrix/types"
)

// TestConfigurationSchema_StrictValidation verifies that all protocols, engines, security modes, transports,
// and tab definitions in the schema are 100% accurate and free of invalid, cross-contaminated, or erroneous fields.
func TestConfigurationSchema_StrictValidation(t *testing.T) {
	langs := []string{"ru", "en"}

	for _, lang := range langs {
		schema := GetConfigurationSchema(lang)
		if schema == nil {
			t.Fatalf("[%s] schema is nil", lang)
		}

		// 1. Validate Engines list
		if len(schema.Engines) != 3 {
			t.Fatalf("[%s] expected 3 engines (xray-core, sing-box, hysteria2), got %d", lang, len(schema.Engines))
		}

		engineMap := make(map[string]types.EngineOption)
		for _, eng := range schema.Engines {
			engineMap[eng.ID] = eng
		}

		// Xray must NOT claim to support native Hysteria 2 inbound
		if xrayEng, ok := engineMap["xray-core"]; ok {
			for _, proto := range xrayEng.Protocols {
				if proto == ast.ProtoHysteria2 {
					t.Errorf("[%s] xray-core must not list hysteria2 in its inbound protocols list", lang)
				}
				if proto == ast.ProtoTUIC || proto == ast.ProtoShadowTLS {
					t.Errorf("[%s] xray-core must not list %s in its protocols list", lang, proto)
				}
			}
		} else {
			t.Errorf("[%s] xray-core engine not found in schema", lang)
		}

		// sing-box must support all multi-core protocols
		if singboxEng, ok := engineMap["sing-box"]; ok {
			expectedProtos := []string{ast.ProtoVLESS, ast.ProtoTrojan, ast.ProtoShadowsocks, ast.ProtoVMess, ast.ProtoWireGuard, ast.ProtoHysteria2, ast.ProtoTUIC, ast.ProtoShadowTLS}
			for _, exp := range expectedProtos {
				found := false
				for _, p := range singboxEng.Protocols {
					if p == exp {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("[%s] sing-box missing expected protocol: %s", lang, exp)
				}
			}
		} else {
			t.Errorf("[%s] sing-box engine not found in schema", lang)
		}

		// Hysteria 2 engine must ONLY support hysteria2
		if hy2Eng, ok := engineMap["hysteria2"]; ok {
			if len(hy2Eng.Protocols) != 1 || hy2Eng.Protocols[0] != ast.ProtoHysteria2 {
				t.Errorf("[%s] hysteria2 engine should only support hysteria2, got: %+v", lang, hy2Eng.Protocols)
			}
		} else {
			t.Errorf("[%s] hysteria2 engine not found in schema", lang)
		}

		// 2. Protocol Specific Schema & Tab Validations
		// ==================== HYSTERIA 2 ====================
		hy2, ok := schema.Protocols[ast.ProtoHysteria2]
		if !ok {
			t.Fatalf("[%s] protocol hysteria2 missing in schema", lang)
		}
		// Hysteria 2 engines
		for _, eng := range hy2.SupportedEngines {
			if eng == "xray-core" || eng == "xray" {
				t.Errorf("[%s] hysteria2 must NEVER list xray-core in SupportedEngines! Got: %+v", lang, hy2.SupportedEngines)
			}
		}
		// Hysteria 2 security modes
		for _, sec := range hy2.SupportedSecurity {
			if sec == "reality" || sec == "none" {
				t.Errorf("[%s] hysteria2 must NEVER list %s in SupportedSecurity! Must only use TLS. Got: %+v", lang, sec, hy2.SupportedSecurity)
			}
		}
		// Hysteria 2 transports
		if len(hy2.SupportedTransports) != 1 || hy2.SupportedTransports[0] != "quic" {
			t.Errorf("[%s] hysteria2 SupportedTransports must only be ['quic'], got: %+v", lang, hy2.SupportedTransports)
		}
		// Hysteria 2 tabs
		for _, tab := range hy2.Tabs {
			if tab == "protocol" || tab == "security" {
				t.Errorf("[%s] hysteria2 tabs must NOT include '%s' tab. Got: %+v", lang, tab, hy2.Tabs)
			}
		}
		// Hysteria 2 tab definitions check
		for _, tabDef := range hy2.TabDefinitions {
			if tabDef.ID == "protocol" || tabDef.ID == "security" {
				t.Errorf("[%s] hysteria2 TabDefinitions must NOT include '%s' tab", lang, tabDef.ID)
			}
			for _, grp := range tabDef.Groups {
				for _, f := range grp.Fields {
					if strings.Contains(f.TargetField, "realitySettings") || strings.Contains(f.TargetField, "decryption") {
						t.Errorf("[%s] hysteria2 field '%s' (target: %s) is invalid for Hysteria 2", lang, f.ID, f.TargetField)
					}
				}
			}
		}

		// ==================== VLESS ====================
		vless, ok := schema.Protocols[ast.ProtoVLESS]
		if !ok {
			t.Fatalf("[%s] protocol vless missing in schema", lang)
		}
		// VLESS must support reality, tls, none
		hasReality := false
		for _, s := range vless.SupportedSecurity {
			if s == "reality" {
				hasReality = true
			}
		}
		if !hasReality {
			t.Errorf("[%s] vless must support reality", lang)
		}
		// VLESS tabs must have basic, protocol, stream, security, sniffing, advanced
		expectedVlessTabs := []string{"basic", "protocol", "stream", "security", "sniffing", "advanced"}
		if len(vless.Tabs) != len(expectedVlessTabs) {
			t.Errorf("[%s] vless expected %d tabs, got %d", lang, len(expectedVlessTabs), len(vless.Tabs))
		}

		// ==================== SHADOWSOCKS ====================
		ss, ok := schema.Protocols[ast.ProtoShadowsocks]
		if !ok {
			t.Fatalf("[%s] protocol shadowsocks missing in schema", lang)
		}
		for _, s := range ss.SupportedSecurity {
			if s == "reality" || s == "tls" {
				t.Errorf("[%s] shadowsocks must not list TLS or Reality security modes", lang)
			}
		}
		for _, tab := range ss.Tabs {
			if tab == "stream" || tab == "security" {
				t.Errorf("[%s] shadowsocks must NOT include '%s' tab. Got: %+v", lang, tab, ss.Tabs)
			}
		}

		// ==================== TUIC ====================
		tuic, ok := schema.Protocols[ast.ProtoTUIC]
		if !ok {
			t.Fatalf("[%s] protocol tuic missing in schema", lang)
		}
		if len(tuic.SupportedEngines) != 1 || tuic.SupportedEngines[0] != "sing-box" {
			t.Errorf("[%s] tuic SupportedEngines must only be ['sing-box'], got: %+v", lang, tuic.SupportedEngines)
		}
		for _, s := range tuic.SupportedSecurity {
			if s == "reality" {
				t.Errorf("[%s] tuic must not support reality", lang)
			}
		}
		for _, tab := range tuic.Tabs {
			if tab == "protocol" || tab == "security" {
				t.Errorf("[%s] tuic must NOT include '%s' tab. Got: %+v", lang, tab, tuic.Tabs)
			}
		}

		// ==================== TROJAN ====================
		trojan, ok := schema.Protocols[ast.ProtoTrojan]
		if !ok {
			t.Fatalf("[%s] protocol trojan missing in schema", lang)
		}
		for _, s := range trojan.SupportedSecurity {
			if s == "reality" {
				t.Errorf("[%s] trojan must NOT list reality in SupportedSecurity! Reality is VLESS-specific.", lang)
			}
		}

		// ==================== VMESS ====================
		vmess, ok := schema.Protocols[ast.ProtoVMess]
		if !ok {
			t.Fatalf("[%s] protocol vmess missing in schema", lang)
		}
		for _, s := range vmess.SupportedSecurity {
			if s == "reality" {
				t.Errorf("[%s] vmess must NOT list reality in SupportedSecurity!", lang)
			}
		}
		for _, tab := range vmess.Tabs {
			if tab == "protocol" {
				t.Errorf("[%s] vmess must NOT include 'protocol' tab. Got: %+v", lang, vmess.Tabs)
			}
		}

		// ==================== WIREGUARD ====================
		wg, ok := schema.Protocols[ast.ProtoWireGuard]
		if !ok {
			t.Fatalf("[%s] protocol wireguard missing in schema", lang)
		}
		for _, s := range wg.SupportedSecurity {
			if s == "reality" || s == "tls" {
				t.Errorf("[%s] wireguard must not list TLS or Reality security modes", lang)
			}
		}
		for _, tab := range wg.Tabs {
			if tab == "stream" || tab == "security" {
				t.Errorf("[%s] wireguard must NOT include '%s' tab. Got: %+v", lang, tab, wg.Tabs)
			}
		}
	}
}
