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

		// ==================== ENGINE SPECIFICITY (INBOUND & OUTBOUND) ====================
		if !sliceContains(vless.EngineTransports["xray-core"], "xhttp") {
			t.Errorf("[%s] vless inbound xray-core must support xhttp", lang)
		}
		if sliceContains(vless.EngineTransports["sing-box"], "xhttp") || sliceContains(vless.EngineTransports["sing-box"], "mkcp") {
			t.Errorf("[%s] vless inbound sing-box must not list xhttp or mkcp", lang)
		}

		obVless, ok := schema.OutboundProtocols[ast.ProtoVLESS]
		if !ok {
			t.Fatalf("[%s] outbound vless missing", lang)
		}
		if !sliceContains(obVless.EngineTransports["xray-core"], "xhttp") || sliceContains(obVless.EngineTransports["sing-box"], "xhttp") {
			t.Errorf("[%s] outbound vless EngineTransports mismatch: %+v", lang, obVless.EngineTransports)
		}
		if len(obVless.EngineFingerprints["xray-core"]) == 0 || sliceContains(obVless.EngineFingerprints["xray-core"], "opera") {
			t.Errorf("[%s] outbound vless EngineFingerprints invalid: %+v", lang, obVless.EngineFingerprints)
		}

		var foundFlow, foundEnc, foundXhttpMode, foundMultiMode bool
		for _, tab := range obVless.TabDefinitions {
			for _, grp := range tab.Groups {
				for _, f := range grp.Fields {
					switch f.ID {
					case "ob-flow":
						foundFlow = true
						if len(f.ShowIf) == 0 {
							t.Errorf("[%s] ob-flow must have ShowIf constraints", lang)
						}
					case "ob-vless-encryption":
						foundEnc = true
						if len(f.SupportedEngines) != 1 || f.SupportedEngines[0] != "xray-core" {
							t.Errorf("[%s] ob-vless-encryption must be xray-core only, got %+v", lang, f.SupportedEngines)
						}
					case "ob-xhttp-mode":
						foundXhttpMode = true
						if len(f.SupportedEngines) != 1 || f.SupportedEngines[0] != "xray-core" {
							t.Errorf("[%s] ob-xhttp-mode must be xray-core only, got %+v", lang, f.SupportedEngines)
						}
					case "ob-grpc-multi-mode":
						foundMultiMode = true
						if len(f.SupportedEngines) != 1 || f.SupportedEngines[0] != "xray-core" {
							t.Errorf("[%s] ob-grpc-multi-mode must be xray-core only, got %+v", lang, f.SupportedEngines)
						}
					}
				}
			}
		}
		if !foundFlow || !foundEnc || !foundXhttpMode || !foundMultiMode {
			t.Errorf("[%s] outbound vless missing expected fields (flow=%v enc=%v xhttp=%v multi=%v)", lang, foundFlow, foundEnc, foundXhttpMode, foundMultiMode)
		}

		obTuic, ok := schema.OutboundProtocols[ast.ProtoTUIC]
		if !ok || len(obTuic.SupportedEngines) != 1 || obTuic.SupportedEngines[0] != "sing-box" {
			t.Errorf("[%s] outbound tuic missing or wrong engines: %+v", lang, obTuic.SupportedEngines)
		}
		obShadowTLS, ok := schema.OutboundProtocols[ast.ProtoShadowTLS]
		if !ok || len(obShadowTLS.SupportedEngines) != 1 || obShadowTLS.SupportedEngines[0] != "sing-box" {
			t.Errorf("[%s] outbound shadowtls missing or wrong engines: %+v", lang, obShadowTLS.SupportedEngines)
		}
	}
}

func sliceContains(items []string, target string) bool {
	for _, it := range items {
		if it == target {
			return true
		}
	}
	return false
}

func assertExactEngines(t *testing.T, context string, got []string, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Errorf("%s: expected SupportedEngines %v, got %v", context, want, got)
		return
	}
	for _, w := range want {
		if !sliceContains(got, w) {
			t.Errorf("%s: missing engine %q in %v (want %v)", context, w, got, want)
		}
	}
}

func checkSingleEngineMention(t *testing.T, context, text string, supportedEngines []string, parentEngines []string) {
	t.Helper()
	if text == "" {
		return
	}
	lower := strings.ToLower(text)
	xrayOnly := strings.Contains(lower, "только xray") || strings.Contains(lower, "только для xray") || strings.Contains(lower, "xray only") || strings.Contains(lower, "only for xray")
	sbOnly := strings.Contains(lower, "только sing-box") || strings.Contains(lower, "только для sing-box") || strings.Contains(lower, "sing-box only") || strings.Contains(lower, "only for sing-box")

	effective := supportedEngines
	if len(effective) == 0 {
		effective = parentEngines
	}
	if xrayOnly && !(len(effective) == 1 && effective[0] == "xray-core") {
		t.Errorf("%s: text %q claims Xray-only but effective SupportedEngines=%v", context, text, effective)
	}
	if sbOnly && !(len(effective) == 1 && effective[0] == "sing-box") {
		t.Errorf("%s: text %q claims Sing-box-only but effective SupportedEngines=%v", context, text, effective)
	}
}

// TestStrictEngineIsolationAndCapabilities verifies that no engine-specific field, option, tab,
// or hint/instruction leaks across cores that do not implement that capability.
func TestStrictEngineIsolationAndCapabilities(t *testing.T) {
	for _, lang := range []string{"ru", "en"} {
		schema := GetConfigurationSchema(lang)
		if schema == nil {
			t.Fatalf("[%s] schema is nil", lang)
		}

		sections := []struct {
			name  string
			items map[string]types.ProtocolCapability
		}{
			{"inbound", schema.Protocols},
			{"outbound", schema.OutboundProtocols},
		}

		for _, sec := range sections {
			for proto, capDef := range sec.items {
				protoEngines := capDef.SupportedEngines
				for _, tab := range capDef.TabDefinitions {
					tabEngines := tab.SupportedEngines
					if len(tabEngines) == 0 {
						tabEngines = protoEngines
					}
					checkSingleEngineMention(t, lang+"/"+sec.name+"/"+proto+"/tab:"+tab.ID, tab.Title, tab.SupportedEngines, protoEngines)

					if sec.name == "inbound" && proto == "hysteria2" && tab.ID == "sniffing" {
						assertExactEngines(t, lang+"/inbound/hysteria2/tab:sniffing", tab.SupportedEngines, []string{"sing-box"})
					}

					for _, grp := range tab.Groups {
						grpEngines := grp.SupportedEngines
						if len(grpEngines) == 0 {
							grpEngines = tabEngines
						}
						checkSingleEngineMention(t, lang+"/"+sec.name+"/"+proto+"/group:"+grp.Title, grp.Title, grp.SupportedEngines, tabEngines)
						checkSingleEngineMention(t, lang+"/"+sec.name+"/"+proto+"/group-desc:"+grp.Title, grp.Description, grp.SupportedEngines, tabEngines)

						for _, f := range grp.Fields {
							fieldEngines := f.SupportedEngines
							if len(fieldEngines) == 0 {
								fieldEngines = grpEngines
							}
							ctx := lang + "/" + sec.name + "/" + proto + "/field:" + f.ID + "(" + f.TargetField + ")"
							checkSingleEngineMention(t, ctx+"/label", f.Label, f.SupportedEngines, grpEngines)
							checkSingleEngineMention(t, ctx+"/helptext", f.HelpText, f.SupportedEngines, grpEngines)

							switch f.TargetField {
							case "streamSettings.realitySettings.spiderX", "spiderX",
								"xhttpMode", "streamSettings.xhttpSettings.mode", "streamSettings.xhttpSettings.path",
								"multiMode", "streamSettings.grpcSettings.multiMode",
								"headerType", "encryption", "settings.encryption",
								"decryption", "settings.decryption", "streamSettings.vlessDecryption",
								"fallbacks", "settings.fallbacks.0.dest", "settings.fallbacks.0.path", "settings.fallbacks.0.xver", "settings.fallbacks.0.alpn":
								assertExactEngines(t, ctx, fieldEngines, []string{"xray-core"})
							}

							if sec.name == "outbound" && proto == "hysteria2" {
								switch f.TargetField {
								case "upMbps", "downMbps":
									assertExactEngines(t, ctx, fieldEngines, []string{"hysteria2", "sing-box"})
								case "pinnedPeerCertSha256":
									assertExactEngines(t, ctx, fieldEngines, []string{"xray-core", "hysteria2"})
								}
							}

							if sec.name == "outbound" && (proto == "tuic" || proto == "shadowtls") {
								assertExactEngines(t, ctx, fieldEngines, []string{"sing-box"})
							}

							for _, opt := range f.Options {
								optCtx := ctx + "/opt:" + opt.Value
								checkSingleEngineMention(t, optCtx+"/label", opt.Label, opt.SupportedEngines, fieldEngines)
								checkSingleEngineMention(t, optCtx+"/desc", opt.Description, opt.SupportedEngines, fieldEngines)
								switch opt.Value {
								case "xhttp", "mkcp", "xtls-rprx-vision-udp443", "xchacha20-ietf-poly1305":
									assertExactEngines(t, optCtx, opt.SupportedEngines, []string{"xray-core"})
								case "h2":
									if f.TargetField == "network" || f.TargetField == "streamSettings.network" {
										assertExactEngines(t, optCtx, opt.SupportedEngines, []string{"sing-box"})
									}
								}
							}
						}
					}
				}
			}
		}
	}
}
