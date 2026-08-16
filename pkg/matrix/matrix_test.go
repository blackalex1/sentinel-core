package matrix

import (
	"strings"
	"testing"

	"github.com/blackalex1/sentinel-core/pkg/ast"
)

func TestGetCapabilities_AllCoresAndVersions(t *testing.T) {
	// 1. Xray-core
	capsXray := GetCapabilities(ast.CoreXray, "1.8.16")
	if capsXray.Core != ast.CoreXray {
		t.Errorf("expected CoreXray, got %s", capsXray.Core)
	}
	if !capsXray.IsProtocolSupported(ast.ProtoVLESS) || !capsXray.IsProtocolSupported("VLESS") {
		t.Errorf("expected VLESS supported in Xray")
	}
	if !capsXray.IsProtocolSupported(ast.ProtoVMess) || !capsXray.IsProtocolSupported(ast.ProtoTrojan) || !capsXray.IsProtocolSupported(ast.ProtoShadowsocks) || !capsXray.IsProtocolSupported(ast.ProtoWireGuard) || !capsXray.IsProtocolSupported(ast.ProtoHysteria2) || !capsXray.IsProtocolSupported(ast.ProtoSocks) || !capsXray.IsProtocolSupported(ast.ProtoHTTP) || !capsXray.IsProtocolSupported(ast.ProtoDirect) || !capsXray.IsProtocolSupported(ast.ProtoBlock) {
		t.Errorf("expected standard protocols supported in Xray")
	}
	if capsXray.IsProtocolSupported(ast.ProtoTUIC) || capsXray.IsProtocolSupported(ast.ProtoShadowTLS) {
		t.Errorf("TUIC and ShadowTLS should not be directly supported in Xray")
	}
	if !capsXray.IsFeatureSupported(FeaturePostQuantumTLS) || !capsXray.IsFeatureSupported(FeatureReality) || !capsXray.IsFeatureSupported(FeatureFlowVision) || !capsXray.IsFeatureSupported(FeatureXHTTP) || !capsXray.IsFeatureSupported(FeatureHTTPUpgrade) || !capsXray.IsFeatureSupported(FeatureMux) || !capsXray.IsFeatureSupported(FeatureRouting) || !capsXray.IsFeatureSupported(FeatureChainedInbound) {
		t.Errorf("expected Xray features supported")
	}

	// 2. Sing-box < 1.12.0
	capsSingBoxOld := GetCapabilities(ast.CoreSingBox, "1.11.4")
	if capsSingBoxOld.Core != ast.CoreSingBox {
		t.Errorf("expected CoreSingBox, got %s", capsSingBoxOld.Core)
	}
	if !capsSingBoxOld.IsProtocolSupported(ast.ProtoTUIC) || !capsSingBoxOld.IsProtocolSupported(ast.ProtoShadowTLS) || !capsSingBoxOld.IsProtocolSupported(ast.ProtoHysteria2) {
		t.Errorf("expected SingBox all-in-one protocols supported")
	}
	if capsSingBoxOld.IsFeatureSupported(FeaturePostQuantumTLS) {
		t.Errorf("SingBox should not support PostQuantumTLS by default")
	}
	if capsSingBoxOld.IsFeatureSupported(FeatureRuleSet) {
		t.Errorf("SingBox < 1.12.0 should not support binary RuleSet feature")
	}

	// 3. Sing-box >= 1.12.0
	capsSingBoxNew := GetCapabilities(ast.CoreSingBox, "1.12.0")
	if !capsSingBoxNew.IsFeatureSupported(FeatureRuleSet) {
		t.Errorf("SingBox >= 1.12.0 should support binary RuleSet feature")
	}

	// 4. Hysteria 2 Official Core
	capsHy2 := GetCapabilities(ast.CoreHysteria2, "2.2.4")
	if !capsHy2.IsProtocolSupported(ast.ProtoHysteria2) || !capsHy2.IsProtocolSupported(ast.ProtoDirect) || !capsHy2.IsProtocolSupported(ast.ProtoBlock) {
		t.Errorf("expected Hysteria2 supported in native core")
	}
	if capsHy2.IsProtocolSupported(ast.ProtoVLESS) {
		t.Errorf("VLESS should not be supported in native Hysteria2 core")
	}
	if !capsHy2.IsFeatureSupported(FeatureHysteria2) || !capsHy2.IsFeatureSupported(FeatureSalamander) || !capsHy2.IsFeatureSupported(FeaturePortHopping) {
		t.Errorf("expected Hysteria2 features supported")
	}
	if capsHy2.IsFeatureSupported(FeatureRouting) || capsHy2.IsFeatureSupported(FeatureChainedInbound) || capsHy2.IsFeatureSupported(FeatureTun) {
		t.Errorf("expected Routing/Tun not supported in native Hysteria2 client")
	}

	// 5. WireGuard Core
	capsWG := GetCapabilities(ast.CoreWireGuard, "1.0.0")
	if !capsWG.IsProtocolSupported(ast.ProtoWireGuard) {
		t.Errorf("expected WireGuard supported in WG core")
	}
	if capsWG.IsProtocolSupported(ast.ProtoVLESS) {
		t.Errorf("VLESS should not be supported in WireGuard core")
	}

	// 6. Unknown Core
	capsUnknown := GetCapabilities(ast.TargetCore("unknown-core"), "1.0.0")
	if capsUnknown == nil || len(capsUnknown.SupportedProtos) != 0 {
		t.Errorf("unexpected unknown core caps: %+v", capsUnknown)
	}
}

func TestIsVersionGe(t *testing.T) {
	tests := []struct {
		actual   string
		target   string
		expected bool
	}{
		{"", "1.12.0", true}, // Unspecified defaults to true
		{"1.12.0", "1.12.0", true},
		{"1.12.4", "1.12.0", true},
		{"1.11.4", "1.12.0", false},
		{"v1.12.0", "1.12.0", true},
		{"1.13.0", "v1.12.0", true},
		{"2.0.0", "1.12.0", true},
		{"1.0.0", "1.12.0", false},
	}

	for _, tc := range tests {
		got := isVersionGe(tc.actual, tc.target)
		if got != tc.expected {
			t.Errorf("isVersionGe(%q, %q) = %v, expected %v", tc.actual, tc.target, got, tc.expected)
		}
	}
}

func TestNegotiator_Comprehensive(t *testing.T) {
	negotiator := NewNegotiator()

	// 1. Nil profile
	_, _, err := negotiator.Negotiate(nil, ast.CoreXray, "1.8.16", false)
	if err == nil {
		t.Errorf("expected error for nil profile")
	}

	// 2. Unsupported protocol (TUIC on Xray)
	tuicNode := &ast.ServerProfile{
		Protocol: ast.ProtoTUIC,
		Address:  "tuic.server.com",
		Port:     8443,
	}
	_, _, err = negotiator.Negotiate(tuicNode, ast.CoreXray, "1.8.16", false)
	if err == nil {
		t.Errorf("expected error for unsupported TUIC on Xray")
	}

	// 3. Post-Quantum Cryptography Negotiation
	pqNode := &ast.ServerProfile{
		Name:        "PQ-Node",
		Protocol:    ast.ProtoVLESS,
		Address:     "vless.server.com",
		Port:        443,
		Security:    ast.SecurityReality,
		PublicKey:   "pubKey123",
		PostQuantum: true,
	}

	// 3a. On Xray (supports PQ) -> success without warnings
	adaptedXray, warningsXray, err := negotiator.Negotiate(pqNode, ast.CoreXray, "1.8.16", false)
	if err != nil || len(warningsXray) != 0 || !adaptedXray.PostQuantum {
		t.Errorf("expected PQ preserved on Xray: err=%v, warnings=%+v", err, warningsXray)
	}

	// 3b. On Sing-box with strictMode = true -> error
	_, _, err = negotiator.Negotiate(pqNode, ast.CoreSingBox, "1.11.4", true)
	if err == nil {
		t.Errorf("expected strict mode rejection for PQ on Sing-box")
	}

	// 3c. On Sing-box with strictMode = false -> warning and graceful downgrade
	adaptedSingBox, warningsSingBox, err := negotiator.Negotiate(pqNode, ast.CoreSingBox, "1.11.4", false)
	if err != nil {
		t.Fatalf("unexpected error on graceful PQ downgrade: %v", err)
	}
	if len(warningsSingBox) != 1 || warningsSingBox[0].Feature != FeaturePostQuantumTLS {
		t.Errorf("expected FeaturePostQuantumTLS warning: %+v", warningsSingBox)
	}
	if adaptedSingBox.PostQuantum {
		t.Errorf("expected PostQuantum to be downgraded to false on Sing-box")
	}

	// 4. Reality Security Negotiation
	realityNode := &ast.ServerProfile{
		Protocol:  ast.ProtoVLESS,
		Address:   "server.com",
		Port:      443,
		Security:  ast.SecurityReality,
		PublicKey: "pubKey123",
	}
	// Reality on Hysteria2 core -> error (unsupported protocol or unsupported reality)
	_, _, err = negotiator.Negotiate(realityNode, ast.CoreHysteria2, "2.2.4", false)
	if err == nil {
		t.Errorf("expected error for Reality/VLESS on Hysteria2 core")
	}

	// 5. XTLS Vision Flow Negotiation
	visionNode := &ast.ServerProfile{
		Protocol: ast.ProtoHysteria2,
		Address:  "hy2.server.com",
		Port:     443,
		Flow:     "xtls-rprx-vision",
	}
	// FlowVision on native Hysteria2 core (does not support FlowVision)
	// 5a. strictMode = true -> error
	_, _, err = negotiator.Negotiate(visionNode, ast.CoreHysteria2, "2.2.4", true)
	if err == nil {
		t.Errorf("expected strict mode error for Vision Flow on Hysteria2 core")
	}

	// 5b. strictMode = false -> warning and stripped flow
	adaptedVision, warningsVision, err := negotiator.Negotiate(visionNode, ast.CoreHysteria2, "2.2.4", false)
	if err != nil {
		t.Fatalf("unexpected error on flow stripping: %v", err)
	}
	if len(warningsVision) != 1 || warningsVision[0].Feature != FeatureFlowVision {
		t.Errorf("expected FeatureFlowVision warning: %+v", warningsVision)
	}
	if adaptedVision.Flow != "" {
		t.Errorf("expected Flow to be stripped, got '%s'", adaptedVision.Flow)
	}

	// 6. Test AutoNegotiate helper function
	autoNode, autoWarn, autoErr := AutoNegotiate(pqNode, ast.CoreSingBox, "1.11.4", false)
	if autoErr != nil || len(autoWarn) != 1 || autoNode.PostQuantum {
		t.Errorf("AutoNegotiate failed: node=%+v, warn=%+v, err=%v", autoNode, autoWarn, autoErr)
	}
}

func TestGetConfigurationSchema_Comprehensive(t *testing.T) {
	// 1. Russian Schema
	schemaRu := GetConfigurationSchema("ru")
	if schemaRu.Language != "ru" {
		t.Errorf("expected language ru, got %s", schemaRu.Language)
	}
	if len(schemaRu.Engines) != 3 {
		t.Errorf("expected 3 engine options, got %d", len(schemaRu.Engines))
	}
	if len(schemaRu.Protocols) < 7 {
		t.Errorf("expected at least 7 protocols in schema, got %d", len(schemaRu.Protocols))
	}
	if len(schemaRu.SniffingOptions) != 4 {
		t.Errorf("expected 4 sniffing options, got %d", len(schemaRu.SniffingOptions))
	}
	if len(schemaRu.Presets) == 0 {
		t.Errorf("expected non-empty presets list in schema")
	}

	// Verify specific protocol details in RU schema
	vlessRu, ok := schemaRu.Protocols[ast.ProtoVLESS]
	if !ok || vlessRu.DisplayName != "VLESS" || vlessRu.DefaultPort != 443 {
		t.Errorf("unexpected VLESS capability in RU schema: %+v", vlessRu)
	}
	if len(vlessRu.SupportedEngines) != 2 || len(vlessRu.SupportedSecurity) != 3 {
		t.Errorf("unexpected VLESS supported engines/security: %+v", vlessRu)
	}

	// 2. English Schema
	schemaEn := GetConfigurationSchema("en")
	if schemaEn.Language != "en" {
		t.Errorf("expected language en, got %s", schemaEn.Language)
	}
	if len(schemaEn.Engines) != 3 {
		t.Errorf("expected 3 engine options in EN schema, got %d", len(schemaEn.Engines))
	}

	vlessEn, ok := schemaEn.Protocols[ast.ProtoVLESS]
	if !ok || !strings.Contains(vlessEn.Description, "Modern") {
		t.Errorf("unexpected English description for VLESS: %+v", vlessEn)
	}

	// 3. Fallbacks: empty string and unknown languages
	schemaEmpty := GetConfigurationSchema("")
	if schemaEmpty == nil || len(schemaEmpty.Engines) == 0 {
		t.Errorf("expected valid fallback schema for empty lang")
	}

	schemaOther := GetConfigurationSchema("de")
	if schemaOther == nil || schemaOther.Language != "ru" {
		t.Errorf("expected German fallback to Russian schema")
	}
}
