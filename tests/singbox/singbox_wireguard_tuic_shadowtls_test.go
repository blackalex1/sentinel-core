package singbox_test

import (
	"encoding/json"
	"testing"

	"github.com/blackalex1/sentinel-core/pkg/ast"
	"github.com/blackalex1/sentinel-core/pkg/builder"
)

// 1. Native WireGuard Outbound in Sing-box
func TestSingbox_WireGuard_Outbound(t *testing.T) {
	valid32Key := "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="

	node := &ast.ServerProfile{
		Protocol:      ast.ProtoWireGuard,
		Address:       "198.51.100.50",
		Port:          51820,
		PrivateKey:    valid32Key,
		PeerPublicKey: valid32Key,
		PreSharedKey:  valid32Key,
		LocalAddress:  []string{"10.0.0.2/32", "fd00::2/128"},
		ReservedBytes: []int{0, 1, 2},
		MTU:           1420,
		Name:          "WireGuard-Singbox-Outbound",
	}

	spec := buildClientTestSpec(node)
	res, err := builder.BuildClientConfig(spec)
	if err != nil {
		t.Fatalf("BuildClientConfig failed: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(res.ConfigJSON), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	endpoints, hasEndpoints := parsed["endpoints"].([]interface{})
	if !hasEndpoints || len(endpoints) == 0 {
		t.Fatalf("expected endpoints in sing-box config: %v", parsed)
	}

	ep := endpoints[0].(map[string]interface{})
	if ep["type"] != "wireguard" {
		t.Fatalf("expected endpoint type wireguard, got %v", ep["type"])
	}

	runSingboxSyntaxCheck(t, "WireGuard Outbound in Sing-box", res.ConfigJSON)
	t.Logf("✅ Sing-box WireGuard Outbound passed live verification")
}

// 2. TUIC Outbound in Sing-box (v5 protocol)
func TestSingbox_TUIC_Outbound(t *testing.T) {
	node := &ast.ServerProfile{
		Protocol:          ast.ProtoTUIC,
		Address:           "198.51.100.51",
		Port:              8443,
		UUID:              "b9f3857a-ce20-4e1e-b5e0-6f3d141fa2b2",
		Password:          "tuicPassword123",
		CongestionControl: "bbr",
		UDPRelayMode:      "native",
		ZeroRTTHandshake:  true,
		SNI:               "tuic.example.com",
		Insecure:          true,
		Name:              "TUIC-Singbox-Outbound",
	}

	spec := buildClientTestSpec(node)
	res, err := builder.BuildClientConfig(spec)
	if err != nil {
		t.Fatalf("BuildClientConfig failed: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(res.ConfigJSON), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	outbounds := parsed["outbounds"].([]interface{})
	primary := outbounds[0].(map[string]interface{})
	if primary["type"] != "tuic" {
		t.Fatalf("expected outbound type tuic, got %v", primary["type"])
	}

	runSingboxSyntaxCheck(t, "TUIC Outbound in Sing-box", res.ConfigJSON)
	t.Logf("✅ Sing-box TUIC Outbound passed live verification")
}

// 3. ShadowTLS Outbound in Sing-box (v3 protocol)
func TestSingbox_ShadowTLS_Outbound(t *testing.T) {
	node := &ast.ServerProfile{
		Protocol:         ast.ProtoShadowTLS,
		Address:          "198.51.100.52",
		Port:             443,
		Password:         "shadowtlsSecretPass",
		ShadowTLSVersion: 3,
		SNI:              "www.microsoft.com",
		Name:             "ShadowTLS-Singbox-Outbound",
	}

	spec := buildClientTestSpec(node)
	res, err := builder.BuildClientConfig(spec)
	if err != nil {
		t.Fatalf("BuildClientConfig failed: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(res.ConfigJSON), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	outbounds := parsed["outbounds"].([]interface{})
	primary := outbounds[0].(map[string]interface{})
	if primary["type"] != "shadowtls" {
		t.Fatalf("expected outbound type shadowtls, got %v", primary["type"])
	}

	runSingboxSyntaxCheck(t, "ShadowTLS Outbound in Sing-box", res.ConfigJSON)
	t.Logf("✅ Sing-box ShadowTLS Outbound passed live verification")
}
