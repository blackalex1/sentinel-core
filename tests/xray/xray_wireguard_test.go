package xray_test

import (
	"encoding/json"
	"testing"

	"github.com/blackalex1/sentinel-core/pkg/ast"
	"github.com/blackalex1/sentinel-core/pkg/builder"
)

// 1. Native WireGuard Outbound in Xray
func TestXray_WireGuard_Outbound(t *testing.T) {
	// Standard 32-byte Base64 WireGuard Keys
	valid32Key := "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="

	node := &ast.ServerProfile{
		Protocol:      ast.ProtoWireGuard,
		Address:       "198.51.100.99",
		Port:          51820,
		PrivateKey:    valid32Key,
		PeerPublicKey: valid32Key,
		PreSharedKey:  valid32Key,
		LocalAddress:  []string{"10.0.0.2/32", "fd00::2/128"},
		ReservedBytes: []int{0, 1, 2},
		MTU:           1420,
		Name:          "WireGuard-Xray-Outbound",
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
	if primary["protocol"] != "wireguard" {
		t.Fatalf("expected protocol wireguard, got %v", primary["protocol"])
	}

	runXraySyntaxCheck(t, "WireGuard Outbound in Xray", res.ConfigJSON)
	t.Logf("✅ Xray WireGuard Outbound passed live verification")
}
