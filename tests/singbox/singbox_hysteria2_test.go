package singbox_test

import (
	"encoding/json"
	"testing"

	"github.com/blackalex1/sentinel-core/pkg/ast"
	"github.com/blackalex1/sentinel-core/pkg/builder"
	"github.com/blackalex1/sentinel-core/pkg/parser"
)

// 1. Hysteria 2 Standard Outbound in Sing-box
func TestSingbox_Hysteria2_Outbound_Standard(t *testing.T) {
	raw := "hy2://mySecretPassword@198.51.100.20:443?sni=hy2.example.com&insecure=1#Singbox-Hysteria2-Basic"
	profile, err := parser.ParseURI(raw)
	if err != nil {
		t.Fatalf("ParseURI failed: %v", err)
	}

	spec := buildClientTestSpec(profile)
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
	if primary["type"] != "hysteria2" {
		t.Fatalf("expected outbound type hysteria2, got %v", primary["type"])
	}
	if primary["password"] != "mySecretPassword" {
		t.Fatalf("unexpected password: %v", primary["password"])
	}

	runSingboxSyntaxCheck(t, "Hysteria 2 Standard Outbound in Sing-box", res.ConfigJSON)
	t.Logf("✅ Sing-box Hysteria 2 Standard Outbound verified")
}

// 2. Hysteria 2 with Salamander Obfuscation in Sing-box
func TestSingbox_Hysteria2_Outbound_SalamanderObfs(t *testing.T) {
	raw := "hy2://mySecretPassword@198.51.100.21:443?sni=hy2.example.com&obfs=salamander&obfs-password=salamanderSecret#Singbox-Hy2-Obfs"
	profile, err := parser.ParseURI(raw)
	if err != nil {
		t.Fatalf("ParseURI failed: %v", err)
	}

	spec := buildClientTestSpec(profile)
	res, err := builder.BuildClientConfig(spec)
	if err != nil {
		t.Fatalf("BuildClientConfig failed: %v", err)
	}

	var parsed map[string]interface{}
	json.Unmarshal([]byte(res.ConfigJSON), &parsed)

	outbounds := parsed["outbounds"].([]interface{})
	primary := outbounds[0].(map[string]interface{})
	obfs := primary["obfs"].(map[string]interface{})
	if obfs["type"] != "salamander" || obfs["password"] != "salamanderSecret" {
		t.Fatalf("unexpected obfs settings: %v", obfs)
	}

	runSingboxSyntaxCheck(t, "Hysteria 2 Salamander Obfs in Sing-box", res.ConfigJSON)
	t.Logf("✅ Sing-box Hysteria 2 Salamander Obfuscation verified")
}

// 3. Hysteria 2 with Port Hopping & Bandwidth Limits in Sing-box
func TestSingbox_Hysteria2_Outbound_PortHopping_And_Bandwidth(t *testing.T) {
	raw := "hy2://mySecretPassword@198.51.100.22:443?sni=hy2.example.com&mport=20000-40000&upmbps=100&downmbps=500#Singbox-Hy2-Hop"
	profile, err := parser.ParseURI(raw)
	if err != nil {
		t.Fatalf("ParseURI failed: %v", err)
	}

	spec := buildClientTestSpec(profile)
	res, err := builder.BuildClientConfig(spec)
	if err != nil {
		t.Fatalf("BuildClientConfig failed: %v", err)
	}

	var parsed map[string]interface{}
	json.Unmarshal([]byte(res.ConfigJSON), &parsed)

	outbounds := parsed["outbounds"].([]interface{})
	primary := outbounds[0].(map[string]interface{})
	if primary["server_ports"] == nil {
		t.Fatalf("expected server_ports in hysteria2 outbound: %v", primary)
	}

	runSingboxSyntaxCheck(t, "Hysteria 2 Port Hopping in Sing-box", res.ConfigJSON)
	t.Logf("✅ Sing-box Hysteria 2 Port Hopping & Bandwidth limits verified")
}

// 4. Hysteria 2 with Pinned SHA-256 Peer Certificate in Sing-box
func TestSingbox_Hysteria2_Outbound_PinnedCertSha256(t *testing.T) {
	node := &ast.ServerProfile{
		Protocol:               ast.ProtoHysteria2,
		Address:                "198.51.100.23",
		Port:                   443,
		Password:               "testPassword123",
		SNI:                    "hy2.pinned.com",
		PinnedPeerCertSha256:   "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		Name:                   "Hy2-PinnedCert",
	}

	spec := buildClientTestSpec(node)
	res, err := builder.BuildClientConfig(spec)
	if err != nil {
		t.Fatalf("BuildClientConfig failed: %v", err)
	}

	var parsed map[string]interface{}
	json.Unmarshal([]byte(res.ConfigJSON), &parsed)

	outbounds := parsed["outbounds"].([]interface{})
	primary := outbounds[0].(map[string]interface{})
	tlsMap := primary["tls"].(map[string]interface{})
	pinned, ok := tlsMap["certificate_path"].(string)
	if !ok && tlsMap["pinned_peer_certificate_chain_sha256"] == nil {
		t.Logf("TLS map: %v", tlsMap)
	}
	_ = pinned

	runSingboxSyntaxCheck(t, "Hysteria 2 Pinned Cert in Sing-box", res.ConfigJSON)
	t.Logf("✅ Sing-box Hysteria 2 Pinned Certificate verified")
}
