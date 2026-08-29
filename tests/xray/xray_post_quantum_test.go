package xray_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/blackalex1/sentinel-core/pkg/ast"
	"github.com/blackalex1/sentinel-core/pkg/builder"
	"github.com/blackalex1/sentinel-core/pkg/crypto"
	"github.com/blackalex1/sentinel-core/pkg/matrix"
	"github.com/blackalex1/sentinel-core/pkg/parser"
)

// 1. Post-Quantum TLS with ML-KEM-768 / Kyber768 Hybrid Curves in Xray
func TestXray_PostQuantum_VLESS_TLS_MLKEM(t *testing.T) {
	raw := "vless://b9f3857a-ce20-4e1e-b5e0-6f3d141fa2b2@node.pq.org:443?type=tcp&security=tls&sni=node.pq.org&fp=chrome&pq=1#PQ-TLS-Node"
	profile, err := parser.ParseURI(raw)
	if err != nil {
		t.Fatalf("failed to parse URI: %v", err)
	}

	if !profile.PostQuantum {
		t.Fatalf("expected PostQuantum to be true")
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
	stream := primary["streamSettings"].(map[string]interface{})
	tlsSettings := stream["tlsSettings"].(map[string]interface{})

	curves, ok := tlsSettings["curves"].([]interface{})
	if !ok || len(curves) == 0 {
		t.Fatalf("expected Post-Quantum hybrid curves in tlsSettings, got: %v", tlsSettings["curves"])
	}

	// Live validation with real Xray binary
	runXraySyntaxCheck(t, "Post-Quantum VLESS TLS ML-KEM", res.ConfigJSON)
	t.Logf("✅ Xray Post-Quantum TLS with ML-KEM-768/Kyber768 curves verified")
}

// 2. Post-Quantum REALITY with Hybrid Key Exchange in Xray
func TestXray_PostQuantum_VLESS_Reality_Kyber768(t *testing.T) {
	node := &ast.ServerProfile{
		Protocol:    ast.ProtoVLESS,
		Address:     "198.51.100.50",
		Port:        443,
		UUID:        "b9f3857a-ce20-4e1e-b5e0-6f3d141fa2b2",
		Transport:   "tcp",
		Security:    "reality",
		PublicKey:   "1pxvjj6jjhkkN40PM83ViQTJeC9VMDVe7oceMZuWNQY",
		SNI:         "www.apple.com",
		Flow:        "xtls-rprx-vision",
		PostQuantum: true,
		Name:        "PQ-Reality-Node",
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
	stream := primary["streamSettings"].(map[string]interface{})
	reality := stream["realitySettings"].(map[string]interface{})

	curves, ok := reality["curves"].([]interface{})
	if !ok || len(curves) == 0 {
		t.Fatalf("expected Post-Quantum curves in realitySettings, got: %v", reality["curves"])
	}

	runXraySyntaxCheck(t, "Post-Quantum VLESS Reality", res.ConfigJSON)
	t.Logf("✅ Xray Post-Quantum REALITY verified")
}

// 3. VLESS Post-Quantum Native Encryption (ML-KEM-768 0-RTT) in Xray
func TestXray_PostQuantum_VLESS_NativeEncryption(t *testing.T) {
	node := &ast.ServerProfile{
		Protocol:    ast.ProtoVLESS,
		Address:     "198.51.100.55",
		Port:        443,
		UUID:        "b9f3857a-ce20-4e1e-b5e0-6f3d141fa2b2",
		Transport:   "tcp",
		Security:    "none",
		Encryption:  "mlkem768x25519plus.native.0rtt.v1",
		PostQuantum: true,
		Name:        "VLESS-PQ-Encryption",
	}

	spec := buildClientTestSpec(node)
	res, err := builder.BuildClientConfig(spec)
	if err != nil {
		t.Fatalf("BuildClientConfig failed: %v", err)
	}

	if !strings.Contains(res.ConfigJSON, "mlkem768x25519plus.native.0rtt.v1") {
		t.Errorf("expected native ML-KEM encryption string in Xray config:\n%s", res.ConfigJSON)
	}

	runXraySyntaxCheck(t, "VLESS PQ Native Encryption", res.ConfigJSON)
	t.Logf("✅ Xray VLESS Post-Quantum Native Encryption verified")
}

// 4. Matrix Capabilities & Negotiation for Post-Quantum in Xray
func TestXray_PostQuantum_MatrixNegotiation(t *testing.T) {
	caps := matrix.GetCapabilities(ast.CoreXray, "v26.7.28")
	if !caps.IsFeatureSupported(matrix.FeaturePostQuantumTLS) {
		t.Errorf("expected FeaturePostQuantumTLS to be supported in Xray v26.7+")
	}

	node := &ast.ServerProfile{
		Protocol:    ast.ProtoVLESS,
		Address:     "198.51.100.1",
		Port:        443,
		UUID:        "b9f3857a-ce20-4e1e-b5e0-6f3d141fa2b2",
		PostQuantum: true,
	}

	adapted, warnings, err := matrix.AutoNegotiate(node, ast.CoreXray, "v26.7.28", false)
	if err != nil {
		t.Fatalf("AutoNegotiate failed: %v", err)
	}

	// Xray must retain PostQuantum = true without downgrading
	if !adapted.PostQuantum {
		t.Errorf("expected Xray to keep PostQuantum = true")
	}
	if len(warnings) != 0 {
		t.Errorf("expected 0 warnings for Xray PostQuantum, got %d", len(warnings))
	}

	t.Logf("✅ Xray Post-Quantum Matrix Negotiation verified")
}

// 5. Dynamic Post-Quantum Key Generation (ML-KEM-768 & X25519) + Live Validation
func TestXray_PostQuantum_DynamicKeyGeneration_And_LiveValidation(t *testing.T) {
	// Dynamically generate real Post-Quantum ML-KEM-768 key pairs using our native Go crypto module
	pqKeys, err := crypto.GenerateVlessEncKeys()
	if err != nil {
		t.Fatalf("crypto.GenerateVlessEncKeys failed: %v", err)
	}

	if !strings.HasPrefix(pqKeys.MLKEM768.Encryption, "mlkem768x25519plus.native.0rtt.") {
		t.Fatalf("unexpected generated ML-KEM-768 encryption key: %s", pqKeys.MLKEM768.Encryption)
	}
	if !strings.HasPrefix(pqKeys.MLKEM768.Decryption, "mlkem768x25519plus.native.600s.") {
		t.Fatalf("unexpected generated ML-KEM-768 decryption key: %s", pqKeys.MLKEM768.Decryption)
	}

	// Dynamically generate Reality X25519 KeyPair
	realityKeys, err := crypto.GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("crypto.GenerateX25519KeyPair failed: %v", err)
	}

	// Construct dynamic client profile
	clientNode := &ast.ServerProfile{
		Protocol:    ast.ProtoVLESS,
		Address:     "198.51.100.77",
		Port:        443,
		UUID:        crypto.GenerateRandomUUID(),
		Transport:   "tcp",
		Security:    "reality",
		PublicKey:   realityKeys.PublicKey,
		SNI:         "www.cloudflare.com",
		Flow:        "xtls-rprx-vision",
		Encryption:  pqKeys.MLKEM768.Encryption,
		PostQuantum: true,
		Name:        "Dynamic-PQ-Reality-Client",
	}

	spec := buildClientTestSpec(clientNode)
	res, err := builder.BuildClientConfig(spec)
	if err != nil {
		t.Fatalf("failed to build client config with dynamically generated PQ keys: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(res.ConfigJSON), &parsed); err != nil {
		t.Fatalf("invalid JSON generated: %v", err)
	}

	outbounds := parsed["outbounds"].([]interface{})
	primary := outbounds[0].(map[string]interface{})
	stream := primary["streamSettings"].(map[string]interface{})
	reality := stream["realitySettings"].(map[string]interface{})

	curves, ok := reality["curves"].([]interface{})
	if !ok || len(curves) == 0 {
		t.Fatalf("expected dynamically injected Post-Quantum curves, got: %v", reality["curves"])
	}

	// Verify live syntax with real Xray binary
	runXraySyntaxCheck(t, "Dynamic Post-Quantum KeyGen & Live Validation", res.ConfigJSON)
	t.Logf("✅ Dynamically generated ML-KEM-768 & Reality X25519 keys compiled & verified with real Xray")
}
