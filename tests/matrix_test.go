package tests

import (
	"strings"
	"testing"
	"github.com/blackalex1/sentinel-core/pkg/ast"
	"github.com/blackalex1/sentinel-core/pkg/builder"
	"github.com/blackalex1/sentinel-core/pkg/matrix"
)

func TestMatrix_PostQuantum_Xray(t *testing.T) {
	node := &ast.ServerProfile{
		Name:        "PQ-Xray-Node",
		Protocol:    ast.ProtoVLESS,
		Address:     "198.51.100.1",
		Port:        443,
		UUID:        "test-uuid",
		Security:    ast.SecurityReality,
		PublicKey:   "test-pubkey",
		PostQuantum: true,
	}

	spec := &ast.ConfigSpec{
		TargetCore: ast.CoreXray,
		ServerNode: node,
	}

	res, err := builder.BuildClientConfig(spec)
	if err != nil {
		t.Fatalf("failed to build xray config: %v", err)
	}

	// Verify Post-Quantum Kyber curves are included in Xray output
	if !strings.Contains(res.ConfigJSON, "X25519Kyber768Draft00") {
		t.Fatalf("expected Xray config to contain X25519Kyber768Draft00, got:\n%s", res.ConfigJSON)
	}
}

func TestMatrix_PostQuantum_SingBox_GracefulFallback(t *testing.T) {
	node := &ast.ServerProfile{
		Name:        "PQ-Singbox-Node",
		Protocol:    ast.ProtoVLESS,
		Address:     "198.51.100.1",
		Port:        443,
		UUID:        "test-uuid",
		Security:    ast.SecurityReality,
		PublicKey:   "test-pubkey",
		PostQuantum: true,
	}

	spec := &ast.ConfigSpec{
		TargetCore: ast.CoreSingBox,
		ServerNode: node,
		StrictMode: false, // Graceful fallback
	}

	res, err := builder.BuildClientConfig(spec)
	if err != nil {
		t.Fatalf("failed to build singbox config: %v", err)
	}

	// Should have emitted a negotiation warning
	if len(res.Warnings) == 0 {
		t.Fatalf("expected at least 1 warning for post-quantum fallback, got 0")
	}

	foundPQWarning := false
	for _, w := range res.Warnings {
		if w.Feature == matrix.FeaturePostQuantumTLS {
			foundPQWarning = true
			break
		}
	}
	if !foundPQWarning {
		t.Fatalf("expected FeaturePostQuantumTLS warning, got: %v", res.Warnings)
	}

	// The generated config must still be valid JSON
	if !strings.Contains(res.ConfigJSON, "reality") {
		t.Fatalf("expected singbox config to still have reality, got:\n%s", res.ConfigJSON)
	}
}

func TestMatrix_PostQuantum_SingBox_StrictMode(t *testing.T) {
	node := &ast.ServerProfile{
		Name:        "PQ-Singbox-Node",
		Protocol:    ast.ProtoVLESS,
		Address:     "198.51.100.1",
		Port:        443,
		UUID:        "test-uuid",
		Security:    ast.SecurityReality,
		PublicKey:   "test-pubkey",
		PostQuantum: true,
	}

	spec := &ast.ConfigSpec{
		TargetCore: ast.CoreSingBox,
		ServerNode: node,
		StrictMode: true, // Strict mode must fail
	}

	_, err := builder.BuildClientConfig(spec)
	if err == nil {
		t.Fatalf("expected strict mode failure on unsupported post-quantum feature, but got success")
	}
}
