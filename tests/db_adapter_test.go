package tests

import (
	"testing"
	"github.com/blackalex1/sentinel-core/pkg/adapter"
	"github.com/blackalex1/sentinel-core/pkg/ast"
	"github.com/blackalex1/sentinel-core/pkg/crypto"
)

func TestDBAdapter_EncryptedRowIngestion(t *testing.T) {
	masterSecret := "DBMasterSecret2026!"
	vault, err := crypto.NewVault(masterSecret)
	if err != nil {
		t.Fatalf("failed to create vault: %v", err)
	}

	// 1. Prepare secret parameters map
	secretParams := map[string]interface{}{
		"uuid":         "99999999-8888-7777-6666-555555555555",
		"public_key":   "REALITY_PUBLIC_KEY_XYZ",
		"short_id":     "abcdef12",
		"flow":         "xtls-rprx-vision",
		"post_quantum": true,
		"sni":          "gateway.icloud.com",
	}

	// 2. Encrypt parameters as if stored in the database
	encryptedBlob, err := vault.EncryptMap(secretParams)
	if err != nil {
		t.Fatalf("failed to encrypt map: %v", err)
	}

	// 3. Raw DB row representation
	rawDBRow := &adapter.RawDBNode{
		ID:         "node-db-001",
		Name:       "Encrypted-Node",
		Protocol:   "vless",
		Address:    "10.20.30.40",
		Port:       443,
		Transport:  "tcp",
		Security:   "reality",
		Parameters: encryptedBlob, // Encrypted payload!
	}

	// 4. Ingest and decrypt transparently
	profile, err := adapter.IngestDBNode(rawDBRow, vault)
	if err != nil {
		t.Fatalf("failed to ingest and decrypt raw DB node: %v", err)
	}

	if profile.UUID != "99999999-8888-7777-6666-555555555555" {
		t.Errorf("UUID mismatch, got: %s", profile.UUID)
	}
	if profile.PublicKey != "REALITY_PUBLIC_KEY_XYZ" {
		t.Errorf("PublicKey mismatch, got: %s", profile.PublicKey)
	}
	if !profile.PostQuantum {
		t.Errorf("expected PostQuantum to be true")
	}
	if profile.Protocol != ast.ProtoVLESS {
		t.Errorf("expected protocol vless, got: %s", profile.Protocol)
	}
}
