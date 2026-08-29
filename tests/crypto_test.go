package tests

import (
	"testing"
	"github.com/blackalex1/sentinel-core/pkg/crypto"
)

func TestCryptoVault_EncryptDecrypt(t *testing.T) {
	secret := "MySuperSecureMasterSecretKey123!"
	vault, err := crypto.NewVault(secret)
	if err != nil {
		t.Fatalf("failed to create vault: %v", err)
	}

	plaintext := "vless://a6c8e874-1234-5678-abcd@198.51.100.1:443?security=reality"
	encrypted, err := vault.EncryptString(plaintext)
	if err != nil {
		t.Fatalf("failed to encrypt string: %v", err)
	}

	if !crypto.IsEncrypted(encrypted) {
		t.Fatalf("expected encrypted header, got: %s", encrypted)
	}

	decrypted, err := vault.DecryptString(encrypted)
	if err != nil {
		t.Fatalf("failed to decrypt string: %v", err)
	}

	if decrypted != plaintext {
		t.Fatalf("expected decrypted '%s', got '%s'", plaintext, decrypted)
	}
}

func TestCryptoVault_WrongKey(t *testing.T) {
	vault1, _ := crypto.NewVault("CorrectSecretKey123")
	vault2, _ := crypto.NewVault("WrongSecretKey456")

	encrypted, err := vault1.EncryptString("secret-node-data")
	if err != nil {
		t.Fatalf("encryption failed: %v", err)
	}

	_, err = vault2.DecryptString(encrypted)
	if err == nil {
		t.Fatalf("expected decryption failure with wrong key, but got success")
	}
}

func TestCryptoVault_TamperDetection(t *testing.T) {
	vault, _ := crypto.NewVault("TamperTestSecret")
	encrypted, _ := vault.EncryptString("original-payload")

	// Corrupt one byte in the base64 ciphertext
	chars := []rune(encrypted)
	if chars[len(chars)-2] == 'A' {
		chars[len(chars)-2] = 'B'
	} else {
		chars[len(chars)-2] = 'A'
	}
	corrupted := string(chars)

	_, err := vault.DecryptString(corrupted)
	if err == nil {
		t.Fatalf("expected authentication tag failure on tampered ciphertext, but succeeded")
	}
}

func TestCryptoVault_MapEncryption(t *testing.T) {
	vault, _ := crypto.NewVault("MapTestSecret")

	params := map[string]interface{}{
		"uuid":         "uuid-1234-5678",
		"public_key":   "pubkey-abcdef",
		"post_quantum": true,
		"flow":         "xtls-rprx-vision",
	}

	enc, err := vault.EncryptMap(params)
	if err != nil {
		t.Fatalf("failed to encrypt map: %v", err)
	}

	dec, err := vault.DecryptMap(enc)
	if err != nil {
		t.Fatalf("failed to decrypt map: %v", err)
	}

	if dec["uuid"] != "uuid-1234-5678" || dec["public_key"] != "pubkey-abcdef" {
		t.Fatalf("decrypted map contents mismatch: %v", dec)
	}
}
