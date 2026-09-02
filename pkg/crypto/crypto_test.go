package crypto

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestVault_EncryptDecrypt(t *testing.T) {
	secret := "MySuperSecureMasterSecretKey123!"
	vault, err := NewVault(secret)
	if err != nil {
		t.Fatalf("failed to create vault: %v", err)
	}

	plaintext := "vless://a6c8e874-1234-5678-abcd@198.51.100.1:443?security=reality"
	encrypted, err := vault.EncryptString(plaintext)
	if err != nil {
		t.Fatalf("failed to encrypt string: %v", err)
	}

	if !IsEncrypted(encrypted) {
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

func TestVault_EmptySecret(t *testing.T) {
	_, err := NewVault("")
	if err == nil {
		t.Fatalf("expected error creating vault with empty secret")
	}
}

func TestVault_NewVaultWithKey(t *testing.T) {
	// Invalid key lengths
	_, err := NewVaultWithKey([]byte("short-key"))
	if err == nil {
		t.Fatalf("expected error for key length != 32")
	}

	_, err = NewVaultWithKey(make([]byte, 64))
	if err == nil {
		t.Fatalf("expected error for 64-byte key")
	}

	// Valid 32-byte key
	validKey := make([]byte, 32)
	for i := range validKey {
		validKey[i] = byte(i + 1)
	}
	vault, err := NewVaultWithKey(validKey)
	if err != nil {
		t.Fatalf("failed to create vault with 32-byte key: %v", err)
	}

	enc, err := vault.EncryptString("test-secret-with-raw-key")
	if err != nil {
		t.Fatalf("encryption failed: %v", err)
	}
	dec, err := vault.DecryptString(enc)
	if err != nil || dec != "test-secret-with-raw-key" {
		t.Fatalf("decryption failed or mismatch: %s, err=%v", dec, err)
	}
}

func TestVault_WrongKey(t *testing.T) {
	vault1, _ := NewVault("CorrectSecretKey123")
	vault2, _ := NewVault("WrongSecretKey456")

	encrypted, err := vault1.EncryptString("secret-node-data")
	if err != nil {
		t.Fatalf("encryption failed: %v", err)
	}

	_, err = vault2.DecryptString(encrypted)
	if err == nil {
		t.Fatalf("expected decryption failure with wrong key, but got success")
	}
}

func TestVault_TamperDetection(t *testing.T) {
	vault, _ := NewVault("TamperTestSecret")
	encrypted, _ := vault.EncryptString("original-payload")

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

func TestVault_MapEncryption(t *testing.T) {
	vault, _ := NewVault("MapTestSecret")

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

	// Decrypt invalid JSON map
	encInvalidJSON, err := vault.EncryptString("this is not json")
	if err != nil {
		t.Fatalf("encryption failed: %v", err)
	}
	_, err = vault.DecryptMap(encInvalidJSON)
	if err == nil {
		t.Fatalf("expected error decrypting non-JSON string into map")
	}
}

func TestCipher_ErrorsAndEdgeCases(t *testing.T) {
	// Key length errors
	_, err := EncryptAEAD([]byte("hello"), []byte("short"))
	if err == nil {
		t.Errorf("expected error with short key")
	}

	_, err = DecryptAEAD(EncryptedPayloadHeader+"test", []byte("short"))
	if err == nil {
		t.Errorf("expected error with short key")
	}

	// Missing header prefix
	key := make([]byte, 32)
	_, err = DecryptAEAD("invalid_header_payload", key)
	if err == nil || !strings.Contains(err.Error(), "missing") {
		t.Errorf("expected missing header error, got: %v", err)
	}

	// Invalid base64
	_, err = DecryptAEAD(EncryptedPayloadHeader+"???invalid_b64???", key)
	if err == nil {
		t.Errorf("expected base64 decode error")
	}

	// Ciphertext too short (< 12 bytes nonce)
	shortB64 := base64.RawURLEncoding.EncodeToString([]byte("short"))
	_, err = DecryptAEAD(EncryptedPayloadHeader+shortB64, key)
	if err == nil || !strings.Contains(err.Error(), "too short") {
		t.Errorf("expected too short error, got: %v", err)
	}
}

func TestKDF_PBKDF2(t *testing.T) {
	// Empty secret error
	_, err := DeriveKeyFromSecret("")
	if err == nil {
		t.Fatalf("expected error for empty secret")
	}

	// Valid derivation
	k1, err := DeriveKeyFromSecret("my-password-123")
	if err != nil || len(k1) != 32 {
		t.Fatalf("expected 32-byte key, got len %d, err: %v", len(k1), err)
	}

	// Negative iterations & empty salt defaults
	k2 := DeriveKeyPBKDF2("my-password-123", nil, -1)
	if len(k2) != 32 {
		t.Fatalf("expected 32-byte key, got len %d", len(k2))
	}

	// Custom salt and iterations
	k3 := DeriveKeyPBKDF2("my-password-123", []byte("custom-salt-123"), 1000)
	if len(k3) != 32 {
		t.Fatalf("expected 32-byte key, got len %d", len(k3))
	}
}

func TestIsEncrypted(t *testing.T) {
	if IsEncrypted("plain-string") {
		t.Errorf("plain-string should not be encrypted")
	}
	if IsEncrypted("") {
		t.Errorf("empty string should not be encrypted")
	}
	if !IsEncrypted(EncryptedPayloadHeader + "xyz123") {
		t.Errorf("string with header should be encrypted")
	}
}

func TestGenerateX25519KeyPair(t *testing.T) {
	kp, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("failed to generate X25519 keypair: %v", err)
	}
	if kp.PrivateKey == "" || kp.PublicKey == "" {
		t.Fatalf("expected non-empty keypair, got: %+v", kp)
	}
}

func TestGenerateVlessEncKeys(t *testing.T) {
	keys, err := GenerateVlessEncKeys()
	if err != nil {
		t.Fatalf("failed to generate VLESS Encryption keys: %v", err)
	}
	if keys.X25519.Decryption == "" || keys.X25519.Encryption == "" {
		t.Fatalf("expected non-empty X25519 vlessenc keys, got: %+v", keys.X25519)
	}
	if keys.MLKEM768.Decryption == "" || keys.MLKEM768.Encryption == "" {
		t.Fatalf("expected non-empty ML-KEM-768 vlessenc keys, got: %+v", keys.MLKEM768)
	}
}
