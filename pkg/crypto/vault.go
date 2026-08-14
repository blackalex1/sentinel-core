package crypto

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Vault handles encrypting and decrypting sensitive database records and parameter blobs.
type Vault struct {
	key []byte
}

// NewVault creates a new Vault instance with a derived 32-byte key.
func NewVault(masterSecret string) (*Vault, error) {
	key, err := DeriveKeyFromSecret(masterSecret)
	if err != nil {
		return nil, err
	}
	return &Vault{key: key}, nil
}

// NewVaultWithKey creates a Vault instance directly with a 32-byte key.
func NewVaultWithKey(key []byte) (*Vault, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("vault key must be exactly 32 bytes, got %d", len(key))
	}
	return &Vault{key: key}, nil
}

// EncryptMap serializes a map of parameters to JSON and encrypts it with AEAD.
func (v *Vault) EncryptMap(data map[string]interface{}) (string, error) {
	jsonBytes, err := json.Marshal(data)
	if err != nil {
		return "", fmt.Errorf("failed to serialize data map to JSON: %w", err)
	}
	return EncryptAEAD(jsonBytes, v.key)
}

// DecryptMap decrypts an AEAD encrypted payload string and deserializes it back to a map.
func (v *Vault) DecryptMap(encryptedPayload string) (map[string]interface{}, error) {
	decryptedBytes, err := DecryptAEAD(encryptedPayload, v.key)
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(decryptedBytes, &result); err != nil {
		return nil, fmt.Errorf("failed to parse decrypted JSON map: %w", err)
	}
	return result, nil
}

// EncryptString encrypts a single plaintext string.
func (v *Vault) EncryptString(plaintext string) (string, error) {
	return EncryptAEAD([]byte(plaintext), v.key)
}

// DecryptString decrypts an encrypted string.
func (v *Vault) DecryptString(encryptedStr string) (string, error) {
	bytes, err := DecryptAEAD(encryptedStr, v.key)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

// IsEncrypted checks if a string has the sentinel encrypted payload header.
func IsEncrypted(val string) bool {
	return strings.HasPrefix(val, EncryptedPayloadHeader)
}
