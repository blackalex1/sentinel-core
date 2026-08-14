package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
)

// CipherAlgorithm defines supported AEAD algorithms
type CipherAlgorithm string

const (
	AlgAES256GCM CipherAlgorithm = "aes-256-gcm"
)

// EncryptedPayloadHeader prefix for encrypted strings in DB
const EncryptedPayloadHeader = "enc:v1:aes-gcm:"

// EncryptAEAD encrypts plaintext using AES-256-GCM with a random 12-byte nonce.
// Returns base64 encoded string with header: enc:v1:aes-gcm:<base64_iv_and_ciphertext>
func EncryptAEAD(plaintext []byte, key []byte) (string, error) {
	if len(key) != 32 {
		return "", fmt.Errorf("encryption key must be exactly 32 bytes (256 bits), got %d bytes", len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM AEAD: %w", err)
	}

	// Generate 12-byte cryptographic nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate random nonce: %w", err)
	}

	// Seal: appends ciphertext and 16-byte authentication tag to nonce
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	encoded := base64.RawURLEncoding.EncodeToString(ciphertext)
	return EncryptedPayloadHeader + encoded, nil
}

// DecryptAEAD decrypts an encrypted payload string if the key matches and integrity tag is valid.
func DecryptAEAD(encryptedStr string, key []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("decryption key must be exactly 32 bytes (256 bits), got %d bytes", len(key))
	}

	if !strings.HasPrefix(encryptedStr, EncryptedPayloadHeader) {
		return nil, fmt.Errorf("invalid payload header: missing '%s'", EncryptedPayloadHeader)
	}

	rawB64 := strings.TrimPrefix(encryptedStr, EncryptedPayloadHeader)
	rawBytes, err := base64.RawURLEncoding.DecodeString(rawB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 ciphertext: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM AEAD: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(rawBytes) < nonceSize {
		return nil, fmt.Errorf("ciphertext is too short: corrupted payload")
	}

	nonce, ciphertext := rawBytes[:nonceSize], rawBytes[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("AEAD authentication/decryption failed: incorrect key or corrupted data (%w)", err)
	}

	return plaintext, nil
}
