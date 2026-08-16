package integrity

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

var (
	ErrInvalidSignature = errors.New("cryptographic signature verification failed")
	ErrInvalidKey       = errors.New("invalid public/private key length or format")
)

// GenerateEd25519KeyPair generates a new Ed25519 public/private key pair encoded in Base64.
func GenerateEd25519KeyPair() (pubKeyB64 string, privKeyB64 string, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate ed25519 keypair: %w", err)
	}
	return base64.StdEncoding.EncodeToString(pub), base64.StdEncoding.EncodeToString(priv), nil
}

// SignPayloadEd25519 signs a byte payload with an Ed25519 private key (Base64).
func SignPayloadEd25519(payload []byte, privKeyB64 string) (string, error) {
	privKeyBytes, err := base64.StdEncoding.DecodeString(privKeyB64)
	if err != nil {
		return "", fmt.Errorf("failed to decode ed25519 private key: %w", err)
	}
	if len(privKeyBytes) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("%w: expected %d bytes, got %d", ErrInvalidKey, ed25519.PrivateKeySize, len(privKeyBytes))
	}

	sig := ed25519.Sign(ed25519.PrivateKey(privKeyBytes), payload)
	return base64.StdEncoding.EncodeToString(sig), nil
}

// VerifyPayloadEd25519 verifies that the signature matches the payload and Ed25519 public key.
func VerifyPayloadEd25519(payload []byte, signatureB64 string, pubKeyB64 string) error {
	pubKeyBytes, err := base64.StdEncoding.DecodeString(pubKeyB64)
	if err != nil {
		return fmt.Errorf("failed to decode ed25519 public key: %w", err)
	}
	if len(pubKeyBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: expected %d bytes, got %d", ErrInvalidKey, ed25519.PublicKeySize, len(pubKeyBytes))
	}

	sigBytes, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}

	if !ed25519.Verify(ed25519.PublicKey(pubKeyBytes), payload, sigBytes) {
		return ErrInvalidSignature
	}
	return nil
}

// ComputeHMACSHA256 generates a hex-encoded HMAC-SHA256 authentication tag for a message.
func ComputeHMACSHA256(payload []byte, secretKey []byte) string {
	mac := hmac.New(sha256.New, secretKey)
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifyHMACSHA256 performs a constant-time comparison of an HMAC-SHA256 tag.
func VerifyHMACSHA256(payload []byte, expectedHexMAC string, secretKey []byte) bool {
	expectedBytes, err := hex.DecodeString(expectedHexMAC)
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, secretKey)
	mac.Write(payload)
	actualBytes := mac.Sum(nil)
	return hmac.Equal(actualBytes, expectedBytes)
}

// ComputePayloadChecksum returns standard SHA256 hex checksum of a string or byte payload.
func ComputePayloadChecksum(payload []byte) string {
	hash := sha256.Sum256(payload)
	return hex.EncodeToString(hash[:])
}

// IsValidChecksum verifies if the payload matches the expected SHA256 hex string.
func IsValidChecksum(payload []byte, expectedChecksumHex string) bool {
	actual := ComputePayloadChecksum(payload)
	return strings.EqualFold(actual, strings.TrimSpace(expectedChecksumHex))
}
