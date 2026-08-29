package crypto

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
)

// Standard TLS 1.3 Key Exchange Curves / Post-Quantum Hybrid Groups
const (
	CurveX25519MLKEM768     = "X25519MLKEM768"     // NIST FIPS 203 ML-KEM Standard
	CurveX25519Kyber768Draft = "X25519Kyber768Draft00" // Kyber draft hybrid
	CurveX25519             = "X25519"             // Classical Curve25519
	CurveSecP256r1MLKEM768  = "SecP256r1MLKEM768"  // NIST P-256 + ML-KEM
)

// DefaultPostQuantumCurves returns standard hybrid Post-Quantum key exchange curve groups supported by modern proxy cores.
func DefaultPostQuantumCurves() []string {
	return []string{CurveX25519MLKEM768, CurveX25519Kyber768Draft, CurveX25519}
}

// KeyPair represents a cryptographic public/private keypair.
type KeyPair struct {
	PrivateKey string `json:"privateKey"`
	PublicKey  string `json:"publicKey"`
}

// GenerateX25519KeyPair generates standard Reality-compatible X25519 keypair in base64 RawURLEncoding.
func GenerateX25519KeyPair() (*KeyPair, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate X25519 key: %w", err)
	}

	privBytes := priv.Bytes()
	pubBytes := priv.PublicKey().Bytes()

	return &KeyPair{
		PrivateKey: base64.RawURLEncoding.EncodeToString(privBytes),
		PublicKey:  base64.RawURLEncoding.EncodeToString(pubBytes),
	}, nil
}

// GenerateRandomPassword generates a secure random URL-safe string of given byte length
func GenerateRandomPassword(byteLength int) string {
	if byteLength <= 0 {
		byteLength = 16
	}
	b := make([]byte, byteLength)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// GenerateShadowsocksKey generates a valid base64 key or random string for Shadowsocks ciphers
func GenerateShadowsocksKey(method string) string {
	if strings.HasPrefix(method, "2022-blake3-aes-128") {
		b := make([]byte, 16)
		_, _ = rand.Read(b)
		return base64.StdEncoding.EncodeToString(b)
	} else if strings.HasPrefix(method, "2022-blake3-aes-256") || strings.HasPrefix(method, "2022-blake3-chacha20") {
		b := make([]byte, 32)
		_, _ = rand.Read(b)
		return base64.StdEncoding.EncodeToString(b)
	}
	return GenerateRandomPassword(16)
}

// GenerateRandomUUID generates a random UUID v4 string
func GenerateRandomUUID() string {
	var u [16]byte
	_, _ = rand.Read(u[:])
	u[6] = (u[6] & 0x0f) | 0x40 // Version 4
	u[8] = (u[8] & 0x3f) | 0x80 // Variant RFC 4122
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", u[0:4], u[4:6], u[6:8], u[8:10], u[10:16])
}
