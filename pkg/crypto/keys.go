package crypto

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

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
