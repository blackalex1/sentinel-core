package crypto

import (
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// VlessEncKeys represents X25519 and ML-KEM-768 key pairs for VLESS Encryption
type VlessEncKeys struct {
	X25519   VlessKeyPair `json:"x25519"`
	MLKEM768 VlessKeyPair `json:"mlkem768"`
}

type VlessKeyPair struct {
	Decryption string `json:"decryption"`
	Encryption string `json:"encryption"`
}

// GenerateVlessEncKeys generates standard X25519 and ML-KEM-768 (Post-Quantum) keypairs compliant with Xray vlessenc
func GenerateVlessEncKeys() (*VlessEncKeys, error) {
	// 1. X25519 Key Pair
	xPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate X25519 key: %w", err)
	}

	xDec := "mlkem768x25519plus.native.600s." + base64.RawURLEncoding.EncodeToString(xPriv.Bytes())
	xEnc := "mlkem768x25519plus.native.0rtt." + base64.RawURLEncoding.EncodeToString(xPriv.PublicKey().Bytes())

	// 2. ML-KEM-768 / PQ Key Pair (using 64-byte seed compliant with Xray vlessenc)
	seed := make([]byte, mlkem.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return nil, fmt.Errorf("failed to generate random seed for ML-KEM-768: %w", err)
	}

	mlkDec, err := mlkem.NewDecapsulationKey768(seed)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ML-KEM-768 key from seed: %w", err)
	}

	mlDec := "mlkem768x25519plus.native.600s." + base64.RawURLEncoding.EncodeToString(seed)
	mlEnc := "mlkem768x25519plus.native.0rtt." + base64.RawURLEncoding.EncodeToString(mlkDec.EncapsulationKey().Bytes())

	return &VlessEncKeys{
		X25519: VlessKeyPair{
			Decryption: xDec,
			Encryption: xEnc,
		},
		MLKEM768: VlessKeyPair{
			Decryption: mlDec,
			Encryption: mlEnc,
		},
	}, nil
}
