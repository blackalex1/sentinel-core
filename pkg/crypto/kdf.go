package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

// DeriveKeyPBKDF2 derives a 32-byte (256-bit) encryption key from a master secret and salt using HMAC-SHA256.
func DeriveKeyPBKDF2(secret string, salt []byte, iterations int) []byte {
	if iterations <= 0 {
		iterations = 100000 // Industry standard recommended minimum for SHA-256
	}
	if len(salt) == 0 {
		salt = []byte("sentinel-secure-vault-salt-v1")
	}

	prf := hmac.New(sha256.New, []byte(secret))
	keyLength := 32 // 256 bits

	numBlocks := (keyLength + sha256.Size - 1) / sha256.Size
	var derivedKey []byte

	for block := 1; block <= numBlocks; block++ {
		prf.Reset()
		prf.Write(salt)
		var blockBytes [4]byte
		binary.BigEndian.PutUint32(blockBytes[:], uint32(block))
		prf.Write(blockBytes[:])
		u := prf.Sum(nil)

		t := make([]byte, len(u))
		copy(t, u)

		for iter := 1; iter < iterations; iter++ {
			prf.Reset()
			prf.Write(u)
			u = prf.Sum(nil)
			for k := 0; k < len(t); k++ {
				t[k] ^= u[k]
			}
		}
		derivedKey = append(derivedKey, t...)
	}

	return derivedKey[:keyLength]
}

// DeriveKeyFromSecret generates a 32-byte key from any raw secret string (e.g. from environment variable or password).
func DeriveKeyFromSecret(secret string) ([]byte, error) {
	if len(secret) == 0 {
		return nil, fmt.Errorf("master secret key cannot be empty")
	}
	return DeriveKeyPBKDF2(secret, []byte("sentinel-vault-master-key-salt"), 100000), nil
}
