package integrity

import (
	"testing"
)

func TestEd25519SigningAndVerification(t *testing.T) {
	pubKeyB64, privKeyB64, err := GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("failed to generate ed25519 keypair: %v", err)
	}

	payload := []byte(`{"preset":"ru","action":"direct","domains":["yandex.ru"]}`)

	// Sign
	signature, err := SignPayloadEd25519(payload, privKeyB64)
	if err != nil {
		t.Fatalf("failed to sign payload: %v", err)
	}

	// Verify genuine
	if err := VerifyPayloadEd25519(payload, signature, pubKeyB64); err != nil {
		t.Fatalf("expected valid signature verification, got: %v", err)
	}

	// Verify tampered payload
	tamperedPayload := []byte(`{"preset":"ru","action":"proxy","domains":["yandex.ru"]}`)
	if err := VerifyPayloadEd25519(tamperedPayload, signature, pubKeyB64); err == nil {
		t.Fatalf("expected signature verification to fail on tampered payload")
	}
}

func TestHMACAndChecksum(t *testing.T) {
	secret := []byte("sentinel-master-secret-key-32b!")
	payload := []byte("vless://user@198.51.100.1:443?type=tcp&security=reality")

	mac := ComputeHMACSHA256(payload, secret)
	if !VerifyHMACSHA256(payload, mac, secret) {
		t.Fatalf("HMAC verification failed")
	}

	if VerifyHMACSHA256([]byte("tampered"), mac, secret) {
		t.Fatalf("HMAC verification should have failed on tampered payload")
	}

	checksum := ComputePayloadChecksum(payload)
	if !IsValidChecksum(payload, checksum) {
		t.Fatalf("checksum verification failed")
	}
}

func TestSanitizerSSRF(t *testing.T) {
	s := NewSanitizer(true)

	// Legitimate endpoint
	if err := s.AuditEndpoint("google.com", 443); err != nil {
		t.Fatalf("expected google.com:443 to be valid, got: %v", err)
	}

	// AWS Cloud Metadata IP
	if err := s.AuditEndpoint("169.254.169.254", 80); err == nil {
		t.Fatalf("expected 169.254.169.254 to be blocked due to SSRF rule")
	}

	// GCP Metadata Domain
	if err := s.AuditEndpoint("metadata.google.internal", 80); err == nil {
		t.Fatalf("expected metadata.google.internal to be blocked")
	}

	// Command injection in host
	if err := s.AuditEndpoint("example.com;rm -rf /", 80); err == nil {
		t.Fatalf("expected shell injection pattern to be blocked")
	}

	// Audit JSON Config
	jsonValid := []byte(`{"outbounds":[{"server":"proxy.example.com","server_port":443}]}`)
	if err := s.SanitizeJSONConfig(jsonValid); err != nil {
		t.Fatalf("expected valid JSON config to pass, got: %v", err)
	}

	jsonMalicious := []byte(`{"outbounds":[{"server":"169.254.169.254","server_port":80}]}`)
	if err := s.SanitizeJSONConfig(jsonMalicious); err == nil {
		t.Fatalf("expected JSON config with metadata IP to fail")
	}
}

func TestZeroize(t *testing.T) {
	key := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	ZeroizeBytes(key)
	for i, b := range key {
		if b != 0 {
			t.Fatalf("byte at index %d was not zeroized, got %d", i, b)
		}
	}
}
