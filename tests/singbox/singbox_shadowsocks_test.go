package singbox_test

import (
	"encoding/json"
	"testing"

	"github.com/blackalex1/sentinel-core/pkg/ast"
	"github.com/blackalex1/sentinel-core/pkg/builder"
	"github.com/blackalex1/sentinel-core/pkg/crypto"
)

// 1. Shadowsocks-2022 Blake3 (AES-128, AES-256, ChaCha20) in Sing-box
func TestSingbox_Shadowsocks_2022_Blake3(t *testing.T) {
	ciphers := []string{
		"2022-blake3-aes-128-gcm",
		"2022-blake3-aes-256-gcm",
		"2022-blake3-chacha20-poly1305",
	}

	for _, cipher := range ciphers {
		t.Run("Cipher_"+cipher, func(t *testing.T) {
			key := crypto.GenerateShadowsocksKey(cipher)
			profile := &ast.ServerProfile{
				Protocol: ast.ProtoShadowsocks,
				Address:  "198.51.100.10",
				Port:     8388,
				Cipher:   cipher,
				Password: key,
				Name:     "SS-2022-" + cipher,
			}

			spec := buildClientTestSpec(profile)
			res, err := builder.BuildClientConfig(spec)
			if err != nil {
				t.Fatalf("BuildClientConfig failed for %s: %v", cipher, err)
			}

			var parsed map[string]interface{}
			if err := json.Unmarshal([]byte(res.ConfigJSON), &parsed); err != nil {
				t.Fatalf("invalid JSON for %s: %v", cipher, err)
			}

			outbounds := parsed["outbounds"].([]interface{})
			primary := outbounds[0].(map[string]interface{})
			if primary["type"] != "shadowsocks" {
				t.Fatalf("expected type shadowsocks, got %v", primary["type"])
			}
			if primary["method"] != cipher {
				t.Fatalf("expected method %s, got %v", cipher, primary["method"])
			}

			runSingboxSyntaxCheck(t, "Shadowsocks 2022 "+cipher, res.ConfigJSON)
		})
	}
}

// 2. Standard AEAD Shadowsocks Ciphers in Sing-box
func TestSingbox_Shadowsocks_AEAD(t *testing.T) {
	ciphers := []string{
		"aes-128-gcm",
		"aes-256-gcm",
		"chacha20-ietf-poly1305",
	}

	for _, cipher := range ciphers {
		t.Run("AEAD_"+cipher, func(t *testing.T) {
			node := &ast.ServerProfile{
				Protocol: ast.ProtoShadowsocks,
				Address:  "198.51.100.11",
				Port:     8388,
				Cipher:   cipher,
				Password: crypto.GenerateRandomPassword(16),
				Name:     "SS-AEAD-" + cipher,
			}

			spec := buildClientTestSpec(node)
			res, err := builder.BuildClientConfig(spec)
			if err != nil {
				t.Fatalf("BuildClientConfig failed for %s: %v", cipher, err)
			}

			runSingboxSyntaxCheck(t, "Shadowsocks AEAD "+cipher, res.ConfigJSON)
		})
	}
}

// 3. Shadowsocks Server Inbound in Sing-box
func TestSingbox_Shadowsocks_Server_Inbound(t *testing.T) {
	inbound := ast.ServerInboundSpec{
		Protocol:      "shadowsocks",
		ListenAddress: "0.0.0.0",
		Port:          8388,
		RawSettings: map[string]interface{}{
			"method":   "2022-blake3-aes-128-gcm",
			"password": crypto.GenerateShadowsocksKey("2022-blake3-aes-128-gcm"),
		},
		Clients: []ast.ServerInboundClient{
			{Password: crypto.GenerateShadowsocksKey("2022-blake3-aes-128-gcm")},
		},
	}

	serverJSON, err := builder.BuildServerConfig(ast.CoreSingBox, []ast.ServerInboundSpec{inbound}, nil, "")
	if err != nil {
		t.Fatalf("BuildServerConfig failed: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(serverJSON), &parsed); err != nil {
		t.Fatalf("invalid server JSON: %v", err)
	}

	inbounds := parsed["inbounds"].([]interface{})
	primary := inbounds[0].(map[string]interface{})
	if primary["type"] != "shadowsocks" {
		t.Fatalf("expected type shadowsocks, got %v", primary["type"])
	}

	runSingboxSyntaxCheck(t, "Shadowsocks Server Inbound in Sing-box", serverJSON)
	t.Logf("✅ Sing-box Shadowsocks Server Inbound verified")
}
