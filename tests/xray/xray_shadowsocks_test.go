package xray_test

import (
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/blackalex1/sentinel-core/pkg/ast"
	"github.com/blackalex1/sentinel-core/pkg/builder"
	"github.com/blackalex1/sentinel-core/pkg/parser"
)

// 1. Shadowsocks AEAD Standard Ciphers in Xray
func TestXray_Shadowsocks_AEAD_Ciphers(t *testing.T) {
	ciphers := []string{"aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305"}

	for _, c := range ciphers {
		t.Run("AEAD_"+c, func(t *testing.T) {
			b64 := base64.URLEncoding.EncodeToString([]byte(fmt.Sprintf("%s:SecretPassword_123!", c)))
			raw := fmt.Sprintf("ss://%s@198.51.100.25:8388#SS-%s", b64, c)

			profile, err := parser.ParseURI(raw)
			if err != nil {
				t.Fatalf("failed to parse SS URI: %v", err)
			}

			spec := buildClientTestSpec(profile)
			res, err := builder.BuildClientConfig(spec)
			if err != nil {
				t.Fatalf("BuildClientConfig failed for SS %s: %v", c, err)
			}

			runXraySyntaxCheck(t, "Shadowsocks "+c, res.ConfigJSON)
		})
	}
}

// 2. Shadowsocks 2022 (AEAD-2022) in Xray
func TestXray_Shadowsocks_2022_Blake3(t *testing.T) {
	raw16Key := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef")) // 16 bytes
	b64Auth128 := base64.StdEncoding.EncodeToString([]byte("2022-blake3-aes-128-gcm:" + raw16Key))
	raw128 := fmt.Sprintf("ss://%s@198.51.100.73:9001#SS-2022-128", b64Auth128)

	p128, err := parser.ParseURI(raw128)
	if err != nil {
		t.Fatalf("failed to parse SS-2022-128 URI: %v", err)
	}

	spec128 := buildClientTestSpec(p128)
	res128, err := builder.BuildClientConfig(spec128)
	if err != nil {
		t.Fatalf("BuildClientConfig failed: %v", err)
	}

	runXraySyntaxCheck(t, "Shadowsocks 2022-128", res128.ConfigJSON)
	t.Logf("✅ Xray Shadowsocks 2022 passed live verification")
}

// 3. Shadowsocks Server Inbound in Xray
func TestXray_Shadowsocks_Server_Inbound(t *testing.T) {
	inbound := ast.ServerInboundSpec{
		Protocol:      "shadowsocks",
		ListenAddress: "0.0.0.0",
		Port:          8388,
		Clients: []ast.ServerInboundClient{
			{Password: "StrongSecretPass777", Email: "user1@ss"},
		},
		RawSettings: map[string]interface{}{
			"method":   "aes-256-gcm",
			"password": "StrongSecretPass777",
			"network":  "tcp,udp",
		},
	}

	serverJSON, err := builder.BuildServerConfig(ast.CoreXray, []ast.ServerInboundSpec{inbound}, nil, "")
	if err != nil {
		t.Fatalf("BuildServerConfig failed: %v", err)
	}

	runXraySyntaxCheck(t, "Shadowsocks Server Inbound", serverJSON)
	t.Logf("✅ Xray Shadowsocks Server Inbound verified")
}
