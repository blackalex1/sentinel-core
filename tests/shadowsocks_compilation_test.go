package tests

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/blackalex1/sentinel-core/pkg/ast"
	"github.com/blackalex1/sentinel-core/pkg/builder"
	"github.com/blackalex1/sentinel-core/pkg/compiler/singbox"
	"github.com/blackalex1/sentinel-core/pkg/compiler/xray"
	"github.com/blackalex1/sentinel-core/pkg/parser"
	"github.com/blackalex1/sentinel-core/pkg/routing"
)

func runSingBoxSyntaxCheck(t *testing.T, configJSON string) {
	t.Helper()
	sbBin := findCoreBin("sing-box")
	if sbBin == "" {
		t.Skip("sing-box binary not found, skipping live check")
		return
	}

	tmpFile, err := os.CreateTemp("", "ss-singbox-check-*.json")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(configJSON); err != nil {
		t.Fatalf("failed to write temp config: %v", err)
	}
	tmpFile.Close()

	cmd := exec.Command(sbBin, "check", "-c", tmpFile.Name())
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("sing-box check failed: %v\nOutput: %s\nConfig:\n%s", err, string(out), configJSON)
	}
}

func runXraySyntaxCheck(t *testing.T, configJSON string) {
	t.Helper()
	xrayBin := findCoreBin("xray")
	if xrayBin == "" {
		t.Skip("xray binary not found, skipping live check")
		return
	}

	tmpFile, err := os.CreateTemp("", "ss-xray-check-*.json")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(configJSON); err != nil {
		t.Fatalf("failed to write temp config: %v", err)
	}
	tmpFile.Close()

	cmd := exec.Command(xrayBin, "-test", "-config", tmpFile.Name())
	out, err := cmd.CombinedOutput()
	outStr := string(out)
	if err != nil && !strings.Contains(outStr, "Configuration OK") {
		t.Fatalf("xray check failed: %v\nOutput: %s\nConfig:\n%s", err, outStr, configJSON)
	}
}

func buildTestSpec(targetCore ast.TargetCore, profile *ast.ServerProfile) *ast.ConfigSpec {
	engine := routing.NewEngine()
	return &ast.ConfigSpec{
		TargetCore: targetCore,
		LogLevel:   "info",
		ClientInbound: &ast.ClientInboundSpec{
			Mode:          ast.InboundModeSystemProxy,
			SocksPort:     10818,
			HTTPPort:      10819,
			ListenAddress: "127.0.0.1",
		},
		ServerNode: profile,
		Routing:    engine.CompilePolicy(routing.DefaultSmartPolicy()),
		DNS: &ast.DNSSpec{
			RemoteServer: "https://1.1.1.1/dns-query",
			DirectServer: "8.8.8.8",
			Strategy:     "ipv4_only",
		},
	}
}

// 1. SIP002 Standard Shadowsocks URI Compilation to Sing-box & Xray
func TestShadowsocks_SIP002_Compilation(t *testing.T) {
	b64Auth := base64.URLEncoding.EncodeToString([]byte("aes-256-gcm:SecretPassword_123!"))
	rawURI := fmt.Sprintf("ss://%s@198.51.100.25:8388#Production-SS", b64Auth)

	profile, err := parser.ParseURI(rawURI)
	if err != nil {
		t.Fatalf("failed to parse SIP002 SS URI: %v", err)
	}

	if profile.Protocol != ast.ProtoShadowsocks {
		t.Fatalf("expected protocol %s, got %s", ast.ProtoShadowsocks, profile.Protocol)
	}
	if profile.Cipher != "aes-256-gcm" {
		t.Errorf("expected cipher aes-256-gcm, got %s", profile.Cipher)
	}
	if profile.Password != "SecretPassword_123!" {
		t.Errorf("expected password SecretPassword_123!, got %s", profile.Password)
	}
	if profile.Address != "198.51.100.25" || profile.Port != 8388 {
		t.Errorf("expected 198.51.100.25:8388, got %s:%d", profile.Address, profile.Port)
	}

	// Compile to Sing-box Client Config
	resSingBox, err := builder.BuildClientConfig(buildTestSpec(ast.CoreSingBox, profile))
	if err != nil {
		t.Fatalf("failed to build Sing-box client config: %v", err)
	}

	var sbMap map[string]interface{}
	if err := json.Unmarshal([]byte(resSingBox.ConfigJSON), &sbMap); err != nil {
		t.Fatalf("generated invalid JSON for Sing-box: %v", err)
	}

	runSingBoxSyntaxCheck(t, resSingBox.ConfigJSON)

	// Compile to Xray Client Config
	resXray, err := builder.BuildClientConfig(buildTestSpec(ast.CoreXray, profile))
	if err != nil {
		t.Fatalf("failed to build Xray client config: %v", err)
	}

	var xrayMap map[string]interface{}
	if err := json.Unmarshal([]byte(resXray.ConfigJSON), &xrayMap); err != nil {
		t.Fatalf("generated invalid JSON for Xray: %v", err)
	}

	runXraySyntaxCheck(t, resXray.ConfigJSON)
}

// 2. Shadowsocks 2022 (AEAD-2022) Blake3 Cipher Compilation
func TestShadowsocks_2022_Blake3_Compilation(t *testing.T) {
	// 2022-blake3-aes-128-gcm requires exactly 16 bytes base64 key
	raw16Key := base64.StdEncoding.EncodeToString([]byte("1234567890123456"))
	b64Auth := base64.StdEncoding.EncodeToString([]byte("2022-blake3-aes-128-gcm:" + raw16Key))
	rawURI := fmt.Sprintf("ss://%s@node.example.org:9000#SS-2022-Fast", b64Auth)

	profile, err := parser.ParseURI(rawURI)
	if err != nil {
		t.Fatalf("failed to parse SS-2022 URI: %v", err)
	}

	if profile.Cipher != "2022-blake3-aes-128-gcm" {
		t.Errorf("expected cipher 2022-blake3-aes-128-gcm, got %s", profile.Cipher)
	}

	res, err := builder.BuildClientConfig(buildTestSpec(ast.CoreSingBox, profile))
	if err != nil {
		t.Fatalf("failed to build Sing-box SS-2022 config: %v", err)
	}

	if !strings.Contains(res.ConfigJSON, "2022-blake3-aes-128-gcm") {
		t.Errorf("expected 2022-blake3-aes-128-gcm in config, got:\n%s", res.ConfigJSON)
	}

	runSingBoxSyntaxCheck(t, res.ConfigJSON)
}

// 3. ChaCha20-Poly1305 & Plain Method:Password Format Compilation
func TestShadowsocks_ChaCha20_PlainFormat_Compilation(t *testing.T) {
	b64Auth := base64.URLEncoding.EncodeToString([]byte("chacha20-ietf-poly1305:ComplexP@ssw0rd!#123"))
	rawURI := fmt.Sprintf("ss://%s@ss-node.vpn.net:443#ChaChaNode", b64Auth)

	profile, err := parser.ParseURI(rawURI)
	if err != nil {
		t.Fatalf("failed to parse plain format SS URI: %v", err)
	}

	if profile.Cipher != "chacha20-ietf-poly1305" {
		t.Errorf("expected chacha20-ietf-poly1305, got %s", profile.Cipher)
	}
	if profile.Address != "ss-node.vpn.net" || profile.Port != 443 {
		t.Errorf("expected ss-node.vpn.net:443, got %s:%d", profile.Address, profile.Port)
	}

	res, err := builder.BuildClientConfig(buildTestSpec(ast.CoreSingBox, profile))
	if err != nil {
		t.Fatalf("failed to build Sing-box ChaCha20 config: %v", err)
	}

	runSingBoxSyntaxCheck(t, res.ConfigJSON)
}

// 4. Legacy Whole-String Base64 Shadowsocks URI Compilation
func TestShadowsocks_LegacyBase64_Compilation(t *testing.T) {
	legacyBody := "aes-128-gcm:pass12345@192.0.2.1:8888"
	rawURI := "ss://" + base64.StdEncoding.EncodeToString([]byte(legacyBody)) + "#LegacyNode"

	profile, err := parser.ParseURI(rawURI)
	if err != nil {
		t.Fatalf("failed to parse legacy base64 SS URI: %v", err)
	}

	if profile.Cipher != "aes-128-gcm" || profile.Password != "pass12345" {
		t.Errorf("unexpected cipher/password: %s / %s", profile.Cipher, profile.Password)
	}
	if profile.Address != "192.0.2.1" || profile.Port != 8888 {
		t.Errorf("unexpected endpoint: %s:%d", profile.Address, profile.Port)
	}

	res, err := builder.BuildClientConfig(buildTestSpec(ast.CoreSingBox, profile))
	if err != nil {
		t.Fatalf("failed to compile Sing-box config from legacy SS: %v", err)
	}

	runSingBoxSyntaxCheck(t, res.ConfigJSON)
}

// 5. Failover Client Config with Multiple Shadowsocks and Mixed Profiles
func TestShadowsocks_Failover_MultiNode_Compilation(t *testing.T) {
	rawSS1 := "ss://" + base64.URLEncoding.EncodeToString([]byte("aes-128-gcm:p1")) + "@198.51.100.1:8388#SS-Primary"
	rawSS2 := "ss://" + base64.URLEncoding.EncodeToString([]byte("aes-256-gcm:p2")) + "@198.51.100.2:8389#SS-Backup1"
	rawSS3 := "ss://" + base64.URLEncoding.EncodeToString([]byte("chacha20-ietf-poly1305:p3")) + "@198.51.100.3:8390#SS-Backup2"

	p1, _ := parser.ParseURI(rawSS1)
	p2, _ := parser.ParseURI(rawSS2)
	p3, _ := parser.ParseURI(rawSS3)

	profiles := []*ast.ServerProfile{p1, p2, p3}

	res, err := builder.BuildFailoverClientConfig(profiles, ast.CoreSingBox, 10818, 10819, "https://1.1.1.1/dns-query")
	if err != nil {
		t.Fatalf("failed to build failover client config for Shadowsocks nodes: %v", err)
	}

	var sbMap map[string]interface{}
	if err := json.Unmarshal([]byte(res.ConfigJSON), &sbMap); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}

	outbounds, ok := sbMap["outbounds"].([]interface{})
	if !ok || len(outbounds) < 4 {
		t.Fatalf("expected at least 4 outbounds (failover selector + 3 SS nodes), got %d", len(outbounds))
	}

	runSingBoxSyntaxCheck(t, res.ConfigJSON)
}

// 6. Direct Compiler Unit Tests for Sing-box & Xray Outbounds
func TestShadowsocks_DirectCompiler_OutboundSchema(t *testing.T) {
	spec := &ast.ConfigSpec{
		TargetCore: ast.CoreSingBox,
		LogLevel:   "info",
		ClientInbound: &ast.ClientInboundSpec{
			Mode:          ast.InboundModeSystemProxy,
			SocksPort:     10818,
			HTTPPort:      10819,
			ListenAddress: "127.0.0.1",
		},
		ServerNode: &ast.ServerProfile{
			Protocol: ast.ProtoShadowsocks,
			Address:  "198.51.100.77",
			Port:     8388,
			Cipher:   "aes-256-gcm",
			Password: "MySuperPassword!",
			Name:     "ss-out",
		},
		Routing: &ast.RoutingSpec{
			DefaultAction: ast.ActionProxy,
		},
	}

	sc := singbox.NewCompiler()
	sbJSON, _, err := sc.Compile(spec)
	if err != nil {
		t.Fatalf("singbox Compile failed: %v", err)
	}
	runSingBoxSyntaxCheck(t, sbJSON)

	// Xray compilation check
	spec.TargetCore = ast.CoreXray
	xc := xray.NewCompiler()
	xrayJSON, _, err := xc.Compile(spec)
	if err != nil {
		t.Fatalf("xray Compile failed: %v", err)
	}
	runXraySyntaxCheck(t, xrayJSON)
}
