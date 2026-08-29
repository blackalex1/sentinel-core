package tests

import (
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/blackalex1/sentinel-core/pkg/ast"
	"github.com/blackalex1/sentinel-core/pkg/builder"
	"github.com/blackalex1/sentinel-core/pkg/parser"
	"github.com/blackalex1/sentinel-core/pkg/routing"
)

func verifyWithLiveCores(t *testing.T, testName string, profile *ast.ServerProfile) {
	t.Helper()

	engine := routing.NewEngine()
	policy := routing.DefaultSmartPolicy()

	// 1. Sing-box Verification
	specSingBox := &ast.ConfigSpec{
		TargetCore: ast.CoreSingBox,
		LogLevel:   "info",
		ClientInbound: &ast.ClientInboundSpec{
			Mode:          ast.InboundModeSystemProxy,
			SocksPort:     10818,
			HTTPPort:      10819,
			ListenAddress: "127.0.0.1",
		},
		ServerNode: profile,
		Routing:    engine.CompilePolicy(policy),
		DNS: &ast.DNSSpec{
			RemoteServer: "https://1.1.1.1/dns-query",
			DirectServer: "8.8.8.8",
			Strategy:     "ipv4_only",
		},
	}

	resSingBox, err := builder.BuildClientConfig(specSingBox)
	if err != nil {
		t.Fatalf("[%s] Sing-box builder error: %v", testName, err)
	}

	sbBin := findCoreBin("sing-box")
	if sbBin != "" {
		tmpFile, err := os.CreateTemp("", "live-sb-*.json")
		if err != nil {
			t.Fatalf("failed to create temp file: %v", err)
		}
		defer os.Remove(tmpFile.Name())
		tmpFile.WriteString(resSingBox.ConfigJSON)
		tmpFile.Close()

		cmd := exec.Command(sbBin, "check", "-c", tmpFile.Name())
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("[%s] Sing-box (v1.14+) live syntax check failed: %v\nOutput: %s\nConfig:\n%s", testName, err, string(out), resSingBox.ConfigJSON)
		}
	}

	// 2. Xray Verification
	specXray := &ast.ConfigSpec{
		TargetCore: ast.CoreXray,
		LogLevel:   "warning",
		ClientInbound: &ast.ClientInboundSpec{
			Mode:          ast.InboundModeSystemProxy,
			SocksPort:     10818,
			HTTPPort:      10819,
			ListenAddress: "127.0.0.1",
		},
		ServerNode: profile,
		Routing:    engine.CompilePolicy(policy),
		DNS: &ast.DNSSpec{
			RemoteServer: "https://1.1.1.1/dns-query",
			DirectServer: "8.8.8.8",
			Strategy:     "ipv4_only",
		},
	}

	resXray, err := builder.BuildClientConfig(specXray)
	if err != nil {
		t.Fatalf("[%s] Xray builder error: %v", testName, err)
	}

	xrayBin := findCoreBin("xray")
	if xrayBin != "" {
		tmpFile, err := os.CreateTemp("", "live-xray-*.json")
		if err != nil {
			t.Fatalf("failed to create temp file: %v", err)
		}
		defer os.Remove(tmpFile.Name())
		tmpFile.WriteString(resXray.ConfigJSON)
		tmpFile.Close()

		cmd := exec.Command(xrayBin, "-test", "-config", tmpFile.Name())
		out, err := cmd.CombinedOutput()
		outStr := string(out)
		if err != nil && !strings.Contains(outStr, "Configuration OK") {
			t.Fatalf("[%s] Xray (v26.7+ pre-release) live syntax check failed: %v\nOutput: %s\nConfig:\n%s", testName, err, outStr, resXray.ConfigJSON)
		}
	}
}

// ==========================================
// VLESS REALITY AND TRANSPORT MATRIX TESTS
// ==========================================

func TestLiveMatrix_VLESS_Reality_TCP_Vision(t *testing.T) {
	raw := "vless://b9f3857a-ce20-4e1e-b5e0-6f3d141fa2b2@198.51.100.50:443?type=tcp&security=reality&pbk=1pxvjj6jjhkkN40PM83ViQTJeC9VMDVe7oceMZuWNQY&fp=chrome&sni=www.apple.com&sid=0123456789abcdef&spx=%2F&flow=xtls-rprx-vision#Reality-TCP-Vision"
	profile, err := parser.ParseURI(raw)
	if err != nil {
		t.Fatalf("URI parse failed: %v", err)
	}
	verifyWithLiveCores(t, "VLESS Reality TCP Vision", profile)
}

func TestLiveMatrix_VLESS_Reality_gRPC(t *testing.T) {
	raw := "vless://b9f3857a-ce20-4e1e-b5e0-6f3d141fa2b2@198.51.100.51:8443?type=grpc&security=reality&pbk=1pxvjj6jjhkkN40PM83ViQTJeC9VMDVe7oceMZuWNQY&fp=firefox&sni=www.microsoft.com&sid=abcdef0123456789&serviceName=vless-grpc#Reality-gRPC"
	profile, err := parser.ParseURI(raw)
	if err != nil {
		t.Fatalf("URI parse failed: %v", err)
	}
	verifyWithLiveCores(t, "VLESS Reality gRPC", profile)
}

func TestLiveMatrix_VLESS_Reality_WebSocket(t *testing.T) {
	raw := "vless://b9f3857a-ce20-4e1e-b5e0-6f3d141fa2b2@198.51.100.52:443?type=ws&security=reality&pbk=1pxvjj6jjhkkN40PM83ViQTJeC9VMDVe7oceMZuWNQY&fp=safari&sni=gateway.icloud.com&sid=12345678&path=%2Fvless-ws&host=gateway.icloud.com#Reality-WS"
	profile, err := parser.ParseURI(raw)
	if err != nil {
		t.Fatalf("URI parse failed: %v", err)
	}
	verifyWithLiveCores(t, "VLESS Reality WebSocket", profile)
}

func TestLiveMatrix_VLESS_Reality_HTTPUpgrade(t *testing.T) {
	raw := "vless://b9f3857a-ce20-4e1e-b5e0-6f3d141fa2b2@198.51.100.53:443?type=httpupgrade&security=reality&pbk=1pxvjj6jjhkkN40PM83ViQTJeC9VMDVe7oceMZuWNQY&fp=edge&sni=www.google.com&sid=aabbccdd&path=%2Fhu#Reality-HTTPUpgrade"
	profile, err := parser.ParseURI(raw)
	if err != nil {
		t.Fatalf("URI parse failed: %v", err)
	}
	verifyWithLiveCores(t, "VLESS Reality HTTPUpgrade", profile)
}

func TestLiveMatrix_VLESS_TCP_TLS_Vision(t *testing.T) {
	raw := "vless://a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d@tls-node.vpn.org:443?type=tcp&security=tls&sni=tls-node.vpn.org&fp=chrome&flow=xtls-rprx-vision&alpn=h2%2Chttp%2F1.1#VLESS-TLS-TCP"
	profile, err := parser.ParseURI(raw)
	if err != nil {
		t.Fatalf("URI parse failed: %v", err)
	}
	verifyWithLiveCores(t, "VLESS TCP TLS Vision", profile)
}

func TestLiveMatrix_VLESS_WS_TLS(t *testing.T) {
	raw := "vless://a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d@cdn.cloudflare.net:443?type=ws&security=tls&sni=my-subdomain.workers.dev&path=%2Fchat&host=my-subdomain.workers.dev#VLESS-WS-TLS-CDN"
	profile, err := parser.ParseURI(raw)
	if err != nil {
		t.Fatalf("URI parse failed: %v", err)
	}
	verifyWithLiveCores(t, "VLESS WS TLS CDN", profile)
}

func TestLiveMatrix_VLESS_Plain_NoTLS(t *testing.T) {
	raw := "vless://a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d@198.51.100.60:8080?type=tcp&security=none#VLESS-Plain-Direct"
	profile, err := parser.ParseURI(raw)
	if err != nil {
		t.Fatalf("URI parse failed: %v", err)
	}
	verifyWithLiveCores(t, "VLESS Plain No TLS", profile)
}

// ==========================================
// SHADOWSOCKS MULTI-CIPHER MATRIX TESTS
// ==========================================

func TestLiveMatrix_Shadowsocks_AES256GCM(t *testing.T) {
	b64Auth := base64.URLEncoding.EncodeToString([]byte("aes-256-gcm:P@ssword!2026_Secure"))
	raw := fmt.Sprintf("ss://%s@198.51.100.70:8388#SS-AES256GCM", b64Auth)
	profile, err := parser.ParseURI(raw)
	if err != nil {
		t.Fatalf("URI parse failed: %v", err)
	}
	verifyWithLiveCores(t, "Shadowsocks AES-256-GCM", profile)
}

func TestLiveMatrix_Shadowsocks_AES128GCM(t *testing.T) {
	b64Auth := base64.URLEncoding.EncodeToString([]byte("aes-128-gcm:FastPass999"))
	raw := fmt.Sprintf("ss://%s@198.51.100.71:8389#SS-AES128GCM", b64Auth)
	profile, err := parser.ParseURI(raw)
	if err != nil {
		t.Fatalf("URI parse failed: %v", err)
	}
	verifyWithLiveCores(t, "Shadowsocks AES-128-GCM", profile)
}

func TestLiveMatrix_Shadowsocks_ChaCha20Poly1305(t *testing.T) {
	b64Auth := base64.URLEncoding.EncodeToString([]byte("chacha20-ietf-poly1305:UltraFastStreamKey_77"))
	raw := fmt.Sprintf("ss://%s@198.51.100.72:8390#SS-ChaCha20", b64Auth)
	profile, err := parser.ParseURI(raw)
	if err != nil {
		t.Fatalf("URI parse failed: %v", err)
	}
	verifyWithLiveCores(t, "Shadowsocks ChaCha20-Poly1305", profile)
}

func TestLiveMatrix_Shadowsocks_2022_Blake3_AES128(t *testing.T) {
	raw16Key := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef")) // exactly 16 bytes for 128-bit key
	b64Auth := base64.StdEncoding.EncodeToString([]byte("2022-blake3-aes-128-gcm:" + raw16Key))
	raw := fmt.Sprintf("ss://%s@198.51.100.73:9001#SS-2022-128", b64Auth)
	profile, err := parser.ParseURI(raw)
	if err != nil {
		t.Fatalf("URI parse failed: %v", err)
	}
	verifyWithLiveCores(t, "Shadowsocks 2022 Blake3 AES-128-GCM", profile)
}

func TestLiveMatrix_Shadowsocks_2022_Blake3_AES256(t *testing.T) {
	raw32Key := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef")) // exactly 32 bytes for 256-bit key
	b64Auth := base64.StdEncoding.EncodeToString([]byte("2022-blake3-aes-256-gcm:" + raw32Key))
	raw := fmt.Sprintf("ss://%s@198.51.100.74:9002#SS-2022-256", b64Auth)
	profile, err := parser.ParseURI(raw)
	if err != nil {
		t.Fatalf("URI parse failed: %v", err)
	}
	verifyWithLiveCores(t, "Shadowsocks 2022 Blake3 AES-256-GCM", profile)
}

func TestLiveMatrix_Shadowsocks_LegacyWholeBase64(t *testing.T) {
	legacyStr := "aes-256-gcm:LegacyPassword123@198.51.100.75:8400"
	raw := "ss://" + base64.StdEncoding.EncodeToString([]byte(legacyStr)) + "#SS-Legacy-WholeBase64"
	profile, err := parser.ParseURI(raw)
	if err != nil {
		t.Fatalf("URI parse failed: %v", err)
	}
	verifyWithLiveCores(t, "Shadowsocks Legacy Whole Base64", profile)
}
