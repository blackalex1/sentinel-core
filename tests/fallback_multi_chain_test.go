package tests

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/blackalex1/sentinel-core/pkg/ast"
	"github.com/blackalex1/sentinel-core/pkg/builder"
	"github.com/blackalex1/sentinel-core/pkg/crypto"
	"github.com/blackalex1/sentinel-core/pkg/routing"
)

// TestMultiProtocol_DeepFallbackChain_SingBox tests a 5-hop synthetic fallback chain
// across Hysteria2 -> VLESS Reality -> Shadowsocks 2022 -> Trojan -> VMess
func TestMultiProtocol_DeepFallbackChain_SingBox(t *testing.T) {
	singboxBin := getBinPath("../../panel/bin/sing-box.exe")

	mockRealityKeys, err := crypto.GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("failed to generate synthetic reality keys: %v", err)
	}

	// 1. Primary: Hysteria 2 with 4 fallback destinations
	hy2Out := map[string]interface{}{
		"tag":      "mock-hy2-main",
		"protocol": "hysteria2",
		"settings": map[string]interface{}{
			"address":               "hy2.mock-provider.net",
			"port":                  "20000:30000",
			"password":              "synthetic_hy2_password_abc123",
			"backup_outbounds":      []string{"mock-vless-bak1", "mock-ss-bak2", "mock-trojan-bak3", "mock-vmess-bak4"},
			"health_check_url":      "https://www.gstatic.com/generate_204",
			"health_check_interval": 15,
			"fallback_strategy":     "priority",
			"obfs": map[string]interface{}{
				"type": "salamander",
				"salamander": map[string]interface{}{
					"password": "synthetic_salamander_pwd_987",
				},
			},
		},
		"streamSettings": map[string]interface{}{
			"security": "tls",
			"tlsSettings": map[string]interface{}{
				"serverName":    "mock-cdn.example.org",
				"allowInsecure": true,
			},
		},
	}

	// 2. Backup 1: VLESS Reality
	vlessOut := map[string]interface{}{
		"tag":      "mock-vless-bak1",
		"protocol": "vless",
		"settings": map[string]interface{}{
			"vnext": []interface{}{
				map[string]interface{}{
					"address": "vless.mock-provider.net",
					"port":    443,
					"users": []interface{}{
						map[string]interface{}{
							"id":         "a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d",
							"flow":       "xtls-rprx-vision",
							"encryption": "none",
						},
					},
				},
			},
		},
		"streamSettings": map[string]interface{}{
			"network":  "tcp",
			"security": "reality",
			"realitySettings": map[string]interface{}{
				"serverName":  "gateway.mock-target.com",
				"fingerprint": "chrome",
				"publicKey":   mockRealityKeys.PublicKey,
				"shortId":     "01234567",
			},
		},
	}

	// 3. Backup 2: Shadowsocks 2022 Blake3
	ssOut := map[string]interface{}{
		"tag":      "mock-ss-bak2",
		"protocol": "shadowsocks",
		"settings": map[string]interface{}{
			"method":   "2022-blake3-aes-128-gcm",
			"password": "AQEBAQEBAQEBAQEBAQEBAQ==",
			"servers": []map[string]interface{}{
				{
					"address": "ss.mock-provider.net",
					"port":    8388,
				},
			},
		},
	}

	// 4. Backup 3: Trojan with gRPC & TLS
	trojanOut := map[string]interface{}{
		"tag":      "mock-trojan-bak3",
		"protocol": "trojan",
		"settings": map[string]interface{}{
			"servers": []map[string]interface{}{
				{
					"address":  "trojan.mock-provider.net",
					"port":     443,
					"password": "synthetic_trojan_pwd_456",
				},
			},
		},
		"streamSettings": map[string]interface{}{
			"network":  "grpc",
			"security": "tls",
			"grpcSettings": map[string]interface{}{
				"serviceName": "mock-trojan-grpc-service",
			},
			"tlsSettings": map[string]interface{}{
				"serverName": "trojan.mock-provider.net",
			},
		},
	}

	// 5. Backup 4: VMess with WebSocket
	vmessOut := map[string]interface{}{
		"tag":      "mock-vmess-bak4",
		"protocol": "vmess",
		"settings": map[string]interface{}{
			"vnext": []interface{}{
				map[string]interface{}{
					"address": "vmess.mock-provider.net",
					"port":    443,
					"users": []interface{}{
						map[string]interface{}{
							"id":       "b2c3d4e5-f6a7-8b9c-0d1e-2f3a4b5c6d7e",
							"security": "auto",
						},
					},
				},
			},
		},
		"streamSettings": map[string]interface{}{
			"network":  "ws",
			"security": "none",
			"wsSettings": map[string]interface{}{
				"path": "/mock-vmess-path",
			},
		},
	}

	// Inbound with synthetic test parameters
	inbound := ast.ServerInboundSpec{
		Tag:      "mock-inbound",
		Port:     10443,
		Protocol: "vless",
		StreamSettings: map[string]interface{}{
			"security": "reality",
			"realitySettings": map[string]interface{}{
				"dest":        "gateway.mock-target.com:443",
				"serverNames": []string{"gateway.mock-target.com"},
				"privateKey":  mockRealityKeys.PrivateKey,
				"shortIds":    []string{"01234567"},
			},
		},
		Clients: []ast.ServerInboundClient{
			{
				ID:   "c3d4e5f6-a7b8-9c0d-1e2f-3a4b5c6d7e8f",
				Flow: "xtls-rprx-vision",
			},
		},
	}

	table := routing.NewRoutingTable("mock-hy2-main")
	routingAST := table.CompileToAST()
	routingAST.Outbounds = []map[string]interface{}{hy2Out, vlessOut, ssOut, trojanOut, vmessOut}

	cfgJSON, err := builder.BuildServerConfig(ast.CoreSingBox, []ast.ServerInboundSpec{inbound}, routingAST, "127.0.0.1:9090")
	if err != nil {
		t.Fatalf("failed to compile Sing-box deep fallback config: %v", err)
	}

	// Verifications in compiled JSON
	if !strings.Contains(cfgJSON, `"type": "urltest"`) {
		t.Fatalf("expected urltest group in Sing-box config, got:\n%s", cfgJSON)
	}
	if !strings.Contains(cfgJSON, `"tag": "mock-hy2-main"`) {
		t.Fatalf("expected urltest tag mock-hy2-main, got:\n%s", cfgJSON)
	}
	if !strings.Contains(cfgJSON, `"mock-hy2-main-primary"`) {
		t.Fatalf("expected primary node tag mock-hy2-main-primary, got:\n%s", cfgJSON)
	}
	if !strings.Contains(cfgJSON, `"mock-vless-bak1"`) {
		t.Fatalf("expected mock-vless-bak1 in outbounds, got:\n%s", cfgJSON)
	}
	if !strings.Contains(cfgJSON, `"mock-ss-bak2"`) {
		t.Fatalf("expected mock-ss-bak2 in outbounds, got:\n%s", cfgJSON)
	}
	if !strings.Contains(cfgJSON, `"mock-trojan-bak3"`) {
		t.Fatalf("expected mock-trojan-bak3 in outbounds, got:\n%s", cfgJSON)
	}
	if !strings.Contains(cfgJSON, `"mock-vmess-bak4"`) {
		t.Fatalf("expected mock-vmess-bak4 in outbounds, got:\n%s", cfgJSON)
	}

	// Live binary check
	if singboxBin != "" {
		tmpFile, err := os.CreateTemp("", "sb-deep-fallback-*.json")
		if err != nil {
			t.Fatalf("failed to create temp file: %v", err)
		}
		tmpFile.WriteString(cfgJSON)
		tmpFile.Close()

		cmd := exec.Command(singboxBin, "check", "-c", tmpFile.Name())
		out, err := cmd.CombinedOutput()
		os.Remove(tmpFile.Name())
		if err != nil {
			t.Fatalf("sing-box check failed for deep fallback chain: %v\nOutput: %s\nConfig:\n%s", err, string(out), cfgJSON)
		}
		t.Logf("Sing-box check passed 100%% successfully with 4-level fallback across 5 protocols!")
	}
}

// TestMultiProtocol_DeepFallbackChain_Xray tests a 4-level synthetic fallback chain in Xray
// with Observatory + Balancers across VLESS -> Shadowsocks -> Trojan -> VMess
func TestMultiProtocol_DeepFallbackChain_Xray(t *testing.T) {
	xrayBin := getBinPath("../../panel/bin/xray.exe")

	mockRealityKeys, err := crypto.GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("failed to generate synthetic reality keys: %v", err)
	}

	// 1. Primary: VLESS Reality with 3 fallbacks
	vlessOut := map[string]interface{}{
		"tag":      "mock-vless-main",
		"protocol": "vless",
		"settings": map[string]interface{}{
			"backup_outbounds":      []string{"mock-ss-bak1", "mock-trojan-bak2", "mock-vmess-bak3"},
			"health_check_url":      "https://www.gstatic.com/generate_204",
			"health_check_interval": 15,
			"vnext": []interface{}{
				map[string]interface{}{
					"address": "vless.mock-provider.net",
					"port":    443,
					"users": []interface{}{
						map[string]interface{}{
							"id":         "a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d",
							"flow":       "xtls-rprx-vision",
							"encryption": "none",
						},
					},
				},
			},
		},
		"streamSettings": map[string]interface{}{
			"network":  "tcp",
			"security": "reality",
			"realitySettings": map[string]interface{}{
				"serverName":  "gateway.mock-target.com",
				"fingerprint": "chrome",
				"publicKey":   mockRealityKeys.PublicKey,
				"shortId":     "01234567",
			},
		},
	}

	// 2. Backup 1: Shadowsocks
	ssOut := map[string]interface{}{
		"tag":      "mock-ss-bak1",
		"protocol": "shadowsocks",
		"settings": map[string]interface{}{
			"servers": []map[string]interface{}{
				{
					"address":  "ss.mock-provider.net",
					"port":     8388,
					"method":   "2022-blake3-aes-128-gcm",
					"password": "AQEBAQEBAQEBAQEBAQEBAQ==",
				},
			},
		},
	}

	// 3. Backup 2: Trojan TLS
	trojanOut := map[string]interface{}{
		"tag":      "mock-trojan-bak2",
		"protocol": "trojan",
		"settings": map[string]interface{}{
			"servers": []map[string]interface{}{
				{
					"address":  "trojan.mock-provider.net",
					"port":     443,
					"password": "synthetic_trojan_pwd_456",
				},
			},
		},
		"streamSettings": map[string]interface{}{
			"security": "tls",
			"tlsSettings": map[string]interface{}{
				"serverName": "trojan.mock-provider.net",
			},
		},
	}

	// 4. Backup 3: VMess TCP
	vmessOut := map[string]interface{}{
		"tag":      "mock-vmess-bak3",
		"protocol": "vmess",
		"settings": map[string]interface{}{
			"vnext": []interface{}{
				map[string]interface{}{
					"address": "vmess.mock-provider.net",
					"port":    443,
					"users": []interface{}{
						map[string]interface{}{
							"id":       "b2c3d4e5-f6a7-8b9c-0d1e-2f3a4b5c6d7e",
							"security": "auto",
						},
					},
				},
			},
		},
	}

	inbound := ast.ServerInboundSpec{
		Tag:      "mock-inbound",
		Port:     10444,
		Protocol: "vless",
		StreamSettings: map[string]interface{}{
			"security": "reality",
			"realitySettings": map[string]interface{}{
				"dest":        "gateway.mock-target.com:443",
				"serverNames": []string{"gateway.mock-target.com"},
				"privateKey":  mockRealityKeys.PrivateKey,
				"shortIds":    []string{"01234567"},
			},
		},
		Clients: []ast.ServerInboundClient{
			{
				ID:   "c3d4e5f6-a7b8-9c0d-1e2f-3a4b5c6d7e8f",
				Flow: "xtls-rprx-vision",
			},
		},
	}

	table := routing.NewRoutingTable("mock-vless-main")
	routingAST := table.CompileToAST()
	routingAST.Outbounds = []map[string]interface{}{vlessOut, ssOut, trojanOut, vmessOut}

	cfgJSON, err := builder.BuildServerConfig(ast.CoreXray, []ast.ServerInboundSpec{inbound}, routingAST, "")
	if err != nil {
		t.Fatalf("failed to compile Xray deep fallback config: %v", err)
	}

	// Verifications in compiled JSON
	if !strings.Contains(cfgJSON, `"observatory"`) {
		t.Fatalf("expected observatory in Xray config, got:\n%s", cfgJSON)
	}
	if !strings.Contains(cfgJSON, `"balancer-mock-vless-main"`) {
		t.Fatalf("expected balancer-mock-vless-main in config, got:\n%s", cfgJSON)
	}
	if !strings.Contains(cfgJSON, `"fallbackTag": "mock-ss-bak1"`) {
		t.Fatalf("expected fallbackTag mock-ss-bak1, got:\n%s", cfgJSON)
	}

	// Live binary check
	if xrayBin != "" {
		tmpFile, err := os.CreateTemp("", "xray-deep-fallback-*.json")
		if err != nil {
			t.Fatalf("failed to create temp file: %v", err)
		}
		tmpFile.WriteString(cfgJSON)
		tmpFile.Close()

		cmd := exec.Command(xrayBin, "-test", "-config", tmpFile.Name())
		out, err := cmd.CombinedOutput()
		os.Remove(tmpFile.Name())
		if err != nil {
			t.Fatalf("xray check failed for deep fallback chain: %v\nOutput: %s\nConfig:\n%s", err, string(out), cfgJSON)
		}
		t.Logf("Xray check passed 100%% successfully with 3-level fallback across 4 protocols!")
	}
}
