package tests

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/blackalex1/sentinel-core/pkg/ast"
	"github.com/blackalex1/sentinel-core/pkg/builder"
	"github.com/blackalex1/sentinel-core/pkg/compiler/hysteria"
	"github.com/blackalex1/sentinel-core/pkg/crypto"
	"github.com/blackalex1/sentinel-core/pkg/matrix"
)

const (
	// Generated with panel/bin/xray.exe vlessenc (Authentication: X25519)
	testVlessEncX25519Client = "mlkem768x25519plus.native.0rtt.5fC7yNdk9zyapGqqEAiWnf1rSzYK8R2E8cw-3DWpJgE"
	testVlessDecX25519Server = "mlkem768x25519plus.native.600s.2PH_cN6i9d_Inek5wS733lAR-hjAfx1NlYXl_b4bXnk"

	// Generated with panel/bin/xray.exe vlessenc (Authentication: ML-KEM-768 Post-Quantum)
	testVlessEncPQClient = "mlkem768x25519plus.native.0rtt.prM4cCJN5JqWSBoGJxdHZ_MIYLk6v8iTl8tljNpaqDBjEdwaOqyB1GZIMre0E9BXzbqzFDI82MqetpifADGJiep5uZKzk8yNRnkxpQYX9EcdQBajDyhGO8UXZXMU5SirTCR6Bjwp2mCd3OxXm0lzb2cz2flMzpJajNVF5TwtrVBtg1e7LFoZ2dtTP3JFbRI6g5Vpeemb-rYTNdNWc0yD4EVgSkQgOXnMW_dPceAWu-xmELoXqWq9WCG16Ss4ZMSNCSWn50E_9bUXbpVV2kCrhamq0HUAYPHAKyFXryN7xylOWqRt3DNblkUcmUeQikirFXVz08vMQ8BV7JnA-gJJuxU-Uax18bY1MeeeaVcDo1AYBDO1dglPtegab2y5a2ylk8QU_4O4SQGC9pOjsLMlKDyUyKdNYCKuIPxyh0Fz4RaPPDBslbgy5DYilDkOlZZcuKJEicmck0VG6UBfjOt7vKgYflcTEsbOEid5OvUvWmDNpZgQe7KSM4lr0IRQvgERiDJPjLoRzZMGDqEz28WxUMNwKkavk1fPHvorSNWsrqCtJiuyFOUJDjG-Jtu22SfKmpO9vMit2zlY5WY1VFtlCjUzfBOODFpHCWe-lsG4WnUZCIVcGEE01UVlG_SwF9Y1tasM80KXKhFZ5pp6ySxiWqt8DozIvpBTllSK-QmrZagnvSGLytHI8xF5AlccNds_5vivIom0_2uUvYc5RGdRNkAOZxyo7dxJZUGjdjtPy_d6awZdbMhSkbNIQJPI67EGeJiM1YTKj-tInCAcpTd8CRN4BGDN93mewgdxxfteMICgt7mV9JLH_cmHGUweDFGXf1B0UxiknbOdGYtyS5ott8iE_DdUgDhfUyyzR5uQYaWeKSvBSmw73VK-pRygfDuMzHNF4WhqahF8-vANcRsjMzcQ2PVaSkEikoAgqlm6nbNTBnoqVZK3kZuGkAW_nSysvCK9_vSXZzIHJ2pjWzbDmnMQnKYMbwnF-QvBJWzHsTo-AaVSqFo8dNHN4dy0m8RdTNWKo7aBimkO6MwEE6wbYcezSeKp5JiMHjB_NNGuKNcYhngHl2UFWsOV1UIEPEOGDqkuTPIm6Rq02xVRUkMUPAQjSwxVoDqL52AZmPmvCligFrhK5kZxVhRpk6Ylt8ih8jYauNwVMotIAbMsDozOS6G4G5dhuwycx6Y7AbKz_DEhZ6Kca3mQzbuADOG4_LNTGhlOaMELA8oSEmd0tXOg6NhtgEAicwPDwNZFlPpJK2YyvTXBafJKAUkSFEJW9KMGFmnMq5Zy16ALAtJaKWlxNIsLV2FrvjqnWXwDcDcDi4uttpeX8-l0AkC4FsfACvI4ynGV8_uvu8N0L8xHCrBvGHYs2iIbyVKYzbEPjNMeg5ZXm2EM6bOCSghTNpRiv1E0lIYRbAJKhbHMjMi9X5NUmjt63FJHV9wVLfJ2tOo5Tkthw4FWBJCB0iCRMoCoITUGrKOBEdu4UEGuUxYbvOGK8mu-2kuPvAGGZNsgNZKHXyq-ElU7G9CEfjMp1we6tmMdlBvu5lOBXPBRLcN28L68XIDVZRQIryYnTbngZDjs9xg"
	testVlessDecPQServer = "mlkem768x25519plus.native.600s.T34ZW0oKFdFAv-zlK2eEg2DEifdlQ8HGjinjagwrtuoaMTMi1trtyxsFOew1NBE7huddueVEXVySUaHNM_O6kA"
)

func assertXrayConfigValid(t *testing.T, xrayBin, cfgJSON string) {
	t.Helper()
	if xrayBin == "" {
		t.Skip("xray binary not found, skipping live check")
		return
	}
	f, err := os.CreateTemp("", "xray-perm-*.json")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(f.Name())
	_, _ = f.WriteString(cfgJSON)
	_ = f.Close()

	cmd := exec.Command(xrayBin, "-test", "-config", f.Name())
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("xray -test rejected config: %v\nOutput:\n%s\nConfig:\n%s", err, string(out), cfgJSON)
	}
}

func assertSingboxConfigValid(t *testing.T, singboxBin, cfgJSON string) {
	t.Helper()
	if singboxBin == "" {
		t.Skip("sing-box binary not found, skipping live check")
		return
	}
	f, err := os.CreateTemp("", "sb-perm-*.json")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(f.Name())
	_, _ = f.WriteString(cfgJSON)
	_ = f.Close()

	if out, err := runSingboxCheck(singboxBin, f.Name()); err != nil {
		t.Fatalf("sing-box check rejected config: %v\nOutput:\n%s\nConfig:\n%s", err, string(out), cfgJSON)
	}
}

func assertHysteriaConfigValid(t *testing.T, hyBin, mode, cfgJSON string) {
	t.Helper()
	if hyBin == "" {
		t.Skip("hysteria binary not found, skipping live check")
		return
	}
	f, err := os.CreateTemp("", "hy2-perm-*.json")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(f.Name())
	_, _ = f.WriteString(cfgJSON)
	_ = f.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 350*time.Millisecond)
	defer cancel()

	cmd := exec.CommandContext(ctx, hyBin, mode, "-c", f.Name(), "--disable-update-check")
	out, _ := cmd.CombinedOutput()
	outStr := string(out)
	lower := strings.ToLower(outStr)
	for _, bad := range []string{
		"failed to load config",
		"failed to parse config",
		"invalid character",
		"unknown field",
		"failed to initialize",
	} {
		if strings.Contains(lower, bad) {
			t.Fatalf("hysteria %s failed config validation (%s):\nOutput:\n%s\nConfig:\n%s", mode, bad, outStr, cfgJSON)
		}
	}
}

func baseClientInbound() *ast.ClientInboundSpec {
	return &ast.ClientInboundSpec{
		Mode:          ast.InboundModeSystemProxy,
		SocksPort:     nextTestPort(),
		HTTPPort:      nextTestPort(),
		ListenAddress: "127.0.0.1",
	}
}

func compileStrictClient(t *testing.T, target ast.TargetCore, node *ast.ServerProfile) string {
	t.Helper()
	res, err := builder.BuildClientConfig(&ast.ConfigSpec{
		TargetCore:    target,
		StrictMode:    true,
		LogLevel:      "warn",
		ClientInbound: baseClientInbound(),
		ServerNode:    node,
		Routing:       &ast.RoutingSpec{},
	})
	if err != nil {
		t.Fatalf("BuildClientConfig(core=%s, proto=%s, net=%s, sec=%s, strict=true) failed: %v", target, node.Protocol, node.Transport, node.Security, err)
	}
	return res.ConfigJSON
}

func testSHA256Pin() string {
	sum := sha256.Sum256([]byte("sentinel-test-cert"))
	return hex.EncodeToString(sum[:])
}

func allSchemaFingerprints() []string {
	schema := matrix.GetConfigurationSchema("en")
	if vless, ok := schema.OutboundProtocols[ast.ProtoVLESS]; ok && len(vless.EngineFingerprints["xray-core"]) > 0 {
		return vless.EngineFingerprints["xray-core"]
	}
	return []string{"chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random", "randomized"}
}

func TestLive_FullSchemaPermutations_VLESS_Xray(t *testing.T) {
	xrayBin := findCoreBin("xray")
	realityKeys, err := crypto.GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair failed: %v", err)
	}
	fingerprints := allSchemaFingerprints()

	// 1. VLESS Xray transports x compatible securities
	xrayTransports := []struct {
		name       string
		transport  string
		headerType string
		xhttpMode  string
		multiMode  bool
	}{
		{"tcp", ast.TransportTCP, "", "", false},
		{"tcp_http", ast.TransportTCP, "http", "", false},
		{"ws", ast.TransportWS, "", "", false},
		{"grpc_single", ast.TransportGRPC, "", "", false},
		{"grpc_multi", ast.TransportGRPC, "", "", true},
		{"httpupgrade", ast.TransportHTTPUpgrade, "", "", false},
		{"xhttp_auto", ast.TransportXHTTP, "", "auto", false},
		{"xhttp_packet_up", ast.TransportXHTTP, "", "packet-up", false},
		{"xhttp_stream_up", ast.TransportXHTTP, "", "stream-up", false},
		{"xhttp_stream_one", ast.TransportXHTTP, "", "stream-one", false},
	}

	// KCP obfs types supported on Xray
	for _, kcpType := range []string{"none", "srtp", "utp", "wechat-video", "dtls", "wireguard"} {
		t.Run("Outbound_KCP_"+kcpType, func(t *testing.T) {
			cfg := compileStrictClient(t, ast.CoreXray, &ast.ServerProfile{
				Name:       "kcp-" + kcpType,
				Protocol:   ast.ProtoVLESS,
				Address:    "203.0.113.10",
				Port:       nextTestPort(),
				UUID:       "e99dc462-8409-4e45-bf28-665544332211",
				Transport:  ast.TransportKCP,
				Security:   ast.SecurityNone,
				HeaderType: kcpType,
			})
			assertXrayConfigValid(t, xrayBin, cfg)
		})
	}

	for _, tr := range xrayTransports {
		secs := []string{ast.SecurityNone, ast.SecurityTLS}
		// Xray REALITY is valid on RAW(tcp plain), gRPC, and XHTTP
		if tr.transport == ast.TransportGRPC || tr.transport == ast.TransportXHTTP || (tr.transport == ast.TransportTCP && tr.headerType == "") {
			secs = append(secs, ast.SecurityReality)
		}

		for _, sec := range secs {
			t.Run("Outbound_"+tr.name+"_"+sec, func(t *testing.T) {
				node := &ast.ServerProfile{
					Name:        tr.name + "-" + sec,
					Protocol:    ast.ProtoVLESS,
					Address:     "203.0.113.11",
					Port:        443,
					UUID:        "e99dc462-8409-4e45-bf28-665544332211",
					Transport:   tr.transport,
					Security:    sec,
					HeaderType:  tr.headerType,
					XHTTPMode:   tr.xhttpMode,
					MultiMode:   tr.multiMode,
					Path:        "/vless-path",
					Host:        "cdn.example.com",
					ServiceName: "vless.GrpcService",
				}
				if sec == ast.SecurityTLS {
					node.SNI = "cdn.example.com"
					node.ALPN = []string{"h2", "http/1.1"}
					node.Fingerprint = "chrome"
				} else if sec == ast.SecurityReality {
					node.SNI = "www.microsoft.com"
					node.PublicKey = realityKeys.PublicKey
					node.ShortID = "aabbccdd"
					node.SpiderX = "/custom-spider"
					node.Fingerprint = "chrome"
				}
				cfg := compileStrictClient(t, ast.CoreXray, node)
				assertXrayConfigValid(t, xrayBin, cfg)
			})
		}
	}

	// 2. Xray VLESS Flows, Fingerprints, PostQuantum, Insecure, VLESS Encryption (X25519 + ML-KEM-768)
	for _, flow := range []string{"", "xtls-rprx-vision", "xtls-rprx-vision-udp443"} {
		for _, sec := range []string{ast.SecurityTLS, ast.SecurityReality} {
			name := fmt.Sprintf("Outbound_Flow_%s_%s", sec, flow)
			if flow == "" {
				name = fmt.Sprintf("Outbound_Flow_%s_none", sec)
			}
			t.Run(name, func(t *testing.T) {
				node := &ast.ServerProfile{
					Name:        name,
					Protocol:    ast.ProtoVLESS,
					Address:     "203.0.113.12",
					Port:        443,
					UUID:        "e99dc462-8409-4e45-bf28-665544332211",
					Transport:   ast.TransportTCP,
					Security:    sec,
					Flow:        flow,
					Fingerprint: "chrome",
					PostQuantum: true,
				}
				if sec == ast.SecurityTLS {
					node.SNI = "cdn.example.com"
					node.ALPN = []string{"h2", "http/1.1"}
					node.Insecure = true
				} else {
					node.SNI = "www.microsoft.com"
					node.PublicKey = realityKeys.PublicKey
					node.ShortID = "11223344"
					node.SpiderX = "/"
				}
				cfg := compileStrictClient(t, ast.CoreXray, node)
				assertXrayConfigValid(t, xrayBin, cfg)
			})
		}
	}

	for _, fp := range fingerprints {
		t.Run("Outbound_Fingerprint_"+fp, func(t *testing.T) {
			cfg := compileStrictClient(t, ast.CoreXray, &ast.ServerProfile{
				Name:        "fp-" + fp,
				Protocol:    ast.ProtoVLESS,
				Address:     "203.0.113.13",
				Port:        443,
				UUID:        "e99dc462-8409-4e45-bf28-665544332211",
				Transport:   ast.TransportTCP,
				Security:    ast.SecurityReality,
				Flow:        "xtls-rprx-vision",
				SNI:         "www.apple.com",
				PublicKey:   realityKeys.PublicKey,
				ShortID:     "001122",
				SpiderX:     "/",
				Fingerprint: fp,
			})
			assertXrayConfigValid(t, xrayBin, cfg)
		})
	}

	for _, enc := range []struct {
		name string
		val  string
	}{
		{"plain", "none"},
		{"vlessenc_x25519", testVlessEncX25519Client},
		{"vlessenc_mlkem768_pq", testVlessEncPQClient},
	} {
		t.Run("Outbound_Encryption_"+enc.name, func(t *testing.T) {
			cfg := compileStrictClient(t, ast.CoreXray, &ast.ServerProfile{
				Name:       "enc-" + enc.name,
				Protocol:   ast.ProtoVLESS,
				Address:    "203.0.113.14",
				Port:       443,
				UUID:       "e99dc462-8409-4e45-bf28-665544332211",
				Transport:  ast.TransportXHTTP,
				XHTTPMode:  "auto",
				Path:       "/enc",
				Security:   ast.SecurityNone,
				Encryption: enc.val,
			})
			assertXrayConfigValid(t, xrayBin, cfg)
		})
	}

	// Non-strict negotiation: legacy h2 -> xhttp stream-one on Xray 26+
	t.Run("Outbound_LegacyH2_AutoMigratesToXHTTP", func(t *testing.T) {
		res, err := builder.BuildClientConfig(&ast.ConfigSpec{
			TargetCore:    ast.CoreXray,
			StrictMode:    false,
			LogLevel:      "warn",
			ClientInbound: baseClientInbound(),
			ServerNode: &ast.ServerProfile{
				Name:      "legacy-h2",
				Protocol:  ast.ProtoVLESS,
				Address:   "203.0.113.15",
				Port:      443,
				UUID:      "e99dc462-8409-4e45-bf28-665544332211",
				Transport: ast.TransportH2,
				Security:  ast.SecurityTLS,
				SNI:       "cdn.example.com",
				Path:      "/legacy-h2",
			},
			Routing: &ast.RoutingSpec{},
		})
		if err != nil {
			t.Fatalf("BuildClientConfig(legacy h2 non-strict) failed: %v", err)
		}
		assertXrayConfigValid(t, xrayBin, res.ConfigJSON)
	})

	// 3. Xray VLESS Server Inbounds (all transports + Reality spiderX + TLS + Fallbacks + Decryption)
	certPath, keyPath, cleanup := createTestCertAndKey(t)
	defer cleanup()

	serverCases := []struct {
		name string
		spec ast.ServerInboundSpec
	}{
		{
			name: "Inbound_TCP_REALITY_Vision_SpiderX",
			spec: ast.ServerInboundSpec{
				Tag:        "vless-real-in",
				Protocol:   ast.ProtoVLESS,
				Port:       nextTestPort(),
				Transport:  ast.TransportTCP,
				Security:   ast.SecurityReality,
				SNI:        "www.microsoft.com",
				PrivateKey: realityKeys.PrivateKey,
				ShortIDs:   []string{"aabbccdd"},
				Clients:    []ast.ServerInboundClient{{UUID: "e99dc462-8409-4e45-bf28-665544332211", Email: "u1", Flow: "xtls-rprx-vision"}},
				StreamSettings: map[string]interface{}{
					"realitySettings": map[string]interface{}{
						"spiderX": "/custom",
					},
				},
			},
		},
		{
			name: "Inbound_TCP_TLS_Fallbacks",
			spec: ast.ServerInboundSpec{
				Tag:       "vless-tls-fb",
				Protocol:  ast.ProtoVLESS,
				Port:      nextTestPort(),
				Transport: ast.TransportTCP,
				Security:  ast.SecurityTLS,
				SNI:       "vpn.example.com",
				CertPath:  certPath,
				KeyPath:   keyPath,
				Clients:   []ast.ServerInboundClient{{UUID: "e99dc462-8409-4e45-bf28-665544332211", Email: "u1", Flow: "xtls-rprx-vision"}},
				Fallbacks: []map[string]interface{}{{"dest": 8080, "xver": 1}},
			},
		},
		{
			name: "Inbound_TCP_HTTP_Obfuscation",
			spec: ast.ServerInboundSpec{
				Tag:       "vless-tcp-http",
				Protocol:  ast.ProtoVLESS,
				Port:      nextTestPort(),
				Transport: ast.TransportTCP,
				Security:  ast.SecurityNone,
				Clients:   []ast.ServerInboundClient{{UUID: "e99dc462-8409-4e45-bf28-665544332211", Email: "u1"}},
				StreamSettings: map[string]interface{}{
					"tcpSettings": map[string]interface{}{
						"header": map[string]interface{}{
							"type": "http",
							"request": map[string]interface{}{
								"path": []interface{}{"/index.html"},
							},
						},
					},
				},
			},
		},
		{
			name: "Inbound_GRPC_MultiMode",
			spec: ast.ServerInboundSpec{
				Tag:       "vless-grpc-multi",
				Protocol:  ast.ProtoVLESS,
				Port:      nextTestPort(),
				Transport: ast.TransportGRPC,
				Security:  ast.SecurityTLS,
				CertPath:  certPath,
				KeyPath:   keyPath,
				Clients:   []ast.ServerInboundClient{{UUID: "e99dc462-8409-4e45-bf28-665544332211", Email: "u1"}},
				StreamSettings: map[string]interface{}{
					"grpcSettings": map[string]interface{}{
						"serviceName": "grpcMulti",
						"multiMode":   true,
					},
				},
			},
		},
		{
			name: "Inbound_XHTTP_PacketUp_DecryptionPQ",
			spec: ast.ServerInboundSpec{
				Tag:       "vless-xhttp-dec",
				Protocol:  ast.ProtoVLESS,
				Port:      nextTestPort(),
				Transport: ast.TransportXHTTP,
				Security:  ast.SecurityNone,
				Clients:   []ast.ServerInboundClient{{UUID: "e99dc462-8409-4e45-bf28-665544332211", Email: "u1"}},
				RawSettings: map[string]interface{}{
					"decryption": testVlessDecPQServer,
				},
				StreamSettings: map[string]interface{}{
					"xhttpSettings": map[string]interface{}{
						"mode": "packet-up",
						"path": "/xhttp-dec",
						"host": "cdn.example.com",
					},
				},
			},
		},
	}

	for _, sc := range serverCases {
		t.Run(sc.name, func(t *testing.T) {
			cfg, err := builder.BuildServerConfig(ast.CoreXray, []ast.ServerInboundSpec{sc.spec}, &ast.RoutingSpec{}, "")
			if err != nil {
				t.Fatalf("BuildServerConfig(%s) failed: %v", sc.name, err)
			}
			assertXrayConfigValid(t, xrayBin, cfg)
		})
	}
}

func TestLive_FullSchemaPermutations_VLESS_SingBox(t *testing.T) {
	sbBin := findCoreBin("sing-box")
	realityKeys, err := crypto.GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair failed: %v", err)
	}
	fingerprints := allSchemaFingerprints()

	for _, tr := range []string{ast.TransportTCP, ast.TransportWS, ast.TransportGRPC, ast.TransportHTTPUpgrade, ast.TransportH2} {
		secs := []string{ast.SecurityNone, ast.SecurityTLS}
		if tr == ast.TransportTCP || tr == ast.TransportGRPC || tr == ast.TransportH2 {
			secs = append(secs, ast.SecurityReality)
		}
		for _, sec := range secs {
			t.Run("Outbound_"+tr+"_"+sec, func(t *testing.T) {
				node := &ast.ServerProfile{
					Name:        tr + "-" + sec,
					Protocol:    ast.ProtoVLESS,
					Address:     "203.0.113.21",
					Port:        443,
					UUID:        "e99dc462-8409-4e45-bf28-665544332211",
					Transport:   tr,
					Security:    sec,
					Path:        "/sb-path",
					Host:        "cdn.example.com",
					ServiceName: "sbGrpc",
				}
				if sec == ast.SecurityTLS {
					node.SNI = "cdn.example.com"
					node.ALPN = []string{"h2", "http/1.1"}
					node.Fingerprint = "chrome"
				} else if sec == ast.SecurityReality {
					node.SNI = "www.microsoft.com"
					node.PublicKey = realityKeys.PublicKey
					node.ShortID = "aabbccdd"
					node.Fingerprint = "chrome"
				}
				cfg := compileStrictClient(t, ast.CoreSingBox, node)
				assertSingboxConfigValid(t, sbBin, cfg)
			})
		}
	}

	// Sing-box flows ("" and "xtls-rprx-vision") & all fingerprints
	for _, flow := range []string{"", "xtls-rprx-vision"} {
		for _, sec := range []string{ast.SecurityTLS, ast.SecurityReality} {
			tag := flow
			if tag == "" {
				tag = "none"
			}
			t.Run("Outbound_Flow_"+sec+"_"+tag, func(t *testing.T) {
				node := &ast.ServerProfile{
					Name:        "sb-flow-" + tag,
					Protocol:    ast.ProtoVLESS,
					Address:     "203.0.113.22",
					Port:        443,
					UUID:        "e99dc462-8409-4e45-bf28-665544332211",
					Transport:   ast.TransportTCP,
					Security:    sec,
					Flow:        flow,
					Fingerprint: "chrome",
				}
				if sec == ast.SecurityTLS {
					node.SNI = "cdn.example.com"
					node.ALPN = []string{"h2", "http/1.1"}
					node.Insecure = true
				} else {
					node.SNI = "www.apple.com"
					node.PublicKey = realityKeys.PublicKey
					node.ShortID = "123456"
				}
				cfg := compileStrictClient(t, ast.CoreSingBox, node)
				assertSingboxConfigValid(t, sbBin, cfg)
			})
		}
	}

	for _, fp := range fingerprints {
		t.Run("Outbound_Fingerprint_"+fp, func(t *testing.T) {
			cfg := compileStrictClient(t, ast.CoreSingBox, &ast.ServerProfile{
				Name:        "sb-fp-" + fp,
				Protocol:    ast.ProtoVLESS,
				Address:     "203.0.113.23",
				Port:        443,
				UUID:        "e99dc462-8409-4e45-bf28-665544332211",
				Transport:   ast.TransportTCP,
				Security:    ast.SecurityReality,
				Flow:        "xtls-rprx-vision",
				SNI:         "www.apple.com",
				PublicKey:   realityKeys.PublicKey,
				ShortID:     "001122",
				Fingerprint: fp,
			})
			assertSingboxConfigValid(t, sbBin, cfg)
		})
	}

	certPath, keyPath, cleanup := createTestCertAndKey(t)
	defer cleanup()

	for _, tr := range []string{ast.TransportTCP, ast.TransportWS, ast.TransportGRPC, ast.TransportHTTPUpgrade, ast.TransportH2} {
		sec := ast.SecurityTLS
		if tr == ast.TransportTCP {
			sec = ast.SecurityReality
		}
		t.Run("Inbound_"+tr+"_"+sec, func(t *testing.T) {
			in := ast.ServerInboundSpec{
				Tag:       "sb-vless-" + tr,
				Protocol:  ast.ProtoVLESS,
				Port:      nextTestPort(),
				Transport: tr,
				Security:  sec,
				SNI:       "www.microsoft.com",
				Clients:   []ast.ServerInboundClient{{UUID: "e99dc462-8409-4e45-bf28-665544332211", Email: "u1"}},
			}
			if sec == ast.SecurityReality {
				in.PrivateKey = realityKeys.PrivateKey
				in.ShortIDs = []string{"aabbccdd"}
				in.Clients[0].Flow = "xtls-rprx-vision"
			} else {
				in.CertPath = certPath
				in.KeyPath = keyPath
			}
			if tr == ast.TransportGRPC {
				in.StreamSettings = map[string]interface{}{"grpcSettings": map[string]interface{}{"serviceName": "sbGrpc"}}
			} else if tr != ast.TransportTCP {
				in.StreamSettings = map[string]interface{}{tr + "Settings": map[string]interface{}{"path": "/in-" + tr, "host": "cdn.example.com"}}
			}
			cfg, err := builder.BuildServerConfig(ast.CoreSingBox, []ast.ServerInboundSpec{in}, &ast.RoutingSpec{}, "")
			if err != nil {
				t.Fatalf("BuildServerConfig(sing-box %s) failed: %v", tr, err)
			}
			assertSingboxConfigValid(t, sbBin, cfg)
		})
	}
}

func TestLive_FullSchemaPermutations_Hysteria2_AllEngines(t *testing.T) {
	hyBin := findCoreBin("hysteria")
	sbBin := findCoreBin("sing-box")
	xrayBin := findCoreBin("xray")
	pin := testSHA256Pin()

	obfsCases := []struct {
		name string
		typ  string
		pass string
	}{
		{"plain", "", ""},
		{"salamander", "salamander", "sal-pass-123"},
	}

	// 1. Native Hysteria 2 client + server
	for _, ob := range obfsCases {
		for _, insecure := range []bool{false, true} {
			name := fmt.Sprintf("Native_Client_%s_insecure_%v", ob.name, insecure)
			t.Run(name, func(t *testing.T) {
				node := &ast.ServerProfile{
					Name:                 name,
					Protocol:             ast.ProtoHysteria2,
					Address:              "203.0.113.30",
					Port:                 443,
					Password:             "hy2-secret",
					SNI:                  "hy2.example.com",
					ALPN:                 []string{"h3"},
					Insecure:             insecure,
					ObfsType:             ob.typ,
					ObfsPassword:         ob.pass,
					PortHopping:          "20000-40000",
					BandwidthUp:          "100 mbps",
					BandwidthDown:        "500 mbps",
					PinnedPeerCertSha256: pin,
				}
				comp := hysteria.NewCompiler()
				cfg, _, err := comp.Compile(&ast.ConfigSpec{
					TargetCore:    ast.CoreHysteria2,
					LogLevel:      "info",
					ClientInbound: baseClientInbound(),
					ServerNode:    node,
				})
				if err != nil {
					t.Fatalf("hysteria compile failed: %v", err)
				}
				assertHysteriaConfigValid(t, hyBin, "client", cfg)
			})
		}
	}

	certPath, keyPath, cleanup := createTestCertAndKey(t)
	defer cleanup()
	for _, masq := range []struct {
		typ string
		val string
	}{
		{"proxy", "https://www.bing.com"},
		{"string", "Not Found"},
	} {
		t.Run("Native_Server_masq_"+masq.typ, func(t *testing.T) {
			cfg, err := builder.BuildServerConfig(ast.CoreHysteria2, []ast.ServerInboundSpec{{
				Tag:           "hy2-srv",
				Protocol:      ast.ProtoHysteria2,
				Port:          nextTestPort(),
				CertPath:      certPath,
				KeyPath:       keyPath,
				Clients:       []ast.ServerInboundClient{{Email: "u1", Password: "hy2-srv-password"}},
				ObfsType:      "salamander",
				ObfsPassword:  "srv-sal-pass",
				BandwidthUp:   "200 mbps",
				BandwidthDown: "500 mbps",
				MasqType:      masq.typ,
				MasqValue:     masq.val,
			}}, nil, "")
			if err != nil {
				t.Fatalf("BuildServerConfig(hysteria2) failed: %v", err)
			}
			assertHysteriaConfigValid(t, hyBin, "server", cfg)
		})
	}

	// 2. Sing-box Hysteria 2 client + server
	for _, ob := range obfsCases {
		t.Run("SingBox_Client_"+ob.name, func(t *testing.T) {
			cfg := compileStrictClient(t, ast.CoreSingBox, &ast.ServerProfile{
				Name:          "sb-hy2-" + ob.name,
				Protocol:      ast.ProtoHysteria2,
				Address:       "203.0.113.31",
				Port:          443,
				Password:      "hy2-secret",
				SNI:           "hy2.example.com",
				ALPN:          []string{"h3"},
				Insecure:      true,
				ObfsType:      ob.typ,
				ObfsPassword:  ob.pass,
				PortHopping:   "20000-40000",
				BandwidthUp:   "100 mbps",
				BandwidthDown: "200 mbps",
			})
			assertSingboxConfigValid(t, sbBin, cfg)
		})
	}
	t.Run("SingBox_Server", func(t *testing.T) {
		cfg, err := builder.BuildServerConfig(ast.CoreSingBox, []ast.ServerInboundSpec{{
			Tag:           "sb-hy2-in",
			Protocol:      ast.ProtoHysteria2,
			Port:          nextTestPort(),
			CertPath:      certPath,
			KeyPath:       keyPath,
			Clients:       []ast.ServerInboundClient{{Email: "u1", Password: "hy2-srv-password"}},
			ObfsType:      "salamander",
			ObfsPassword:  "srv-sal-pass",
			BandwidthUp:   "200 mbps",
			BandwidthDown: "500 mbps",
			MasqType:      "proxy",
			MasqValue:     "https://www.bing.com",
		}}, &ast.RoutingSpec{}, "")
		if err != nil {
			t.Fatalf("BuildServerConfig(sing-box hy2) failed: %v", err)
		}
		assertSingboxConfigValid(t, sbBin, cfg)
	})

	// 3. Xray-core Hysteria 2 client outbound (including pinnedPeerCertSha256 & salamander & portHopping)
	for _, ob := range obfsCases {
		t.Run("Xray_Client_"+ob.name, func(t *testing.T) {
			cfg := compileStrictClient(t, ast.CoreXray, &ast.ServerProfile{
				Name:                 "xray-hy2-" + ob.name,
				Protocol:             ast.ProtoHysteria2,
				Address:              "203.0.113.32",
				Port:                 443,
				Password:             "hy2-secret",
				SNI:                  "hy2.example.com",
				ALPN:                 []string{"h3"},
				Insecure:             false,
				ObfsType:             ob.typ,
				ObfsPassword:         ob.pass,
				PortHopping:          "20000-40000",
				PinnedPeerCertSha256: pin,
			})
			assertXrayConfigValid(t, xrayBin, cfg)
		})
	}
}

func TestLive_FullSchemaPermutations_AllOtherProtocols(t *testing.T) {
	sbBin := findCoreBin("sing-box")
	xrayBin := findCoreBin("xray")
	realityKeys, err := crypto.GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair failed: %v", err)
	}

	raw16 := make([]byte, 16)
	raw32 := make([]byte, 32)
	_, _ = rand.Read(raw16)
	_, _ = rand.Read(raw32)
	k16 := base64.StdEncoding.EncodeToString(raw16)
	k32 := base64.StdEncoding.EncodeToString(raw32)

	// 1. Trojan across Xray & Sing-box
	for _, core := range []ast.TargetCore{ast.CoreXray, ast.CoreSingBox} {
		transports := []string{ast.TransportTCP, ast.TransportWS, ast.TransportGRPC, ast.TransportHTTPUpgrade, ast.TransportXHTTP}
		if core == ast.CoreSingBox {
			transports = []string{ast.TransportTCP, ast.TransportWS, ast.TransportGRPC, ast.TransportHTTPUpgrade, ast.TransportH2}
		}
		for _, tr := range transports {
			secs := []string{ast.SecurityTLS}
			if tr == ast.TransportTCP || tr == ast.TransportGRPC || tr == ast.TransportXHTTP || (core == ast.CoreSingBox && tr == ast.TransportH2) {
				secs = append(secs, ast.SecurityReality)
			}
			for _, sec := range secs {
				t.Run(fmt.Sprintf("Trojan_%s_%s_%s", core, tr, sec), func(t *testing.T) {
					node := &ast.ServerProfile{
						Name:        "trojan-" + tr,
						Protocol:    ast.ProtoTrojan,
						Address:     "203.0.113.40",
						Port:        443,
						Password:    "trojan-pass",
						Transport:   tr,
						Security:    sec,
						Path:        "/tr",
						Host:        "tr.example.com",
						ServiceName: "trGrpc",
						XHTTPMode:   "packet-up",
						MultiMode:   core == ast.CoreXray && tr == ast.TransportGRPC,
						Fingerprint: "chrome",
					}
					if sec == ast.SecurityTLS {
						node.SNI = "tr.example.com"
						node.ALPN = []string{"h2", "http/1.1"}
					} else {
						node.SNI = "www.microsoft.com"
						node.PublicKey = realityKeys.PublicKey
						node.ShortID = "aabbcc"
						if core == ast.CoreXray {
							node.SpiderX = "/tr-spx"
						}
					}
					cfg := compileStrictClient(t, core, node)
					if core == ast.CoreXray {
						assertXrayConfigValid(t, xrayBin, cfg)
					} else {
						assertSingboxConfigValid(t, sbBin, cfg)
					}
				})
			}
		}
	}

	// 2. VMess across Xray & Sing-box
	for _, core := range []ast.TargetCore{ast.CoreXray, ast.CoreSingBox} {
		transports := []string{ast.TransportTCP, ast.TransportWS, ast.TransportGRPC, ast.TransportHTTPUpgrade}
		if core == ast.CoreSingBox {
			transports = append(transports, ast.TransportH2)
		}
		for _, tr := range transports {
			for _, sec := range []string{ast.SecurityNone, ast.SecurityTLS} {
				t.Run(fmt.Sprintf("VMess_%s_%s_%s", core, tr, sec), func(t *testing.T) {
					node := &ast.ServerProfile{
						Name:        "vmess-" + tr,
						Protocol:    ast.ProtoVMess,
						Address:     "203.0.113.41",
						Port:        443,
						UUID:        "e99dc462-8409-4e45-bf28-665544332211",
						Transport:   tr,
						Security:    sec,
						Path:        "/vm",
						Host:        "vm.example.com",
						ServiceName: "vmGrpc",
					}
					if sec == ast.SecurityTLS {
						node.SNI = "vm.example.com"
						node.Fingerprint = "firefox"
					}
					cfg := compileStrictClient(t, core, node)
					if core == ast.CoreXray {
						assertXrayConfigValid(t, xrayBin, cfg)
					} else {
						assertSingboxConfigValid(t, sbBin, cfg)
					}
				})
			}
		}
	}

	// 3. Shadowsocks (shared + Xray-only xchacha20-ietf-poly1305)
	ssCiphers := []struct {
		cipher   string
		password string
		xrayOnly bool
	}{
		{"2022-blake3-aes-128-gcm", k16, false},
		{"2022-blake3-aes-256-gcm", k32, false},
		{"2022-blake3-chacha20-poly1305", k32, false},
		{"aes-128-gcm", "ss-pass-128", false},
		{"aes-256-gcm", "ss-pass-256", false},
		{"chacha20-ietf-poly1305", "ss-pass-chacha", false},
		{"xchacha20-ietf-poly1305", "ss-pass-xchacha", true},
	}
	for _, c := range ssCiphers {
		cores := []ast.TargetCore{ast.CoreXray}
		if !c.xrayOnly {
			cores = append(cores, ast.CoreSingBox)
		}
		for _, core := range cores {
			t.Run(fmt.Sprintf("Shadowsocks_%s_%s", core, c.cipher), func(t *testing.T) {
				cfg := compileStrictClient(t, core, &ast.ServerProfile{
					Name:     "ss-" + c.cipher,
					Protocol: ast.ProtoShadowsocks,
					Address:  "203.0.113.42",
					Port:     8388,
					Cipher:   c.cipher,
					Password: c.password,
				})
				if core == ast.CoreXray {
					assertXrayConfigValid(t, xrayBin, cfg)
				} else {
					assertSingboxConfigValid(t, sbBin, cfg)
				}
			})
		}
	}

	// 4. TUIC (Sing-box only): all congestionControl x udpRelayMode x zeroRttHandshake
	for _, cc := range []string{"bbr", "cubic", "new_reno"} {
		for _, relay := range []string{"native", "quic"} {
			for _, zeroRtt := range []bool{false, true} {
				name := fmt.Sprintf("TUIC_%s_%s_0rtt_%v", cc, relay, zeroRtt)
				t.Run(name, func(t *testing.T) {
					cfg := compileStrictClient(t, ast.CoreSingBox, &ast.ServerProfile{
						Name:              name,
						Protocol:          ast.ProtoTUIC,
						Address:           "203.0.113.43",
						Port:              443,
						UUID:              "e99dc462-8409-4e45-bf28-665544332211",
						Password:          "tuic-secret",
						SNI:               "tuic.example.com",
						ALPN:              []string{"h3"},
						CongestionControl: cc,
						UDPRelayMode:      relay,
						ZeroRTTHandshake:  zeroRtt,
						Insecure:          true,
					})
					assertSingboxConfigValid(t, sbBin, cfg)
				})
			}
		}
	}

	// 5. ShadowTLS (Sing-box only): versions 1, 2, 3
	for _, ver := range []int{1, 2, 3} {
		t.Run(fmt.Sprintf("ShadowTLS_v%d", ver), func(t *testing.T) {
			cfg := compileStrictClient(t, ast.CoreSingBox, &ast.ServerProfile{
				Name:             fmt.Sprintf("stls-v%d", ver),
				Protocol:         ast.ProtoShadowTLS,
				Address:          "203.0.113.44",
				Port:             443,
				Password:         "stls-pass",
				SNI:              "www.google.com",
				Fingerprint:      "chrome",
				ShadowTLSVersion: ver,
			})
			assertSingboxConfigValid(t, sbBin, cfg)
		})
	}

	// 6. WireGuard, SOCKS, HTTP on Xray & Sing-box
	wgPrivRaw := make([]byte, 32)
	wgPubRaw := make([]byte, 32)
	_, _ = rand.Read(wgPrivRaw)
	_, _ = rand.Read(wgPubRaw)
	wgPrivKey := base64.StdEncoding.EncodeToString(wgPrivRaw)
	wgPubKey := base64.StdEncoding.EncodeToString(wgPubRaw)
	for _, core := range []ast.TargetCore{ast.CoreXray, ast.CoreSingBox} {
		t.Run("WireGuard_"+string(core), func(t *testing.T) {
			cfg := compileStrictClient(t, core, &ast.ServerProfile{
				Name:          "wg-node",
				Protocol:      ast.ProtoWireGuard,
				Address:       "203.0.113.45",
				Port:          51820,
				PrivateKey:    wgPrivKey,
				PeerPublicKey: wgPubKey,
				LocalAddress:  []string{"10.0.0.2/32"},
				MTU:           1280,
				ReservedBytes: []int{1, 2, 3},
			})
			if core == ast.CoreXray {
				assertXrayConfigValid(t, xrayBin, cfg)
			} else {
				assertSingboxConfigValid(t, sbBin, cfg)
			}
		})

		t.Run("SOCKS_"+string(core), func(t *testing.T) {
			cfg := compileStrictClient(t, core, &ast.ServerProfile{
				Name:     "socks-node",
				Protocol: ast.ProtoSocks,
				Address:  "203.0.113.46",
				Port:     1080,
				Username: "u",
				Password: "p",
			})
			if core == ast.CoreXray {
				assertXrayConfigValid(t, xrayBin, cfg)
			} else {
				assertSingboxConfigValid(t, sbBin, cfg)
			}
		})

		t.Run("HTTP_"+string(core), func(t *testing.T) {
			cfg := compileStrictClient(t, core, &ast.ServerProfile{
				Name:     "http-node",
				Protocol: ast.ProtoHTTP,
				Address:  "203.0.113.47",
				Port:     8080,
				Username: "u",
				Password: "p",
				Security: ast.SecurityTLS,
				SNI:      "proxy.example.com",
			})
			if core == ast.CoreXray {
				assertXrayConfigValid(t, xrayBin, cfg)
			} else {
				assertSingboxConfigValid(t, sbBin, cfg)
			}
		})
	}
}
