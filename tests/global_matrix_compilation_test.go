package tests

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/blackalex1/sentinel-core/pkg/ast"
	"github.com/blackalex1/sentinel-core/pkg/builder"
	"github.com/blackalex1/sentinel-core/pkg/compiler/hysteria"
	"github.com/blackalex1/sentinel-core/pkg/compiler/singbox"
	"github.com/blackalex1/sentinel-core/pkg/compiler/wireguard"
	"github.com/blackalex1/sentinel-core/pkg/compiler/xray"
	"github.com/blackalex1/sentinel-core/pkg/crypto"
	"github.com/blackalex1/sentinel-core/pkg/routing"
)

// TestGlobal_SingBox_AllInbounds_And_AllOutbounds_Compilation creates synthetic test fixtures
// containing ALL supported protocol inbounds and outbounds with all possible configuration options,
// compiles the full Sing-box server configuration, and verifies it with the Sing-box engine.
func TestGlobal_SingBox_AllInbounds_And_AllOutbounds_Compilation(t *testing.T) {
	realityKeys, err := crypto.GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("failed to generate reality keys: %v", err)
	}

	// Generate self-signed cert for TLS inbounds
	certPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "mock.example.com"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, &template, &template, &certPriv.PublicKey, certPriv)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	privDER, _ := x509.MarshalECPrivateKey(certPriv)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privDER})

	certFile, _ := os.CreateTemp("", "mock-cert-*.pem")
	certFile.Write(certPEM)
	certFile.Close()
	defer os.Remove(certFile.Name())

	keyFile, _ := os.CreateTemp("", "mock-key-*.pem")
	keyFile.Write(keyPEM)
	keyFile.Close()
	defer os.Remove(keyFile.Name())

	// 1. Construct comprehensive synthetic inbounds for ALL protocols
	inbounds := []ast.ServerInboundSpec{
		// 1. VLESS Reality (Vision flow, ShortIDs, Handshake SNI)
		{
			Tag:        "vless-reality-in",
			Port:       30001,
			Protocol:   "vless",
			Transport:  "tcp",
			Security:   "reality",
			SNI:        "mock-sni.example.com",
			PrivateKey: realityKeys.PrivateKey,
			ShortIDs:   []string{"0123456789abcdef", "fedcba9876543210"},
			Clients: []ast.ServerInboundClient{
				{
					ID:   "00000000-0000-0000-0000-000000000001",
					UUID: "00000000-0000-0000-0000-000000000001",
					Flow: "xtls-rprx-vision",
				},
			},
		},
		// 2. VLESS WebSocket with TLS
		{
			Tag:       "vless-ws-in",
			Port:      30002,
			Protocol:  "vless",
			Transport: "ws",
			Security:  "tls",
			SNI:       "ws.example.com",
			CertPath:  certFile.Name(),
			KeyPath:   keyFile.Name(),
			StreamSettings: map[string]interface{}{
				"network": "ws",
				"wsSettings": map[string]interface{}{
					"path": "/vless-ws",
					"headers": map[string]interface{}{
						"Host": "ws.example.com",
					},
				},
			},
			Clients: []ast.ServerInboundClient{
				{
					ID:   "00000000-0000-0000-0000-000000000002",
					UUID: "00000000-0000-0000-0000-000000000002",
				},
			},
		},
		// 3. VMess WebSocket TLS
		{
			Tag:       "vmess-ws-in",
			Port:      30003,
			Protocol:  "vmess",
			Transport: "ws",
			Security:  "tls",
			SNI:       "vmess.example.com",
			CertPath:  certFile.Name(),
			KeyPath:   keyFile.Name(),
			StreamSettings: map[string]interface{}{
				"network": "ws",
				"wsSettings": map[string]interface{}{
					"path": "/vmess-ws",
					"headers": map[string]interface{}{
						"Host": "vmess.example.com",
					},
				},
			},
			Clients: []ast.ServerInboundClient{
				{
					ID:   "00000000-0000-0000-0000-000000000003",
					UUID: "00000000-0000-0000-0000-000000000003",
				},
			},
		},
		// 4. Trojan gRPC TLS
		{
			Tag:       "trojan-grpc-in",
			Port:      30004,
			Protocol:  "trojan",
			Transport: "grpc",
			Security:  "tls",
			SNI:       "trojan.example.com",
			CertPath:  certFile.Name(),
			KeyPath:   keyFile.Name(),
			StreamSettings: map[string]interface{}{
				"network": "grpc",
				"grpcSettings": map[string]interface{}{
					"serviceName": "TrojanGrpcService",
				},
			},
			Clients: []ast.ServerInboundClient{
				{
					ID:       "trojan-password-synthetic",
					Password: "trojan-password-synthetic",
				},
			},
		},
		// 5. Shadowsocks 2022 AEAD
		{
			Tag:      "ss-2022-in",
			Port:     30005,
			Protocol: "shadowsocks",
			RawSettings: map[string]interface{}{
				"method":   "2022-blake3-aes-128-gcm",
				"password": "AQEBAQEBAQEBAQEBAQEBAQ==",
			},
		},
		// 6. Shadowsocks Classic AEAD
		{
			Tag:      "ss-aead-in",
			Port:     30006,
			Protocol: "shadowsocks",
			RawSettings: map[string]interface{}{
				"method":   "aes-256-gcm",
				"password": "mock-password-32B-secure-string",
			},
		},
		// 7. Hysteria 2 with Port Hopping, Salamander obfs, and bandwidth
		{
			Tag:           "hysteria2-in",
			Port:          30007,
			Protocol:      "hysteria2",
			PortHop:       "40000-50000",
			BandwidthUp:   "100mbps",
			BandwidthDown: "200mbps",
			ObfsType:      "salamander",
			ObfsPassword:  "mock-salamander-secret",
			Security:      "tls",
			SNI:           "hy2.example.com",
			CertPath:      certFile.Name(),
			KeyPath:       keyFile.Name(),
			RawSettings: map[string]interface{}{
				"password": "mock-hy2-auth-string",
			},
		},
		// 8. TUIC v5 with BBR, Native UDP, and 0-RTT
		{
			Tag:      "tuic-in",
			Port:     30008,
			Protocol: "tuic",
			Security: "tls",
			SNI:      "tuic.example.com",
			CertPath: certFile.Name(),
			KeyPath:  keyFile.Name(),
			Clients: []ast.ServerInboundClient{
				{
					UUID:     "00000000-0000-0000-0000-000000000008",
					Password: "mock-tuic-pass",
				},
			},
			RawSettings: map[string]interface{}{
				"congestion_control": "bbr",
				"udp_relay_mode":     "native",
				"zero_rtt_handshake": true,
			},
		},
		// 9. HTTP Inbound with Users
		{
			Tag:      "http-in",
			Port:     30010,
			Protocol: "http",
			Clients: []ast.ServerInboundClient{
				{Email: "mock_user_1", Password: "mock_pass_1"},
				{Email: "mock_user_2", Password: "mock_pass_2"},
			},
		},
		// 10. SOCKS5 Inbound with Users
		{
			Tag:      "socks-in",
			Port:     30011,
			Protocol: "socks",
			Clients: []ast.ServerInboundClient{
				{Email: "mock_socks_user", Password: "mock_socks_pass"},
			},
		},
	}

	// 2. Construct comprehensive synthetic outbounds for ALL protocols
	outboundProfiles := []*ast.ServerProfile{
		// 1. Direct
		{Protocol: ast.ProtoDirect, Name: "out-direct"},
		// 2. Block
		{Protocol: ast.ProtoBlock, Name: "out-block"},
		// 3. VLESS Reality Outbound
		{
			Protocol:    ast.ProtoVLESS,
			Name:        "out-vless-reality",
			Address:     "vless.example.com",
			Port:        443,
			UUID:        "00000000-0000-0000-0000-000000000010",
			Flow:        "xtls-rprx-vision",
			Security:    "reality",
			SNI:         "www.apple.com",
			PublicKey:   realityKeys.PublicKey,
			ShortID:     "0123456789abcdef",
			Fingerprint: "chrome",
		},
		// 4. VLESS WebSocket TLS
		{
			Protocol:    ast.ProtoVLESS,
			Name:        "out-vless-ws",
			Address:     "vless-ws.example.com",
			Port:        443,
			UUID:        "00000000-0000-0000-0000-000000000011",
			Transport:   "ws",
			Path:        "/ws-path",
			Host:        "vless-ws.example.com",
			Security:    "tls",
			SNI:         "vless-ws.example.com",
			Fingerprint: "chrome",
		},
		// 5. VMess HTTPUpgrade TLS
		{
			Protocol:    ast.ProtoVMess,
			Name:        "out-vmess",
			Address:     "vmess.example.com",
			Port:        443,
			UUID:        "00000000-0000-0000-0000-000000000012",
			Transport:   "httpupgrade",
			Path:        "/hu-path",
			Host:        "vmess.example.com",
			Security:    "tls",
			SNI:         "vmess.example.com",
			Fingerprint: "firefox",
		},
		// 6. Trojan gRPC TLS
		{
			Protocol:    ast.ProtoTrojan,
			Name:        "out-trojan",
			Address:     "trojan.example.com",
			Port:        443,
			Password:    "mock-trojan-pass",
			Transport:   "grpc",
			ServiceName: "TrojanGrpcOut",
			Security:    "tls",
			SNI:         "trojan.example.com",
		},
		// 7. Shadowsocks 2022
		{
			Protocol: ast.ProtoShadowsocks,
			Name:     "out-ss-2022",
			Address:  "ss.example.com",
			Port:     8388,
			Cipher:   "2022-blake3-aes-128-gcm",
			Password: "AQEBAQEBAQEBAQEBAQEBAQ==",
		},
		// 8. Hysteria 2 (Port Hopping range, Salamander obfs, Bandwidth, TLS ALPN h3, Insecure)
		{
			Protocol:      ast.ProtoHysteria2,
			Name:          "out-hysteria2",
			Address:       "hy2.example.com",
			Port:          443,
			PortHopping:   "40000-50000",
			Password:      "mock-hy2-pass",
			BandwidthUp:   "100mbps",
			BandwidthDown: "200mbps",
			ObfsType:      "salamander",
			ObfsPassword:  "mock-salamander-secret",
			SNI:           "hy2.example.com",
			Insecure:      true,
			ALPN:          []string{"h3"},
			Extra: map[string]interface{}{
				"hop_interval": "30s",
			},
		},
		// 9. TUIC v5 Outbound
		{
			Protocol:          ast.ProtoTUIC,
			Name:              "out-tuic",
			Address:           "tuic.example.com",
			Port:              8443,
			UUID:              "00000000-0000-0000-0000-000000000014",
			Password:          "mock-tuic-pass",
			CongestionControl: "bbr",
			UDPRelayMode:      "native",
			ZeroRTTHandshake:  true,
			SNI:               "tuic.example.com",
		},
		// 10. ShadowTLS v3 Outbound
		{
			Protocol:          ast.ProtoShadowTLS,
			Name:              "out-shadowtls",
			Address:           "stls.example.com",
			Port:              443,
			ShadowTLSVersion:  3,
			ShadowTLSPassword: "mock-stls-password",
			ShadowTLSSNI:     "gateway.icloud.com",
			Fingerprint:       "chrome",
		},
		// 11. SOCKS Outbound
		{
			Protocol: ast.ProtoSocks,
			Name:     "out-socks",
			Address:  "socks.example.com",
			Port:     1080,
			Username: "mock-user",
			Password: "mock-pass",
		},
		// 12. HTTP Outbound
		{
			Protocol: ast.ProtoHTTP,
			Name:     "out-http",
			Address:  "http.example.com",
			Port:     8080,
			Username: "mock-user",
			Password: "mock-pass",
		},
	}

	var compiledOutbounds []map[string]interface{}
	for _, p := range outboundProfiles {
		obMap, err := singbox.BuildSingBoxOutbound(p)
		if err != nil {
			t.Fatalf("failed to build singbox outbound for %s: %v", p.Protocol, err)
		}
		compiledOutbounds = append(compiledOutbounds, obMap)
	}

	// 3. Test Raw Database Map Compilation for Hysteria 2 with Port Hopping and Salamander
	rawHy2 := map[string]interface{}{
		"tag":      "raw-hy2-hopping",
		"protocol": "hysteria2",
		"settings": map[string]interface{}{
			"address":   "mock-hy2.example.com",
			"port":      "20000-30000",
			"password":  "mock_auth_secret",
			"up_mbps":   100,
			"down_mbps": 200,
			"obfs": map[string]interface{}{
				"type": "salamander",
				"salamander": map[string]interface{}{
					"password": "mock_salamander_secret",
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
	compiledRawHy2 := singbox.CompileRawOutboundToSingbox(rawHy2)
	compiledOutbounds = append(compiledOutbounds, compiledRawHy2)

	// 4. Build Complete Routing Table
	table := routing.NewRoutingTable("out-direct")
	table.AddRule(routing.RoutingRuleRow{
		Order:   1,
		Name:    "Route Torrent to Block",
		Enabled: true,
		Target:  "out-block",
		Domains: []string{"torrent", "tracker"},
	})
	table.AddRule(routing.RoutingRuleRow{
		Order:   2,
		Name:    "Route Example to VLESS",
		Enabled: true,
		Target:  "out-vless-reality",
		Domains: []string{"domain:example.com"},
	})
	table.AddRule(routing.RoutingRuleRow{
		Order:   3,
		Name:    "Route Hysteria to Raw Hopping",
		Enabled: true,
		Target:  "raw-hy2-hopping",
		Domains: []string{"domain:hy2-target.com"},
	})

	routingAST := table.CompileToAST()
	routingAST.Outbounds = compiledOutbounds

	// 5. Compile Full Sing-box Configuration
	cfgJSON, err := builder.BuildServerConfig(ast.CoreSingBox, inbounds, routingAST, "")
	if err != nil {
		t.Fatalf("failed to compile Sing-box master configuration: %v", err)
	}

	// 6. Validate JSON parsing
	var parsedJSON map[string]interface{}
	if err := json.Unmarshal([]byte(cfgJSON), &parsedJSON); err != nil {
		t.Fatalf("compiled Sing-box config is not valid JSON: %v\nJSON:\n%s", err, cfgJSON)
	}

	// Verify absence of forbidden legacy fields
	if strings.Contains(cfgJSON, `"pinned_peer_cert_sha256"`) {
		t.Errorf("Sing-box config MUST NOT contain pinned_peer_cert_sha256")
	}
	if strings.Contains(cfgJSON, `"salamander": {`) {
		t.Errorf("Sing-box config MUST NOT contain nested salamander struct")
	}

	// 7. Verify with real sing-box binary if available on system
	singboxBin := getBinPath("../../panel/bin/sing-box.exe")
	if singboxBin == "" {
		singboxBin = getBinPath("sing-box")
	}
	if singboxBin != "" {
		tmpFile, err := os.CreateTemp("", "singbox-global-test-*.json")
		if err != nil {
			t.Fatalf("failed to create temp file: %v", err)
		}
		defer os.Remove(tmpFile.Name())

		if _, err := tmpFile.WriteString(cfgJSON); err != nil {
			t.Fatalf("failed to write temp file: %v", err)
		}
		tmpFile.Close()

		cmd := exec.Command(singboxBin, "check", "-c", tmpFile.Name())
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("sing-box check failed on comprehensive matrix: %v\nOutput:\n%s", err, string(out))
		}
		t.Logf("Sing-box check passed 100%% successfully with live binary!")
	}
}

// TestGlobal_Xray_AllInbounds_And_AllOutbounds_Compilation tests full matrix compilation for Xray-core
func TestGlobal_Xray_AllInbounds_And_AllOutbounds_Compilation(t *testing.T) {
	realityKeys, err := crypto.GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("failed to generate reality keys: %v", err)
	}

	inbounds := []ast.ServerInboundSpec{
		{
			Tag:        "vless-xray-in",
			Port:       31001,
			Protocol:   "vless",
			Transport:  "tcp",
			Security:   "reality",
			SNI:        "xray-mock.example.com",
			PrivateKey: realityKeys.PrivateKey,
			ShortIDs:   []string{"0123456789abcdef"},
			Clients: []ast.ServerInboundClient{
				{
					ID:   "00000000-0000-0000-0000-000000000001",
					UUID: "00000000-0000-0000-0000-000000000001",
					Flow: "xtls-rprx-vision",
				},
			},
		},
		{
			Tag:       "vmess-xray-in",
			Port:      31002,
			Protocol:  "vmess",
			Transport: "ws",
			StreamSettings: map[string]interface{}{
				"network": "ws",
				"wsSettings": map[string]interface{}{
					"path": "/vmess-xray",
				},
			},
			Clients: []ast.ServerInboundClient{
				{
					ID:   "00000000-0000-0000-0000-000000000002",
					UUID: "00000000-0000-0000-0000-000000000002",
				},
			},
		},
		{
			Tag:      "trojan-xray-in",
			Port:     31003,
			Protocol: "trojan",
			Clients: []ast.ServerInboundClient{
				{Password: "mock-trojan-pass"},
			},
		},
		{
			Tag:      "ss-xray-in",
			Port:     31004,
			Protocol: "shadowsocks",
			RawSettings: map[string]interface{}{
				"method":   "2022-blake3-aes-128-gcm",
				"password": "AQEBAQEBAQEBAQEBAQEBAQ==",
			},
		},
	}

	outboundProfiles := []*ast.ServerProfile{
		{Protocol: ast.ProtoDirect, Name: "direct"},
		{Protocol: ast.ProtoBlock, Name: "block"},
		{
			Protocol:    ast.ProtoVLESS,
			Name:        "vless-out",
			Address:     "vless.example.com",
			Port:        443,
			UUID:        "00000000-0000-0000-0000-000000000001",
			Flow:        "xtls-rprx-vision",
			Security:    "reality",
			SNI:         "www.apple.com",
			PublicKey:   realityKeys.PublicKey,
			ShortID:     "0123456789abcdef",
			Fingerprint: "chrome",
		},
		{
			Protocol:  ast.ProtoVMess,
			Name:      "vmess-out",
			Address:   "vmess.example.com",
			Port:      443,
			UUID:      "00000000-0000-0000-0000-000000000002",
			Transport: "ws",
			Path:      "/vmess",
			Security:  "tls",
			SNI:       "vmess.example.com",
		},
		{
			Protocol: ast.ProtoTrojan,
			Name:     "trojan-out",
			Address:  "trojan.example.com",
			Port:     443,
			Password: "mock-trojan-pass",
			Security: "tls",
			SNI:      "trojan.example.com",
		},
		{
			Protocol: ast.ProtoShadowsocks,
			Name:     "ss-out",
			Address:  "ss.example.com",
			Port:     8388,
			Cipher:   "2022-blake3-aes-128-gcm",
			Password: "AQEBAQEBAQEBAQEBAQEBAQ==",
		},
		{
			Protocol:      ast.ProtoWireGuard,
			Name:          "wg-out",
			Address:       "wg.example.com",
			Port:          51820,
			PrivateKey:    "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
			PeerPublicKey: "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=",
			PreSharedKey:  "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=",
			LocalAddress:  []string{"10.0.0.2/32"},
			MTU:           1420,
		},
		{
			Protocol: ast.ProtoHysteria2,
			Name:     "hy2-socks-detour",
			Address:  "127.0.0.1",
			Port:     10808,
		},
	}

	var compiledOutbounds []map[string]interface{}
	for _, p := range outboundProfiles {
		obMap, err := xray.BuildXrayOutbound(p)
		if err != nil {
			t.Fatalf("failed to build xray outbound for %s: %v", p.Protocol, err)
		}
		compiledOutbounds = append(compiledOutbounds, obMap)
	}

	table := routing.NewRoutingTable("direct")
	table.AddRule(routing.RoutingRuleRow{
		Order:   1,
		Name:    "Route Secure Domain",
		Enabled: true,
		Target:  "vless-out",
		Domains: []string{"domain:secure.com"},
	})

	routingAST := table.CompileToAST()
	routingAST.Outbounds = compiledOutbounds

	cfgJSON, err := builder.BuildServerConfig(ast.CoreXray, inbounds, routingAST, "")
	if err != nil {
		t.Fatalf("failed to compile Xray server config: %v", err)
	}

	var parsedJSON map[string]interface{}
	if err := json.Unmarshal([]byte(cfgJSON), &parsedJSON); err != nil {
		t.Fatalf("compiled Xray config is not valid JSON: %v\nJSON:\n%s", err, cfgJSON)
	}

	xrayBin := getBinPath("../../panel/bin/xray.exe")
	if xrayBin == "" {
		xrayBin = getBinPath("xray")
	}
	if xrayBin != "" {
		tmpFile, err := os.CreateTemp("", "xray-global-test-*.json")
		if err != nil {
			t.Fatalf("failed to create temp file: %v", err)
		}
		defer os.Remove(tmpFile.Name())

		if _, err := tmpFile.WriteString(cfgJSON); err != nil {
			t.Fatalf("failed to write temp file: %v", err)
		}
		tmpFile.Close()

		cmd := exec.Command(xrayBin, "-test", "-config", tmpFile.Name())
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("xray check failed on comprehensive matrix: %v\nOutput:\n%s", err, string(out))
		}
		t.Logf("Xray check passed 100%% successfully with live binary!")
	}
}

// TestGlobal_Hysteria2_Standalone_Compilation tests standalone Hysteria 2 server and client compilers
func TestGlobal_Hysteria2_Standalone_Compilation(t *testing.T) {
	// Generate self-signed cert for TLS
	certPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "hy2.example.com"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, &template, &template, &certPriv.PublicKey, certPriv)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	privDER, _ := x509.MarshalECPrivateKey(certPriv)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privDER})

	certFile, _ := os.CreateTemp("", "hy2-cert-*.pem")
	certFile.Write(certPEM)
	certFile.Close()
	defer os.Remove(certFile.Name())

	keyFile, _ := os.CreateTemp("", "hy2-key-*.pem")
	keyFile.Write(keyPEM)
	keyFile.Close()
	defer os.Remove(keyFile.Name())

	// 1. Test Server Compiler with maximum parameter set
	inboundSpec := ast.ServerInboundSpec{
		Tag:            "hy2-server-master",
		Port:           34443,
		Protocol:       "hysteria2",
		PortHop:        "34443-44443",
		AdminPort:      19090,
		AuthURL:        "http://127.0.0.1:8080/api/auth",
		ObfsType:       "salamander",
		ObfsPassword:   "salamander_super_secret_password",
		BandwidthUp:    "500mbps",
		BandwidthDown:  "1000mbps",
		MasqType:       "proxy",
		MasqValue:      "https://example.com",
		MasqStatusCode: 200,
		CertPath:       certFile.Name(),
		KeyPath:        keyFile.Name(),
	}

	sc := hysteria.NewServerCompiler()
	srvJSON, err := sc.CompileServer(inboundSpec, 10808, "debug")
	if err != nil {
		t.Fatalf("failed to compile Hysteria 2 server config: %v", err)
	}

	var parsedSrv map[string]interface{}
	if err := json.Unmarshal([]byte(srvJSON), &parsedSrv); err != nil {
		t.Fatalf("compiled Hysteria 2 server config is not valid JSON: %v", err)
	}

	if !strings.Contains(srvJSON, `"listen": ":34443"`) {
		t.Errorf("Hysteria 2 server config missing listen port: %s", srvJSON)
	}
	if !strings.Contains(srvJSON, "salamander_super_secret_password") {
		t.Errorf("Hysteria 2 server config missing obfs password: %s", srvJSON)
	}

	// 2. Test Client Compiler with maximum parameter set
	clientNode := &ast.ServerProfile{
		Protocol:      ast.ProtoHysteria2,
		Name:          "hy2-client-node",
		Address:       "hy2.example.com",
		Port:          443,
		PortHopping:   "40000-50000",
		Password:      "user_auth_secret",
		BandwidthUp:   "100mbps",
		BandwidthDown: "200mbps",
		ObfsType:      "salamander",
		ObfsPassword:  "salamander_super_secret_password",
		SNI:           "hy2.example.com",
		Insecure:      true,
		Extra: map[string]interface{}{
			"hop_interval": "15s",
		},
	}

	spec := &ast.ConfigSpec{
		TargetCore: ast.CoreHysteria2,
		ServerNode: clientNode,
		ClientInbound: &ast.ClientInboundSpec{
			SocksPort: 10808,
			HTTPPort:  10809,
		},
	}

	cc := hysteria.NewCompiler()
	clientJSON, _, err := cc.Compile(spec)
	if err != nil {
		t.Fatalf("failed to compile Hysteria 2 client config: %v", err)
	}

	var parsedClient map[string]interface{}
	if err := json.Unmarshal([]byte(clientJSON), &parsedClient); err != nil {
		t.Fatalf("compiled Hysteria 2 client config is not valid JSON: %v", err)
	}

	if !strings.Contains(clientJSON, "40000-50000") {
		t.Errorf("Hysteria 2 client config missing port hopping: %s", clientJSON)
	}
	t.Logf("Hysteria 2 standalone server and client compilers passed 100%% successfully!")
}

// TestGlobal_WireGuard_Standalone_Compilation tests standalone WireGuard INI config compiler
func TestGlobal_WireGuard_Standalone_Compilation(t *testing.T) {
	node := &ast.ServerProfile{
		Protocol:      ast.ProtoWireGuard,
		Name:          "wg-full-node",
		Address:       "wg.example.com",
		Port:          51820,
		PrivateKey:    "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
		PeerPublicKey: "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=",
		PreSharedKey:  "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=",
		LocalAddress:  []string{"10.0.0.2/32", "fc00::2/128"},
		MTU:           1420,
	}

	conf, err := wireguard.BuildWireGuardConf(node)
	if err != nil {
		t.Fatalf("failed to compile WireGuard .conf: %v", err)
	}

	if !strings.Contains(conf, "[Interface]") || !strings.Contains(conf, "[Peer]") {
		t.Fatalf("WireGuard .conf missing standard sections: %s", conf)
	}
	if !strings.Contains(conf, "PrivateKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=") {
		t.Errorf("WireGuard .conf missing PrivateKey")
	}
	if !strings.Contains(conf, "PublicKey = AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=") {
		t.Errorf("WireGuard .conf missing PublicKey")
	}
	if !strings.Contains(conf, "PresharedKey = AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=") {
		t.Errorf("WireGuard .conf missing PresharedKey")
	}
	if !strings.Contains(conf, "Address = 10.0.0.2/32, fc00::2/128") {
		t.Errorf("WireGuard .conf missing Address list")
	}
	if !strings.Contains(conf, "MTU = 1420") {
		t.Errorf("WireGuard .conf missing MTU")
	}
	t.Logf("WireGuard standalone compiler passed 100%% successfully!")
}

