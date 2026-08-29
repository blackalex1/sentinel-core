package tests

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
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

func findCoreBin(name string) string {
	candidates := []string{
		"../../panel/bin/" + name,
		"../../panel/bin/" + name + ".exe",
		"../../panel/bin/hysteria-windows-amd64.exe",
		"../bin/" + name,
		"../bin/" + name + ".exe",
	}
	for _, c := range candidates {
		if fi, err := os.Stat(c); err == nil && !fi.IsDir() {
			return c
		}
	}
	if lp, err := exec.LookPath(name); err == nil {
		return lp
	}
	return ""
}

func generateTempTLSKeyPair() (certPath, keyPath string, cleanup func(), err error) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "mock.sentinel.internal"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	privDER, _ := x509.MarshalECPrivateKey(priv)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privDER})

	certFile, _ := os.CreateTemp("", "mock-tls-cert-*.pem")
	certFile.Write(certPEM)
	certFile.Close()

	keyFile, _ := os.CreateTemp("", "mock-tls-key-*.pem")
	keyFile.Write(keyPEM)
	keyFile.Close()

	cleanup = func() {
		os.Remove(certFile.Name())
		os.Remove(keyFile.Name())
	}
	return certFile.Name(), keyFile.Name(), cleanup, nil
}

// ==============================================================================
// 1. SING-BOX: Exhaustive Protocol & Real Binary Verification
// ==============================================================================
func TestLiveVerification_SingBox_AllProtocols(t *testing.T) {
	singboxBin := findCoreBin("sing-box")
	if singboxBin == "" {
		t.Skip("sing-box binary not found, skipping live binary execution")
	}

	certPath, keyPath, cleanupTLS, err := generateTempTLSKeyPair()
	if err != nil {
		t.Fatalf("failed to generate temp TLS certs: %v", err)
	}
	defer cleanupTLS()

	realityKeys, err := crypto.GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("failed to generate reality keys: %v", err)
	}

	// Generate exact 16-byte base64 key for ss 2022-blake3-aes-128-gcm
	rawKey16 := make([]byte, 16)
	rand.Read(rawKey16)
	ssKey16 := base64.StdEncoding.EncodeToString(rawKey16)

	protocols := []struct {
		name     string
		inbound  ast.ServerInboundSpec
		outbound *ast.ServerProfile
	}{
		{
			name: "VLESS_Reality_Vision_TCP",
			inbound: ast.ServerInboundSpec{
				Tag:        "vless-reality-in",
				Port:       31001,
				Protocol:   "vless",
				Transport:  "tcp",
				Security:   "reality",
				SNI:        "gateway.icloud.com",
				PrivateKey: realityKeys.PrivateKey,
				ShortIDs:   []string{"0123456789abcdef"},
				Clients: []ast.ServerInboundClient{
					{UUID: "e99dc462-8409-4e45-bf28-665544332211", Flow: "xtls-rprx-vision"},
				},
			},
			outbound: &ast.ServerProfile{
				Protocol:    ast.ProtoVLESS,
				Name:        "vless-reality-out",
				Address:     "ro.sentinel.internal",
				Port:        443,
				UUID:        "e99dc462-8409-4e45-bf28-665544332211",
				Security:    ast.SecurityReality,
				SNI:         "gateway.icloud.com",
				Flow:        "xtls-rprx-vision",
				Fingerprint: "chrome",
				PublicKey:   realityKeys.PublicKey,
				ShortID:     "0123456789abcdef",
			},
		},
		{
			name: "VLESS_TLS_gRPC",
			inbound: ast.ServerInboundSpec{
				Tag:       "vless-grpc-in",
				Port:      31002,
				Protocol:  "vless",
				Transport: "grpc",
				Security:  "tls",
				SNI:       "mock.sentinel.internal",
				CertPath:  certPath,
				KeyPath:   keyPath,
				StreamSettings: map[string]interface{}{
					"grpcSettings": map[string]interface{}{
						"serviceName": "vless-grpc",
					},
				},
				Clients: []ast.ServerInboundClient{
					{UUID: "e99dc462-8409-4e45-bf28-665544332211"},
				},
			},
			outbound: &ast.ServerProfile{
				Protocol:    ast.ProtoVLESS,
				Name:        "vless-grpc-out",
				Address:     "grpc.sentinel.internal",
				Port:        443,
				UUID:        "e99dc462-8409-4e45-bf28-665544332211",
				Transport:   ast.TransportGRPC,
				ServiceName: "vless-grpc",
				Security:    ast.SecurityTLS,
				SNI:         "mock.sentinel.internal",
				Fingerprint: "chrome",
			},
		},
		{
			name: "VLESS_TLS_WebSocket",
			inbound: ast.ServerInboundSpec{
				Tag:       "vless-ws-in",
				Port:      31003,
				Protocol:  "vless",
				Transport: "ws",
				Security:  "tls",
				SNI:       "mock.sentinel.internal",
				CertPath:  certPath,
				KeyPath:   keyPath,
				StreamSettings: map[string]interface{}{
					"wsSettings": map[string]interface{}{
						"path": "/vless-ws",
					},
				},
				Clients: []ast.ServerInboundClient{
					{UUID: "e99dc462-8409-4e45-bf28-665544332211"},
				},
			},
			outbound: &ast.ServerProfile{
				Protocol:    ast.ProtoVLESS,
				Name:        "vless-ws-out",
				Address:     "ws.sentinel.internal",
				Port:        443,
				UUID:        "e99dc462-8409-4e45-bf28-665544332211",
				Transport:   ast.TransportWS,
				Path:        "/vless-ws",
				Security:    ast.SecurityTLS,
				SNI:         "mock.sentinel.internal",
			},
		},
		{
			name: "Hysteria2_SalamanderObfs_PortHopping",
			inbound: ast.ServerInboundSpec{
				Tag:          "hy2-in",
				Port:         31004,
				Protocol:     "hysteria2",
				Security:     "tls",
				SNI:          "mock.sentinel.internal",
				CertPath:     certPath,
				KeyPath:      keyPath,
				ObfsType:     "salamander",
				ObfsPassword: "obfspassword123",
				Clients: []ast.ServerInboundClient{
					{Password: "hy2secretpassword", Email: "user@sentinel"},
				},
			},
			outbound: &ast.ServerProfile{
				Protocol:      ast.ProtoHysteria2,
				Name:          "hy2-out",
				Address:       "hy2.sentinel.internal",
				Port:          443,
				PortHopping:   "40000-50000",
				Password:      "hy2secretpassword",
				ObfsType:      "salamander",
				ObfsPassword:  "obfspassword123",
				SNI:           "mock.sentinel.internal",
				Insecure:      true,
				BandwidthUp:   "100mbps",
				BandwidthDown: "300mbps",
			},
		},
		{
			name: "Trojan_TLS_gRPC",
			inbound: ast.ServerInboundSpec{
				Tag:       "trojan-in",
				Port:      31005,
				Protocol:  "trojan",
				Transport: "grpc",
				Security:  "tls",
				SNI:       "mock.sentinel.internal",
				CertPath:  certPath,
				KeyPath:   keyPath,
				StreamSettings: map[string]interface{}{
					"grpcSettings": map[string]interface{}{
						"serviceName": "trojan-grpc",
					},
				},
				Clients: []ast.ServerInboundClient{
					{Password: "trojanpassword123"},
				},
			},
			outbound: &ast.ServerProfile{
				Protocol:    ast.ProtoTrojan,
				Name:        "trojan-out",
				Address:     "trojan.sentinel.internal",
				Port:        443,
				Password:    "trojanpassword123",
				Transport:   ast.TransportGRPC,
				ServiceName: "trojan-grpc",
				Security:    ast.SecurityTLS,
				SNI:         "mock.sentinel.internal",
			},
		},
		{
			name: "Shadowsocks_2022_Blake3_Aes128Gcm",
			inbound: ast.ServerInboundSpec{
				Tag:      "ss-2022-in",
				Port:     31006,
				Protocol: "shadowsocks",
				RawSettings: map[string]interface{}{
					"method":   "2022-blake3-aes-128-gcm",
					"password": ssKey16,
				},
				Clients: []ast.ServerInboundClient{
					{Password: ssKey16},
				},
			},
			outbound: &ast.ServerProfile{
				Protocol: ast.ProtoShadowsocks,
				Name:     "ss-2022-out",
				Address:  "ss.sentinel.internal",
				Port:     8388,
				Cipher:   "2022-blake3-aes-128-gcm",
				Password: ssKey16,
			},
		},
		{
			name: "TUIC_v5_BBR",
			inbound: ast.ServerInboundSpec{
				Tag:      "tuic-in",
				Port:     31007,
				Protocol: "tuic",
				Security: "tls",
				SNI:      "mock.sentinel.internal",
				CertPath: certPath,
				KeyPath:  keyPath,
				Clients: []ast.ServerInboundClient{
					{UUID: "e99dc462-8409-4e45-bf28-665544332211", Password: "tuicpassword"},
				},
			},
			outbound: &ast.ServerProfile{
				Protocol: ast.ProtoTUIC,
				Name:     "tuic-out",
				Address:  "tuic.sentinel.internal",
				Port:     443,
				UUID:     "e99dc462-8409-4e45-bf28-665544332211",
				Password: "tuicpassword",
				SNI:      "mock.sentinel.internal",
				Insecure: true,
			},
		},
	}

	for _, p := range protocols {
		t.Run(p.name, func(t *testing.T) {
			// 1. Build Server Config
			table := routing.NewRoutingTable(p.outbound.Name)
			routingAST := table.CompileToAST()

			compiledOut, err := singbox.BuildSingBoxOutbound(p.outbound)
			if err != nil {
				t.Fatalf("singbox build outbound failed for %s: %v", p.name, err)
			}
			routingAST.Outbounds = []map[string]interface{}{compiledOut}

			serverCfg, err := builder.BuildServerConfig(ast.CoreSingBox, []ast.ServerInboundSpec{p.inbound}, routingAST, "127.0.0.1:9090")
			if err != nil {
				t.Fatalf("failed to compile Sing-box server config for %s: %v", p.name, err)
			}

			// Validate Server Config with Real Sing-box
			tmpServer, _ := os.CreateTemp("", "sb-server-*.json")
			tmpServer.WriteString(serverCfg)
			tmpServer.Close()
			defer os.Remove(tmpServer.Name())

			cmdServer := exec.Command(singboxBin, "check", "-c", tmpServer.Name())
			outS, errS := cmdServer.CombinedOutput()
			if errS != nil {
				t.Fatalf("Sing-box check FAILED on Server Config for %s: %v\nOutput: %s\nConfig:\n%s", p.name, errS, string(outS), serverCfg)
			}

			// 2. Build Client Config
			clientSpec := &ast.ConfigSpec{
				TargetCore: ast.CoreSingBox,
				ServerNode: p.outbound,
				ClientInbound: &ast.ClientInboundSpec{
					SocksPort: 10818,
					HTTPPort:  10819,
				},
			}
			clientRes, err := builder.BuildClientConfig(clientSpec)
			if err != nil {
				t.Fatalf("failed to compile Sing-box client config for %s: %v", p.name, err)
			}

			tmpClient, _ := os.CreateTemp("", "sb-client-*.json")
			tmpClient.WriteString(clientRes.ConfigJSON)
			tmpClient.Close()
			defer os.Remove(tmpClient.Name())

			cmdClient := exec.Command(singboxBin, "check", "-c", tmpClient.Name())
			outC, errC := cmdClient.CombinedOutput()
			if errC != nil {
				t.Fatalf("Sing-box check FAILED on Client Config for %s: %v\nOutput: %s\nConfig:\n%s", p.name, errC, string(outC), clientRes.ConfigJSON)
			}

			t.Logf("✅ Sing-box verified [Server & Client] for %s", p.name)
		})
	}
}

// ==============================================================================
// 2. XRAY: Exhaustive Protocol & Real Binary Verification
// ==============================================================================
func TestLiveVerification_Xray_AllProtocols(t *testing.T) {
	xrayBin := findCoreBin("xray")
	if xrayBin == "" {
		t.Skip("xray binary not found, skipping live binary execution")
	}

	certPath, keyPath, cleanupTLS, err := generateTempTLSKeyPair()
	if err != nil {
		t.Fatalf("failed to generate temp TLS certs: %v", err)
	}
	defer cleanupTLS()

	realityKeys, err := crypto.GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("failed to generate reality keys: %v", err)
	}

	rawKey16 := make([]byte, 16)
	rand.Read(rawKey16)
	ssKey16 := base64.StdEncoding.EncodeToString(rawKey16)

	protocols := []struct {
		name     string
		inbound  ast.ServerInboundSpec
		outbound *ast.ServerProfile
	}{
		{
			name: "VLESS_Reality_Vision_TCP",
			inbound: ast.ServerInboundSpec{
				Tag:        "vless-reality-in",
				Port:       32001,
				Protocol:   "vless",
				Transport:  "tcp",
				Security:   "reality",
				SNI:        "gateway.icloud.com",
				PrivateKey: realityKeys.PrivateKey,
				ShortIDs:   []string{"0123456789abcdef"},
				Clients: []ast.ServerInboundClient{
					{UUID: "e99dc462-8409-4e45-bf28-665544332211", Flow: "xtls-rprx-vision"},
				},
			},
			outbound: &ast.ServerProfile{
				Protocol:    ast.ProtoVLESS,
				Name:        "vless-reality-out",
				Address:     "ro.sentinel.internal",
				Port:        443,
				UUID:        "e99dc462-8409-4e45-bf28-665544332211",
				Security:    ast.SecurityReality,
				SNI:         "gateway.icloud.com",
				Flow:        "xtls-rprx-vision",
				Fingerprint: "chrome",
				PublicKey:   realityKeys.PublicKey,
				ShortID:     "0123456789abcdef",
			},
		},
		{
			name: "VLESS_TLS_MLKEM_PostQuantum",
			inbound: ast.ServerInboundSpec{
				Tag:       "vless-mlkem-in",
				Port:      32002,
				Protocol:  "vless",
				Transport: "tcp",
				Security:  "tls",
				SNI:       "mock.sentinel.internal",
				CertPath:  certPath,
				KeyPath:   keyPath,
				Clients: []ast.ServerInboundClient{
					{UUID: "e99dc462-8409-4e45-bf28-665544332211"},
				},
			},
			outbound: &ast.ServerProfile{
				Protocol:    ast.ProtoVLESS,
				Name:        "vless-mlkem-out",
				Address:     "pq.sentinel.internal",
				Port:        443,
				UUID:        "e99dc462-8409-4e45-bf28-665544332211",
				Security:    ast.SecurityTLS,
				SNI:         "mock.sentinel.internal",
				Fingerprint: "chrome",
				PostQuantum: true,
			},
		},
		{
			name: "VLESS_TLS_xHTTP",
			inbound: ast.ServerInboundSpec{
				Tag:       "vless-xhttp-in",
				Port:      32003,
				Protocol:  "vless",
				Transport: "xhttp",
				Security:  "tls",
				SNI:       "mock.sentinel.internal",
				CertPath:  certPath,
				KeyPath:   keyPath,
				StreamSettings: map[string]interface{}{
					"xhttpSettings": map[string]interface{}{
						"path": "/vless-xhttp",
					},
				},
				Clients: []ast.ServerInboundClient{
					{UUID: "e99dc462-8409-4e45-bf28-665544332211"},
				},
			},
			outbound: &ast.ServerProfile{
				Protocol:    ast.ProtoVLESS,
				Name:        "vless-xhttp-out",
				Address:     "xhttp.sentinel.internal",
				Port:        443,
				UUID:        "e99dc462-8409-4e45-bf28-665544332211",
				Transport:   "xhttp",
				Path:        "/vless-xhttp",
				Security:    ast.SecurityTLS,
				SNI:         "mock.sentinel.internal",
			},
		},
		{
			name: "VMess_TLS_WebSocket",
			inbound: ast.ServerInboundSpec{
				Tag:       "vmess-ws-in",
				Port:      32004,
				Protocol:  "vmess",
				Transport: "ws",
				Security:  "tls",
				SNI:       "mock.sentinel.internal",
				CertPath:  certPath,
				KeyPath:   keyPath,
				StreamSettings: map[string]interface{}{
					"wsSettings": map[string]interface{}{
						"path": "/vmess-ws",
					},
				},
				Clients: []ast.ServerInboundClient{
					{UUID: "e99dc462-8409-4e45-bf28-665544332211"},
				},
			},
			outbound: &ast.ServerProfile{
				Protocol:    ast.ProtoVMess,
				Name:        "vmess-ws-out",
				Address:     "vmess.sentinel.internal",
				Port:        443,
				UUID:        "e99dc462-8409-4e45-bf28-665544332211",
				Transport:   ast.TransportWS,
				Path:        "/vmess-ws",
				Security:    ast.SecurityTLS,
				SNI:         "mock.sentinel.internal",
			},
		},
		{
			name: "Trojan_TLS_gRPC",
			inbound: ast.ServerInboundSpec{
				Tag:       "trojan-grpc-in",
				Port:      32005,
				Protocol:  "trojan",
				Transport: "grpc",
				Security:  "tls",
				SNI:       "mock.sentinel.internal",
				CertPath:  certPath,
				KeyPath:   keyPath,
				StreamSettings: map[string]interface{}{
					"grpcSettings": map[string]interface{}{
						"serviceName": "trojan-grpc",
					},
				},
				Clients: []ast.ServerInboundClient{
					{Password: "trojanpassword123"},
				},
			},
			outbound: &ast.ServerProfile{
				Protocol:    ast.ProtoTrojan,
				Name:        "trojan-grpc-out",
				Address:     "trojan.sentinel.internal",
				Port:        443,
				Password:    "trojanpassword123",
				Transport:   ast.TransportGRPC,
				ServiceName: "trojan-grpc",
				Security:    ast.SecurityTLS,
				SNI:         "mock.sentinel.internal",
			},
		},
		{
			name: "Shadowsocks_2022_Aes128Gcm",
			inbound: ast.ServerInboundSpec{
				Tag:      "ss-in",
				Port:     32006,
				Protocol: "shadowsocks",
				RawSettings: map[string]interface{}{
					"method":   "2022-blake3-aes-128-gcm",
					"password": ssKey16,
				},
				Clients: []ast.ServerInboundClient{
					{Password: ssKey16},
				},
			},
			outbound: &ast.ServerProfile{
				Protocol: ast.ProtoShadowsocks,
				Name:     "ss-out",
				Address:  "ss.sentinel.internal",
				Port:     8388,
				Cipher:   "2022-blake3-aes-128-gcm",
				Password: ssKey16,
			},
		},
	}

	for _, p := range protocols {
		t.Run(p.name, func(t *testing.T) {
			// 1. Build Server Config
			table := routing.NewRoutingTable(p.outbound.Name)
			routingAST := table.CompileToAST()

			compiledOut, err := xray.BuildXrayOutbound(p.outbound)
			if err != nil {
				t.Fatalf("xray build outbound failed for %s: %v", p.name, err)
			}
			routingAST.Outbounds = []map[string]interface{}{compiledOut}

			serverCfg, err := builder.BuildServerConfig(ast.CoreXray, []ast.ServerInboundSpec{p.inbound}, routingAST, "")
			if err != nil {
				t.Fatalf("failed to compile Xray server config for %s: %v", p.name, err)
			}

			// Validate with Real Xray (-test)
			tmpServer, _ := os.CreateTemp("", "xray-server-*.json")
			tmpServer.WriteString(serverCfg)
			tmpServer.Close()
			defer os.Remove(tmpServer.Name())

			cmdServer := exec.Command(xrayBin, "-test", "-config", tmpServer.Name())
			outS, errS := cmdServer.CombinedOutput()
			if errS != nil {
				t.Fatalf("Xray check FAILED on Server Config for %s: %v\nOutput: %s\nConfig:\n%s", p.name, errS, string(outS), serverCfg)
			}

			// 2. Build Client Config
			clientSpec := &ast.ConfigSpec{
				TargetCore: ast.CoreXray,
				ServerNode: p.outbound,
				ClientInbound: &ast.ClientInboundSpec{
					SocksPort: 10818,
					HTTPPort:  10819,
				},
			}
			clientRes, err := builder.BuildClientConfig(clientSpec)
			if err != nil {
				t.Fatalf("failed to compile Xray client config for %s: %v", p.name, err)
			}

			tmpClient, _ := os.CreateTemp("", "xray-client-*.json")
			tmpClient.WriteString(clientRes.ConfigJSON)
			tmpClient.Close()
			defer os.Remove(tmpClient.Name())

			cmdClient := exec.Command(xrayBin, "-test", "-config", tmpClient.Name())
			outC, errC := cmdClient.CombinedOutput()
			if errC != nil {
				t.Fatalf("Xray check FAILED on Client Config for %s: %v\nOutput: %s\nConfig:\n%s", p.name, errC, string(outC), clientRes.ConfigJSON)
			}

			t.Logf("✅ Xray verified [Server & Client] for %s", p.name)
		})
	}
}

// ==============================================================================
// 3. HYSTERIA 2: Exhaustive Standalone & Schema Verification
// ==============================================================================
func TestLiveVerification_Hysteria2_Standalone(t *testing.T) {
	certPath, keyPath, cleanupTLS, err := generateTempTLSKeyPair()
	if err != nil {
		t.Fatalf("failed to generate temp TLS certs: %v", err)
	}
	defer cleanupTLS()

	inbounds := []ast.ServerInboundSpec{
		{
			Tag:          "hy2-server-in",
			Port:         33001,
			Protocol:     "hysteria2",
			CertPath:     certPath,
			KeyPath:      keyPath,
			ObfsType:     "salamander",
			ObfsPassword: "salamanderSecret",
			MasqType:     "proxy",
			MasqValue:    "https://gateway.icloud.com",
			Clients: []ast.ServerInboundClient{
				{Password: "strongUserPassword123", Email: "client@sentinel"},
			},
		},
	}

	routingTable := routing.NewRoutingTable("direct")
	routingAST := routingTable.CompileToAST()

	serverJSON, err := builder.BuildServerConfig(ast.CoreHysteria2, inbounds, routingAST, "")
	if err != nil {
		t.Fatalf("failed to compile Hysteria 2 server config: %v", err)
	}

	var parsedServer map[string]interface{}
	if err := json.Unmarshal([]byte(serverJSON), &parsedServer); err != nil {
		t.Fatalf("Hysteria 2 server config is not valid JSON: %v\nJSON:\n%s", err, serverJSON)
	}

	if !strings.Contains(serverJSON, "salamanderSecret") || !strings.Contains(serverJSON, "strongUserPassword123") {
		t.Errorf("Hysteria 2 server config missing obfs/client credentials: %s", serverJSON)
	}

	// 2. Client Config Compilation
	clientNode := &ast.ServerProfile{
		Protocol:      ast.ProtoHysteria2,
		Name:          "hy2-client-node",
		Address:       "hy2.sentinel.internal",
		Port:          443,
		PortHopping:   "40000-50000,60000-65000",
		Password:      "strongUserPassword123",
		ObfsType:      "salamander",
		ObfsPassword:  "salamanderSecret",
		SNI:           "mock.sentinel.internal",
		Insecure:      true,
		BandwidthUp:   "100mbps",
		BandwidthDown: "300mbps",
	}

	clientSpec := &ast.ConfigSpec{
		TargetCore: ast.CoreHysteria2,
		ServerNode: clientNode,
		ClientInbound: &ast.ClientInboundSpec{
			SocksPort: 10818,
			HTTPPort:  10819,
		},
	}

	cc := hysteria.NewCompiler()
	clientJSON, _, err := cc.Compile(clientSpec)
	if err != nil {
		t.Fatalf("failed to compile Hysteria 2 client config: %v", err)
	}

	var parsedClient map[string]interface{}
	if err := json.Unmarshal([]byte(clientJSON), &parsedClient); err != nil {
		t.Fatalf("Hysteria 2 client config is not valid JSON: %v\nJSON:\n%s", err, clientJSON)
	}

	if !strings.Contains(clientJSON, "40000-50000,60000-65000") {
		t.Errorf("Hysteria 2 client config missing port hopping range: %s", clientJSON)
	}

	t.Logf("✅ Hysteria 2 verified [Server & Client] Standalone Engine")
}

// ==============================================================================
// 4. WIREGUARD: Standalone INI Configuration Verification
// ==============================================================================
func TestLiveVerification_WireGuard_Standalone(t *testing.T) {
	node := &ast.ServerProfile{
		Protocol:      ast.ProtoWireGuard,
		Name:          "wg-node-1",
		Address:       "wg.sentinel.internal",
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
		t.Fatalf("WireGuard .conf missing standard INI sections:\n%s", conf)
	}
	if !strings.Contains(conf, "PrivateKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=") {
		t.Errorf("missing PrivateKey in WG conf")
	}
	if !strings.Contains(conf, "PublicKey = AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=") {
		t.Errorf("missing PublicKey in WG conf")
	}
	if !strings.Contains(conf, "Endpoint = wg.sentinel.internal:51820") {
		t.Errorf("missing Endpoint in WG conf")
	}
	if !strings.Contains(conf, "MTU = 1420") {
		t.Errorf("missing MTU in WG conf")
	}

	t.Logf("✅ WireGuard verified Standalone INI Engine")
}
