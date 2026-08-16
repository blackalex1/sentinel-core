package tests

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/blackalex1/sentinel-core/pkg/ast"
	"github.com/blackalex1/sentinel-core/pkg/builder"
	"github.com/blackalex1/sentinel-core/pkg/compiler/singbox"
	"github.com/blackalex1/sentinel-core/pkg/compiler/wireguard"
	"github.com/blackalex1/sentinel-core/pkg/compiler/xray"
	"github.com/blackalex1/sentinel-core/pkg/crypto"
	"github.com/blackalex1/sentinel-core/pkg/routing"
)

// Helper to generate self-signed cert and key temporary files
func createTestCertAndKey(t *testing.T) (string, string, func()) {
	certPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ec key: %v", err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "matrix.test.example.com"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &certPriv.PublicKey, certPriv)
	if err != nil {
		t.Fatalf("failed to create cert: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	privDER, err := x509.MarshalECPrivateKey(certPriv)
	if err != nil {
		t.Fatalf("failed to marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privDER})

	certFile, err := os.CreateTemp("", "matrix-cert-*.pem")
	if err != nil {
		t.Fatalf("failed to create temp cert file: %v", err)
	}
	certFile.Write(certPEM)
	certFile.Close()

	keyFile, err := os.CreateTemp("", "matrix-key-*.pem")
	if err != nil {
		t.Fatalf("failed to create temp key file: %v", err)
	}
	keyFile.Write(keyPEM)
	keyFile.Close()

	cleanup := func() {
		os.Remove(certFile.Name())
		os.Remove(keyFile.Name())
	}
	return certFile.Name(), keyFile.Name(), cleanup
}

// 1. Shadowsocks: Test every single cipher and network combination across Sing-box and Xray
func TestExhaustive_Shadowsocks_Ciphers_And_Networks(t *testing.T) {
	ciphers := []struct {
		cipher string
		pwd    string
		is2022 bool
	}{
		{"2022-blake3-aes-128-gcm", "AQEBAQEBAQEBAQEBAQEBAQ==", true},
		{"2022-blake3-aes-256-gcm", "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=", true},
		{"2022-blake3-chacha20-poly1305", "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=", true},
		{"aes-128-gcm", "mock-ss-password-16B", false},
		{"aes-256-gcm", "mock-ss-password-32B-secure-string", false},
		{"chacha20-ietf-poly1305", "mock-ss-password-32B-secure-string", false},
	}

	networks := []string{"tcp", "udp", ""}

	singboxBin := getBinPath("../../panel/bin/sing-box.exe")
	xrayBin := getBinPath("../../panel/bin/xray.exe")

	portCounter := 31000
	for _, c := range ciphers {
		for _, net := range networks {
			testName := fmt.Sprintf("%s_net_%s", c.cipher, net)
			sbPort := portCounter
			xrayPort := portCounter + 1
			portCounter += 2

			t.Run(testName, func(t *testing.T) {
				// 1. Sing-box Outbound
				sbNode := &ast.ServerProfile{
					Protocol: ast.ProtoShadowsocks,
					Name:     "ss-out",
					Address:  "ss.example.com",
					Port:     8388,
					Cipher:   c.cipher,
					Password: c.pwd,
					Extra: map[string]interface{}{
						"network": net,
					},
				}
				sbOut, err := singbox.BuildSingBoxOutbound(sbNode)
				if err != nil {
					t.Fatalf("singbox build ss outbound failed: %v", err)
				}

				sbInbound := ast.ServerInboundSpec{
					Tag:      "ss-in",
					Port:     sbPort,
					Protocol: "shadowsocks",
					RawSettings: map[string]interface{}{
						"method":   c.cipher,
						"password": c.pwd,
						"network":  net,
					},
				}

				table := routing.NewRoutingTable("ss-out")
				routingAST := table.CompileToAST()
				routingAST.Outbounds = []map[string]interface{}{sbOut}

				cfgJSON, err := builder.BuildServerConfig(ast.CoreSingBox, []ast.ServerInboundSpec{sbInbound}, routingAST, "")
				if err != nil {
					t.Fatalf("failed to compile Sing-box config for %s: %v", testName, err)
				}

				if singboxBin != "" {
					tmpFile, _ := os.CreateTemp("", "sb-ss-*.json")
					tmpFile.WriteString(cfgJSON)
					tmpFile.Close()
					cmd := exec.Command(singboxBin, "check", "-c", tmpFile.Name())
					out, err := cmd.CombinedOutput()
					os.Remove(tmpFile.Name())
					if err != nil {
						t.Fatalf("sing-box check failed for %s: %v\nOutput: %s", testName, err, string(out))
					}
				}

				// 2. Xray Outbound & Inbound
				xrayNode := &ast.ServerProfile{
					Protocol: ast.ProtoShadowsocks,
					Name:     "ss-out",
					Address:  "ss.example.com",
					Port:     8388,
					Cipher:   c.cipher,
					Password: c.pwd,
					Extra: map[string]interface{}{
						"network": net,
					},
				}
				xrayOut, err := xray.BuildXrayOutbound(xrayNode)
				if err != nil {
					t.Fatalf("xray build ss outbound failed: %v", err)
				}

				xrayInbound := ast.ServerInboundSpec{
					Tag:      "ss-in",
					Port:     xrayPort,
					Protocol: "shadowsocks",
					RawSettings: map[string]interface{}{
						"method":   c.cipher,
						"password": c.pwd,
					},
				}

				xrayTable := routing.NewRoutingTable("ss-out")
				xrayRoutingAST := xrayTable.CompileToAST()
				xrayRoutingAST.Outbounds = []map[string]interface{}{xrayOut}

				xrayCfgJSON, err := builder.BuildServerConfig(ast.CoreXray, []ast.ServerInboundSpec{xrayInbound}, xrayRoutingAST, "")
				if err != nil {
					t.Fatalf("failed to compile Xray config for %s: %v", testName, err)
				}

				if xrayBin != "" {
					tmpFile, _ := os.CreateTemp("", "xray-ss-*.json")
					tmpFile.WriteString(xrayCfgJSON)
					tmpFile.Close()
					cmd := exec.Command(xrayBin, "-test", "-config", tmpFile.Name())
					out, err := cmd.CombinedOutput()
					os.Remove(tmpFile.Name())
					if err != nil {
						t.Fatalf("xray check failed for %s: %v\nOutput: %s", testName, err, string(out))
					}
				}
			})
		}
	}
}

// 2. VLESS: Test every Transport, Security (Reality vs TLS), Fingerprints, Flows
func TestExhaustive_VLESS_Permutations(t *testing.T) {
	realityKeys, err := crypto.GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("failed to generate keys: %v", err)
	}

	certPath, keyPath, cleanup := createTestCertAndKey(t)
	defer cleanup()

	transports := []struct {
		transport string
		path      string
		host      string
		service   string
	}{
		{"tcp", "", "", ""},
		{"ws", "/vless-ws", "ws.example.com", ""},
		{"grpc", "", "", "VlessGrpcService"},
		{"httpupgrade", "/vless-hu", "hu.example.com", ""},
	}

	fingerprints := []string{"chrome", "firefox", "safari", "ios", "android", "edge", "random"}

	singboxBin := getBinPath("../../panel/bin/sing-box.exe")
	xrayBin := getBinPath("../../panel/bin/xray.exe")

	for _, tr := range transports {
		for _, fp := range fingerprints {
			// A. Test VLESS Reality
			if tr.transport == "tcp" {
				testName := fmt.Sprintf("VLESS_Reality_%s_%s", tr.transport, fp)
				t.Run(testName, func(t *testing.T) {
					sbNode := &ast.ServerProfile{
						Protocol:    ast.ProtoVLESS,
						Name:        "vless-reality-out",
						Address:     "vless.example.com",
						Port:        443,
						UUID:        "00000000-0000-0000-0000-000000000001",
						Flow:        "xtls-rprx-vision",
						Security:    "reality",
						SNI:         "www.apple.com",
						PublicKey:   realityKeys.PublicKey,
						ShortID:     "0123456789abcdef",
						Fingerprint: fp,
					}

					sbOut, err := singbox.BuildSingBoxOutbound(sbNode)
					if err != nil {
						t.Fatalf("singbox build vless reality outbound failed: %v", err)
					}

					sbInbound := ast.ServerInboundSpec{
						Tag:        "vless-in",
						Port:       31001,
						Protocol:   "vless",
						Transport:  "tcp",
						Security:   "reality",
						SNI:        "www.apple.com",
						PrivateKey: realityKeys.PrivateKey,
						ShortIDs:   []string{"0123456789abcdef"},
						Clients: []ast.ServerInboundClient{
							{
								ID:   "00000000-0000-0000-0000-000000000001",
								UUID: "00000000-0000-0000-0000-000000000001",
								Flow: "xtls-rprx-vision",
							},
						},
					}

					table := routing.NewRoutingTable("vless-reality-out")
					routingAST := table.CompileToAST()
					routingAST.Outbounds = []map[string]interface{}{sbOut}

					cfgJSON, err := builder.BuildServerConfig(ast.CoreSingBox, []ast.ServerInboundSpec{sbInbound}, routingAST, "")
					if err != nil {
						t.Fatalf("failed to compile Sing-box config: %v", err)
					}

					if singboxBin != "" {
						tmpFile, _ := os.CreateTemp("", "sb-vless-*.json")
						tmpFile.WriteString(cfgJSON)
						tmpFile.Close()
						cmd := exec.Command(singboxBin, "check", "-c", tmpFile.Name())
						out, err := cmd.CombinedOutput()
						os.Remove(tmpFile.Name())
						if err != nil {
							t.Fatalf("sing-box check failed for %s: %v\nOutput: %s", testName, err, string(out))
						}
					}
				})
			}

			// B. Test VLESS TLS with Transport
			testTLSName := fmt.Sprintf("VLESS_TLS_%s_%s", tr.transport, fp)
			t.Run(testTLSName, func(t *testing.T) {
				sbNode := &ast.ServerProfile{
					Protocol:    ast.ProtoVLESS,
					Name:        "vless-tls-out",
					Address:     "vless-tls.example.com",
					Port:        443,
					UUID:        "00000000-0000-0000-0000-000000000002",
					Transport:   tr.transport,
					Path:        tr.path,
					Host:        tr.host,
					ServiceName: tr.service,
					Security:    "tls",
					SNI:         "vless-tls.example.com",
					Fingerprint: fp,
				}

				sbOut, err := singbox.BuildSingBoxOutbound(sbNode)
				if err != nil {
					t.Fatalf("singbox build vless tls outbound failed: %v", err)
				}

				streamSettings := map[string]interface{}{}
				if tr.transport == "ws" {
					streamSettings["network"] = "ws"
					streamSettings["wsSettings"] = map[string]interface{}{
						"path": tr.path,
						"headers": map[string]interface{}{
							"Host": tr.host,
						},
					}
				} else if tr.transport == "grpc" {
					streamSettings["network"] = "grpc"
					streamSettings["grpcSettings"] = map[string]interface{}{
						"serviceName": tr.service,
					}
				}

				sbInbound := ast.ServerInboundSpec{
					Tag:            "vless-tls-in",
					Port:           31002,
					Protocol:       "vless",
					Transport:      tr.transport,
					Security:       "tls",
					SNI:            "vless-tls.example.com",
					CertPath:       certPath,
					KeyPath:        keyPath,
					StreamSettings: streamSettings,
					Clients: []ast.ServerInboundClient{
						{
							ID:   "00000000-0000-0000-0000-000000000002",
							UUID: "00000000-0000-0000-0000-000000000002",
						},
					},
				}

				table := routing.NewRoutingTable("vless-tls-out")
				routingAST := table.CompileToAST()
				routingAST.Outbounds = []map[string]interface{}{sbOut}

				cfgJSON, err := builder.BuildServerConfig(ast.CoreSingBox, []ast.ServerInboundSpec{sbInbound}, routingAST, "")
				if err != nil {
					t.Fatalf("failed to compile Sing-box config: %v", err)
				}

				if singboxBin != "" {
					tmpFile, _ := os.CreateTemp("", "sb-vlesstls-*.json")
					tmpFile.WriteString(cfgJSON)
					tmpFile.Close()
					cmd := exec.Command(singboxBin, "check", "-c", tmpFile.Name())
					out, err := cmd.CombinedOutput()
					os.Remove(tmpFile.Name())
					if err != nil {
						t.Fatalf("sing-box check failed for %s: %v\nOutput: %s", testTLSName, err, string(out))
					}
				}

				// Xray validation
				xrayNode := &ast.ServerProfile{
					Protocol:    ast.ProtoVLESS,
					Name:        "vless-xray-tls-out",
					Address:     "vless-tls.example.com",
					Port:        443,
					UUID:        "00000000-0000-0000-0000-000000000002",
					Transport:   tr.transport,
					Path:        tr.path,
					Host:        tr.host,
					ServiceName: tr.service,
					Security:    "tls",
					SNI:         "vless-tls.example.com",
					Fingerprint: fp,
				}
				xrayOut, err := xray.BuildXrayOutbound(xrayNode)
				if err != nil {
					t.Fatalf("xray build vless tls outbound failed: %v", err)
				}

				xrayTable := routing.NewRoutingTable("vless-xray-tls-out")
				xrayRoutingAST := xrayTable.CompileToAST()
				xrayRoutingAST.Outbounds = []map[string]interface{}{xrayOut}

				xrayCfgJSON, err := builder.BuildServerConfig(ast.CoreXray, []ast.ServerInboundSpec{sbInbound}, xrayRoutingAST, "")
				if err != nil {
					t.Fatalf("failed to compile Xray config: %v", err)
				}

				if xrayBin != "" {
					tmpFile, _ := os.CreateTemp("", "xray-vlesstls-*.json")
					tmpFile.WriteString(xrayCfgJSON)
					tmpFile.Close()
					cmd := exec.Command(xrayBin, "-test", "-config", tmpFile.Name())
					out, err := cmd.CombinedOutput()
					os.Remove(tmpFile.Name())
					if err != nil {
						t.Fatalf("xray check failed for %s: %v\nOutput: %s", testTLSName, err, string(out))
					}
				}
			})
		}
	}
}

// 3. VMess: Test every Transport and Security option
func TestExhaustive_VMess_Permutations(t *testing.T) {
	transports := []string{"tcp", "ws", "grpc", "httpupgrade"}
	ciphers := []string{"auto", "aes-128-gcm", "chacha20-poly1305", "none", "zero"}
	singboxBin := getBinPath("../../panel/bin/sing-box.exe")

	for _, tr := range transports {
		for _, cipher := range ciphers {
			testName := fmt.Sprintf("VMess_%s_%s", tr, cipher)
			t.Run(testName, func(t *testing.T) {
				sbNode := &ast.ServerProfile{
					Protocol:    ast.ProtoVMess,
					Name:        "vmess-out",
					Address:     "vmess.example.com",
					Port:        443,
					UUID:        "00000000-0000-0000-0000-000000000003",
					Cipher:      cipher,
					Transport:   tr,
					Path:        "/vmess-path",
					Host:        "vmess.example.com",
					Security:    "tls",
					SNI:         "vmess.example.com",
					Fingerprint: "chrome",
				}

				sbOut, err := singbox.BuildSingBoxOutbound(sbNode)
				if err != nil {
					t.Fatalf("singbox build vmess outbound failed: %v", err)
				}

				table := routing.NewRoutingTable("vmess-out")
				routingAST := table.CompileToAST()
				routingAST.Outbounds = []map[string]interface{}{sbOut}

				cfgJSON, err := builder.BuildServerConfig(ast.CoreSingBox, nil, routingAST, "")
				if err != nil {
					t.Fatalf("failed to compile Sing-box config: %v", err)
				}

				if singboxBin != "" {
					tmpFile, _ := os.CreateTemp("", "sb-vmess-*.json")
					tmpFile.WriteString(cfgJSON)
					tmpFile.Close()
					cmd := exec.Command(singboxBin, "check", "-c", tmpFile.Name())
					out, err := cmd.CombinedOutput()
					os.Remove(tmpFile.Name())
					if err != nil {
						t.Fatalf("sing-box check failed for %s: %v\nOutput: %s", testName, err, string(out))
					}
				}
			})
		}
	}
}

// 4. Hysteria 2: Test all combinations of Obfs, Port Hopping, Bandwidths, and Insecure modes
func TestExhaustive_Hysteria2_Permutations(t *testing.T) {
	obfsOptions := []struct {
		obfsType string
		password string
	}{
		{"salamander", "mock_salamander_pwd"},
		{"", ""},
	}

	portOptions := []string{"443", "40000-50000", "8443:20443"}
	bandwidths := []struct {
		up   string
		down string
	}{
		{"100mbps", "200mbps"},
		{"100mb", "200mb"},
		{"50m", "100m"},
		{"1gbps", "2gbps"},
		{"", ""},
	}

	singboxBin := getBinPath("../../panel/bin/sing-box.exe")

	for _, obfs := range obfsOptions {
		for _, port := range portOptions {
			for _, bw := range bandwidths {
				testName := fmt.Sprintf("Hy2_obfs_%s_port_%s_bw_%s", obfs.obfsType, port, bw.up)
				t.Run(testName, func(t *testing.T) {
					sbNode := &ast.ServerProfile{
						Protocol:      ast.ProtoHysteria2,
						Name:          "hy2-out",
						Address:       "hy2.example.com",
						Port:          443,
						PortHopping:   port,
						Password:      "mock-auth-pass",
						BandwidthUp:   bw.up,
						BandwidthDown: bw.down,
						ObfsType:      obfs.obfsType,
						ObfsPassword:  obfs.password,
						SNI:           "hy2.example.com",
						Insecure:      true,
						ALPN:          []string{"h3"},
						Extra: map[string]interface{}{
							"hop_interval": "20s",
						},
					}

					sbOut, err := singbox.BuildSingBoxOutbound(sbNode)
					if err != nil {
						t.Fatalf("singbox build hy2 outbound failed: %v", err)
					}

					table := routing.NewRoutingTable("hy2-out")
					routingAST := table.CompileToAST()
					routingAST.Outbounds = []map[string]interface{}{sbOut}

					cfgJSON, err := builder.BuildServerConfig(ast.CoreSingBox, nil, routingAST, "")
					if err != nil {
						t.Fatalf("failed to compile Sing-box config: %v", err)
					}

					if singboxBin != "" {
						tmpFile, _ := os.CreateTemp("", "sb-hy2-*.json")
						tmpFile.WriteString(cfgJSON)
						tmpFile.Close()
						cmd := exec.Command(singboxBin, "check", "-c", tmpFile.Name())
						out, err := cmd.CombinedOutput()
						os.Remove(tmpFile.Name())
						if err != nil {
							t.Fatalf("sing-box check failed for %s: %v\nOutput: %s", testName, err, string(out))
						}
					}
				})
			}
		}
	}
}

// 5. TUIC: Test every combination of Congestion Controller, UDP Relay Mode, and 0-RTT
func TestExhaustive_TUIC_Permutations(t *testing.T) {
	congestionControllers := []string{"bbr", "cubic", "new_reno", ""}
	udpRelayModes := []string{"native", "quic", ""}
	zeroRTT := []bool{true, false}

	singboxBin := getBinPath("../../panel/bin/sing-box.exe")

	for _, cc := range congestionControllers {
		for _, udpMode := range udpRelayModes {
			for _, zrtt := range zeroRTT {
				testName := fmt.Sprintf("TUIC_cc_%s_udp_%s_0rtt_%v", cc, udpMode, zrtt)
				t.Run(testName, func(t *testing.T) {
					sbNode := &ast.ServerProfile{
						Protocol:          ast.ProtoTUIC,
						Name:              "tuic-out",
						Address:           "tuic.example.com",
						Port:              8443,
						UUID:              "00000000-0000-0000-0000-000000000009",
						Password:          "mock-tuic-pass",
						CongestionControl: cc,
						UDPRelayMode:      udpMode,
						ZeroRTTHandshake:  zrtt,
						SNI:               "tuic.example.com",
					}

					sbOut, err := singbox.BuildSingBoxOutbound(sbNode)
					if err != nil {
						t.Fatalf("singbox build tuic outbound failed: %v", err)
					}

					table := routing.NewRoutingTable("tuic-out")
					routingAST := table.CompileToAST()
					routingAST.Outbounds = []map[string]interface{}{sbOut}

					cfgJSON, err := builder.BuildServerConfig(ast.CoreSingBox, nil, routingAST, "")
					if err != nil {
						t.Fatalf("failed to compile Sing-box config: %v", err)
					}

					if singboxBin != "" {
						tmpFile, _ := os.CreateTemp("", "sb-tuic-*.json")
						tmpFile.WriteString(cfgJSON)
						tmpFile.Close()
						cmd := exec.Command(singboxBin, "check", "-c", tmpFile.Name())
						out, err := cmd.CombinedOutput()
						os.Remove(tmpFile.Name())
						if err != nil {
							t.Fatalf("sing-box check failed for %s: %v\nOutput: %s", testName, err, string(out))
						}
					}
				})
			}
		}
	}
}

// 6. ShadowTLS: Test versions and fingerprints
func TestExhaustive_ShadowTLS_Permutations(t *testing.T) {
	versions := []int{1, 2, 3}
	fps := []string{"chrome", "firefox", "safari", "ios", "edge"}
	singboxBin := getBinPath("../../panel/bin/sing-box.exe")

	for _, v := range versions {
		for _, fp := range fps {
			testName := fmt.Sprintf("ShadowTLS_v%d_fp_%s", v, fp)
			t.Run(testName, func(t *testing.T) {
				sbNode := &ast.ServerProfile{
					Protocol:          ast.ProtoShadowTLS,
					Name:              "stls-out",
					Address:           "stls.example.com",
					Port:              443,
					ShadowTLSVersion:  v,
					ShadowTLSPassword: "mock-stls-secret",
					ShadowTLSSNI:     "gateway.icloud.com",
					Fingerprint:       fp,
				}

				sbOut, err := singbox.BuildSingBoxOutbound(sbNode)
				if err != nil {
					t.Fatalf("singbox build shadowtls outbound failed: %v", err)
				}

				table := routing.NewRoutingTable("stls-out")
				routingAST := table.CompileToAST()
				routingAST.Outbounds = []map[string]interface{}{sbOut}

				cfgJSON, err := builder.BuildServerConfig(ast.CoreSingBox, nil, routingAST, "")
				if err != nil {
					t.Fatalf("failed to compile Sing-box config: %v", err)
				}

				if singboxBin != "" {
					tmpFile, _ := os.CreateTemp("", "sb-stls-*.json")
					tmpFile.WriteString(cfgJSON)
					tmpFile.Close()
					cmd := exec.Command(singboxBin, "check", "-c", tmpFile.Name())
					out, err := cmd.CombinedOutput()
					os.Remove(tmpFile.Name())
					if err != nil {
						t.Fatalf("sing-box check failed for %s: %v\nOutput: %s", testName, err, string(out))
					}
				}
			})
		}
	}
}

// 7. Trojan: Test all transports, ALPNs and TLS fingerprints
func TestExhaustive_Trojan_Permutations(t *testing.T) {
	transports := []string{"tcp", "ws", "grpc"}
	fps := []string{"chrome", "firefox", "safari", "ios", "edge"}
	singboxBin := getBinPath("../../panel/bin/sing-box.exe")

	for _, tr := range transports {
		for _, fp := range fps {
			testName := fmt.Sprintf("Trojan_%s_fp_%s", tr, fp)
			t.Run(testName, func(t *testing.T) {
				sbNode := &ast.ServerProfile{
					Protocol:    ast.ProtoTrojan,
					Name:        "trojan-out",
					Address:     "trojan.example.com",
					Port:        443,
					Password:    "mock-trojan-pass",
					Transport:   tr,
					Path:        "/trojan-ws",
					ServiceName: "TrojanGrpcService",
					Security:    "tls",
					SNI:         "trojan.example.com",
					Fingerprint: fp,
				}

				sbOut, err := singbox.BuildSingBoxOutbound(sbNode)
				if err != nil {
					t.Fatalf("singbox build trojan outbound failed: %v", err)
				}

				table := routing.NewRoutingTable("trojan-out")
				routingAST := table.CompileToAST()
				routingAST.Outbounds = []map[string]interface{}{sbOut}

				cfgJSON, err := builder.BuildServerConfig(ast.CoreSingBox, nil, routingAST, "")
				if err != nil {
					t.Fatalf("failed to compile Sing-box config: %v", err)
				}

				if singboxBin != "" {
					tmpFile, _ := os.CreateTemp("", "sb-trojan-*.json")
					tmpFile.WriteString(cfgJSON)
					tmpFile.Close()
					cmd := exec.Command(singboxBin, "check", "-c", tmpFile.Name())
					out, err := cmd.CombinedOutput()
					os.Remove(tmpFile.Name())
					if err != nil {
						t.Fatalf("sing-box check failed for %s: %v\nOutput: %s", testName, err, string(out))
					}
				}
			})
		}
	}
}

// 8. WireGuard: Test MTU, Dual-stack, and PresharedKey combinations in Xray and standalone .conf
func TestExhaustive_WireGuard_Permutations(t *testing.T) {
	mtus := []int{1280, 1420, 1500, 0}
	addresses := [][]string{
		{"10.0.0.2/32"},
		{"10.0.0.2/32", "fc00::2/128"},
	}
	psks := []string{
		"AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=",
		"",
	}

	xrayBin := getBinPath("../../panel/bin/xray.exe")

	for _, mtu := range mtus {
		for _, addr := range addresses {
			for _, psk := range psks {
				testName := fmt.Sprintf("WG_mtu_%d_addrs_%d_hasPSK_%v", mtu, len(addr), psk != "")
				t.Run(testName, func(t *testing.T) {
					node := &ast.ServerProfile{
						Protocol:      ast.ProtoWireGuard,
						Name:          "wg-out",
						Address:       "wg.example.com",
						Port:          51820,
						PrivateKey:    "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
						PeerPublicKey: "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=",
						PreSharedKey:  psk,
						LocalAddress:  addr,
						MTU:           mtu,
					}

					// Test Xray compilation
					xrayOut, err := xray.BuildXrayOutbound(node)
					if err != nil {
						t.Fatalf("xray build wireguard outbound failed: %v", err)
					}

					xrayTable := routing.NewRoutingTable("wg-out")
					xrayRoutingAST := xrayTable.CompileToAST()
					xrayRoutingAST.Outbounds = []map[string]interface{}{xrayOut}

					cfgJSON, err := builder.BuildServerConfig(ast.CoreXray, nil, xrayRoutingAST, "")
					if err != nil {
						t.Fatalf("failed to compile Xray config: %v", err)
					}

					if xrayBin != "" {
						tmpFile, _ := os.CreateTemp("", "xray-wg-*.json")
						tmpFile.WriteString(cfgJSON)
						tmpFile.Close()
						cmd := exec.Command(xrayBin, "-test", "-config", tmpFile.Name())
						out, err := cmd.CombinedOutput()
						os.Remove(tmpFile.Name())
						if err != nil {
							t.Fatalf("xray check failed for %s: %v\nOutput: %s", testName, err, string(out))
						}
					}

					// Test standalone INI config
					conf, err := wireguard.BuildWireGuardConf(node)
					if err != nil {
						t.Fatalf("failed to build WireGuard conf: %v", err)
					}
					if !strings.Contains(conf, "[Interface]") || !strings.Contains(conf, "[Peer]") {
						t.Fatalf("invalid WireGuard conf generated: %s", conf)
					}
				})
			}
		}
	}
}
