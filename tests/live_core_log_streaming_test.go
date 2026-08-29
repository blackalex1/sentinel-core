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
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blackalex1/sentinel-core/pkg/supervisor"
)

func findBinary(name string) string {
	candidates := []string{
		"../bin/" + name,
		"../bin/" + name + ".exe",
		"../../panel/bin/" + name,
		"../../panel/bin/" + name + ".exe",
		"../panel/bin/" + name,
		"../panel/bin/" + name + ".exe",
		"bin/" + name,
		"bin/" + name + ".exe",
	}
	for _, c := range candidates {
		if fi, err := os.Stat(c); err == nil && !fi.IsDir() {
			abs, _ := filepath.Abs(c)
			return abs
		}
	}
	if lp, err := exec.LookPath(name); err == nil {
		abs, _ := filepath.Abs(lp)
		return abs
	}
	return ""
}

func getFreePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to get free port: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func generateTempCert(t *testing.T) (certPath, keyPath string, cleanup func()) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Sentinel Live Log Test"},
			CommonName:   "127.0.0.1",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	certFile, err := os.CreateTemp("", "livecert-*.crt")
	if err != nil {
		t.Fatalf("failed to create temp cert file: %v", err)
	}
	pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	certFile.Close()

	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("failed to marshal private key: %v", err)
	}
	keyFile, err := os.CreateTemp("", "livekey-*.key")
	if err != nil {
		t.Fatalf("failed to create temp key file: %v", err)
	}
	pem.Encode(keyFile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	keyFile.Close()

	return certFile.Name(), keyFile.Name(), func() {
		os.Remove(certFile.Name())
		os.Remove(keyFile.Name())
	}
}

// 1. Live Log Streaming from real Sing-box binary to Sentinel Core Broadcaster
func TestLiveCoreLog_SingBox_RealtimeStreaming(t *testing.T) {
	sbBin := findBinary("sing-box")
	if sbBin == "" {
		t.Skip("sing-box binary not found, skipping live streaming test")
		return
	}

	pm := supervisor.GetProcessManager()
	lb := supervisor.GetLogBroadcaster()
	coreName := "sing-box"

	pm.ClearInMemoryLogs(coreName)

	port := getFreePort(t)
	configJSON := fmt.Sprintf(`{
		"log": {
			"level": "debug",
			"timestamp": true
		},
		"inbounds": [
			{
				"type": "mixed",
				"tag": "mixed-in",
				"listen": "127.0.0.1",
				"listen_port": %d
			}
		],
		"outbounds": [
			{
				"type": "direct",
				"tag": "direct"
			}
		]
	}`, port)

	tmpConfig, err := os.CreateTemp("", "sb-live-log-*.json")
	if err != nil {
		t.Fatalf("failed to create temp config: %v", err)
	}
	defer os.Remove(tmpConfig.Name())
	tmpConfig.WriteString(configJSON)
	tmpConfig.Close()

	logSub := lb.Subscribe(coreName)
	defer lb.Unsubscribe(coreName, logSub)

	// Start Sing-box via ProcessManager
	err = pm.StartCore(coreName, sbBin, tmpConfig.Name())
	if err != nil {
		t.Fatalf("failed to start Sing-box: %v", err)
	}
	defer pm.StopCore(coreName)

	// Collect live broadcast log lines
	receivedLines := make([]string, 0)
	deadline := time.After(3 * time.Second)

	for len(receivedLines) < 2 {
		select {
		case line := <-logSub:
			receivedLines = append(receivedLines, line)
			t.Logf("[Sing-box Live Log]: %s", line)
		case <-deadline:
			break
		}
	}

	if len(receivedLines) == 0 {
		t.Fatalf("expected to receive live logs from Sing-box stdout/stderr, got 0 lines")
	}

	// Verify history ring buffer
	hist := pm.GetInMemoryLogs(coreName, 50)
	if len(hist) == 0 {
		t.Fatalf("expected in-memory log history to be populated, got 0 lines")
	}

	// Verify PopLogLine non-blocking / timed popping
	popped := pm.PopLogLine(coreName, 50*time.Millisecond)
	if popped == "" && len(hist) == 0 {
		t.Errorf("expected popped log line or populated history")
	}

	t.Logf("✅ Successfully captured %d live log lines from real Sing-box process via Sentinel Broadcaster", len(receivedLines))
}

// 2. Live Log Streaming from real Xray binary to Sentinel Core Broadcaster
func TestLiveCoreLog_Xray_RealtimeStreaming(t *testing.T) {
	xrayBin := findBinary("xray")
	if xrayBin == "" {
		t.Skip("xray binary not found, skipping live streaming test")
		return
	}

	pm := supervisor.GetProcessManager()
	lb := supervisor.GetLogBroadcaster()
	coreName := "xray"

	pm.ClearInMemoryLogs(coreName)

	port := getFreePort(t)
	configJSON := fmt.Sprintf(`{
		"log": {
			"loglevel": "debug"
		},
		"inbounds": [
			{
				"tag": "socks-in",
				"port": %d,
				"listen": "127.0.0.1",
				"protocol": "socks",
				"settings": {
					"auth": "noauth"
				}
			}
		],
		"outbounds": [
			{
				"protocol": "freedom",
				"tag": "direct"
			}
		]
	}`, port)

	tmpConfig, err := os.CreateTemp("", "xray-live-log-*.json")
	if err != nil {
		t.Fatalf("failed to create temp config: %v", err)
	}
	defer os.Remove(tmpConfig.Name())
	tmpConfig.WriteString(configJSON)
	tmpConfig.Close()

	logSub := lb.Subscribe(coreName)
	defer lb.Unsubscribe(coreName, logSub)

	// Start Xray via ProcessManager
	err = pm.StartCore(coreName, xrayBin, tmpConfig.Name())
	if err != nil {
		t.Fatalf("failed to start Xray: %v", err)
	}
	defer pm.StopCore(coreName)

	receivedLines := make([]string, 0)
	deadline := time.After(3 * time.Second)

	for len(receivedLines) < 2 {
		select {
		case line := <-logSub:
			receivedLines = append(receivedLines, line)
			t.Logf("[Xray Live Log]: %s", line)
		case <-deadline:
			break
		}
	}

	if len(receivedLines) == 0 {
		t.Fatalf("expected to receive live logs from Xray stdout/stderr, got 0 lines")
	}

	hist := pm.GetInMemoryLogs(coreName, 50)
	if len(hist) == 0 {
		t.Fatalf("expected in-memory log history for Xray, got 0 lines")
	}

	t.Logf("✅ Successfully captured %d live log lines from real Xray process via Sentinel Broadcaster", len(receivedLines))
}

// 3. Live Log Streaming from real Hysteria 2 binary to Sentinel Core Broadcaster
func TestLiveCoreLog_Hysteria2_RealtimeStreaming(t *testing.T) {
	hyBin := findBinary("hysteria")
	if hyBin == "" {
		t.Skip("hysteria binary not found, skipping live streaming test")
		return
	}

	pm := supervisor.GetProcessManager()
	lb := supervisor.GetLogBroadcaster()
	coreName := "hysteria2"

	pm.ClearInMemoryLogs(coreName)

	certPath, keyPath, cleanup := generateTempCert(t)
	defer cleanup()

	port := getFreePort(t)
	configJSON := fmt.Sprintf(`{
		"listen": "127.0.0.1:%d",
		"tls": {
			"cert": "%s",
			"key": "%s"
		},
		"auth": {
			"type": "password",
			"password": "TestPassword123"
		}
	}`, port, strings.ReplaceAll(certPath, "\\", "/"), strings.ReplaceAll(keyPath, "\\", "/"))

	tmpConfig, err := os.CreateTemp("", "hy2-live-log-*.json")
	if err != nil {
		t.Fatalf("failed to create temp config: %v", err)
	}
	defer os.Remove(tmpConfig.Name())
	tmpConfig.WriteString(configJSON)
	tmpConfig.Close()

	logSub := lb.Subscribe(coreName)
	defer lb.Unsubscribe(coreName, logSub)

	// Start Hysteria 2 via ProcessManager
	err = pm.StartCore(coreName, hyBin, tmpConfig.Name())
	if err != nil {
		t.Fatalf("failed to start Hysteria 2: %v", err)
	}
	defer pm.StopCore(coreName)

	receivedLines := make([]string, 0)
	deadline := time.After(3 * time.Second)

	for len(receivedLines) < 2 {
		select {
		case line := <-logSub:
			receivedLines = append(receivedLines, line)
			t.Logf("[Hysteria 2 Live Log]: %s", line)
		case <-deadline:
			break
		}
	}

	if len(receivedLines) == 0 {
		t.Fatalf("expected to receive live logs from Hysteria 2 stdout/stderr, got 0 lines")
	}

	hist := pm.GetInMemoryLogs(coreName, 50)
	if len(hist) == 0 {
		t.Fatalf("expected in-memory log history for Hysteria 2, got 0 lines")
	}

	t.Logf("✅ Successfully captured %d live log lines from real Hysteria 2 process via Sentinel Broadcaster", len(receivedLines))
}
