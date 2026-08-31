package tests

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/blackalex1/sentinel-core/pkg/supervisor"
)

// TestE2E_RealSingBox_ClientTrafficAndSessionTracking starts a real sing-box server,
// starts a real sing-box client, routes real HTTP traffic through the authenticated proxy tunnel,
// and verifies that sentinel-core captures the real connection event and session info.
func TestE2E_RealSingBox_ClientTrafficAndSessionTracking(t *testing.T) {
	sbBin := findBinary("sing-box")
	if sbBin == "" {
		t.Skip("sing-box binary not found, skipping real binary e2e traffic test")
		return
	}

	pm := supervisor.GetProcessManager()
	st := supervisor.GetSessionTracker()
	st.Clear()

	coreName := "sing-box"
	pm.ClearInMemoryLogs(coreName)

	// 1. Start a local HTTP upstream target server
	targetListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create target listener: %v", err)
	}
	defer targetListener.Close()
	targetPort := targetListener.Addr().(*net.TCPAddr).Port

	targetMux := http.NewServeMux()
	targetMux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("pong-from-real-target"))
	})
	targetServer := &http.Server{Handler: targetMux}
	go func() {
		_ = targetServer.Serve(targetListener)
	}()
	defer targetServer.Close()

	// 2. Configure real Sing-box server with vless inbound and user authentication
	serverPort := getFreePort(t)
	userName := "test_client_alpha"
	userUUID := "6b22e764-d2e2-4262-b5a7-8c9194d58fb9"

	serverConfigJSON := fmt.Sprintf(`{
		"log": {
			"level": "info",
			"timestamp": true
		},
		"inbounds": [
			{
				"type": "vless",
				"tag": "vless-in",
				"listen": "127.0.0.1",
				"listen_port": %d,
				"users": [
					{
						"name": "%s",
						"uuid": "%s"
					}
				]
			}
		],
		"outbounds": [
			{
				"type": "direct",
				"tag": "direct"
			}
		]
	}`, serverPort, userName, userUUID)

	tmpServerConfig, err := os.CreateTemp("", "sb-server-*.json")
	if err != nil {
		t.Fatalf("failed to create server config: %v", err)
	}
	defer os.Remove(tmpServerConfig.Name())
	_, _ = tmpServerConfig.WriteString(serverConfigJSON)
	tmpServerConfig.Close()

	// Start Sing-box Server via sentinel-core ProcessManager
	err = pm.StartCore(coreName, sbBin, tmpServerConfig.Name())
	if err != nil {
		t.Fatalf("failed to start Sing-box server via supervisor: %v", err)
	}
	defer pm.StopCore(coreName)

	time.Sleep(300 * time.Millisecond)

	// 3. Configure real Sing-box client that routes local HTTP traffic to the VLESS server
	clientPort := getFreePort(t)
	clientConfigJSON := fmt.Sprintf(`{
		"log": {
			"level": "warn",
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
				"type": "vless",
				"tag": "vless-out",
				"server": "127.0.0.1",
				"server_port": %d,
				"uuid": "%s"
			}
		]
	}`, clientPort, serverPort, userUUID)

	tmpClientConfig, err := os.CreateTemp("", "sb-client-*.json")
	if err != nil {
		t.Fatalf("failed to create client config: %v", err)
	}
	defer os.Remove(tmpClientConfig.Name())
	_, _ = tmpClientConfig.WriteString(clientConfigJSON)
	tmpClientConfig.Close()

	// Launch real Sing-box client process
	clientCtx, clientCancel := context.WithCancel(context.Background())
	defer clientCancel()

	clientCmd := exec.CommandContext(clientCtx, sbBin, "run", "-c", tmpClientConfig.Name())
	var clientErrBuf bytes.Buffer
	clientCmd.Stderr = &clientErrBuf
	if err := clientCmd.Start(); err != nil {
		t.Fatalf("failed to start Sing-box client: %v", err)
	}
	defer func() {
		clientCancel()
		_ = clientCmd.Process.Kill()
		_ = clientCmd.Wait()
	}()

	time.Sleep(400 * time.Millisecond)

	// 4. Send REAL HTTP traffic through the client proxy to the target server
	proxyURL, err := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", clientPort))
	if err != nil {
		t.Fatalf("failed to parse proxy URL: %v", err)
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
		Timeout: 5 * time.Second,
	}

	targetURL := fmt.Sprintf("http://127.0.0.1:%d/ping", targetPort)
	resp, err := httpClient.Get(targetURL)
	if err != nil {
		t.Fatalf("HTTP request through real Sing-box tunnel failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK || string(body) != "pong-from-real-target" {
		t.Fatalf("unexpected HTTP response through tunnel: status=%d body=%s", resp.StatusCode, string(body))
	}
	t.Logf("✅ Real HTTP traffic successfully passed through Sing-box tunnel: %s", string(body))

	// 5. Verify Sentinel Core SessionTracker captured the real connection
	var matchedSession *supervisor.SessionInfo
	deadline := time.Now().Add(3 * time.Second)

	for time.Now().Before(deadline) {
		active := st.GetActiveSessions()
		for _, s := range active {
			if s.Email == userName && s.Core == "sing-box" {
				matchedSession = s
				break
			}
		}
		if matchedSession != nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	if matchedSession == nil {
		logs := pm.GetInMemoryLogs(coreName, 50)
		t.Fatalf("SessionTracker failed to detect real Sing-box session for %s. Logs:\n%s", userName, logs)
	}

	t.Logf("✅ Verified real Sing-box active session in Sentinel Core: User=%s, IP=%s, Core=%s",
		matchedSession.Email, matchedSession.IP, matchedSession.Core)

	// 6. Verify Recent Session Events stream
	events := st.GetRecentEvents(0, 10)
	var foundEvent bool
	for _, ev := range events {
		if ev.Email == userName && ev.Action == "connect" {
			foundEvent = true
			break
		}
	}
	if !foundEvent {
		t.Errorf("expected connect event for %s in RecentSessionEvents, got: %+v", userName, events)
	}
	t.Logf("✅ Verified real connect event in SessionTracker event queue")
}

// TestE2E_RealXray_ClientTrafficAndSessionTracking starts a real Xray server,
// routes real HTTP traffic through it, and verifies session tracking in sentinel-core.
func TestE2E_RealXray_ClientTrafficAndSessionTracking(t *testing.T) {
	xrayBin := findBinary("xray")
	sbBin := findBinary("sing-box")
	if xrayBin == "" || sbBin == "" {
		t.Skip("xray or sing-box binary not found, skipping real Xray e2e traffic test")
		return
	}

	pm := supervisor.GetProcessManager()
	st := supervisor.GetSessionTracker()
	st.Clear()

	coreName := "xray"
	pm.ClearInMemoryLogs(coreName)

	// 1. Configure real Xray server with Shadowsocks inbound + user email
	serverPort := getFreePort(t)
	userEmail := "xray_client_beta@sentinel.org"
	ssPassword := "4X0OQ6U6f7G2g8H+4jK8lg=="

	serverConfigJSON := fmt.Sprintf(`{
		"log": {
			"loglevel": "debug"
		},
		"inbounds": [
			{
				"tag": "ss-in",
				"port": %d,
				"listen": "127.0.0.1",
				"protocol": "shadowsocks",
				"settings": {
					"method": "2022-blake3-aes-128-gcm",
					"password": "%s",
					"network": "tcp,udp",
					"email": "%s"
				}
			}
		],
		"outbounds": [
			{
				"protocol": "freedom",
				"tag": "direct"
			}
		]
	}`, serverPort, ssPassword, userEmail)

	tmpServerConfig, err := os.CreateTemp("", "xray-server-*.json")
	if err != nil {
		t.Fatalf("failed to create server config: %v", err)
	}
	defer os.Remove(tmpServerConfig.Name())
	_, _ = tmpServerConfig.WriteString(serverConfigJSON)
	tmpServerConfig.Close()

	// Start Xray Server
	err = pm.StartCore(coreName, xrayBin, tmpServerConfig.Name())
	if err != nil {
		t.Fatalf("failed to start Xray server via supervisor: %v", err)
	}
	defer pm.StopCore(coreName)

	time.Sleep(400 * time.Millisecond)

	// 3. Configure Sing-box client to route HTTP traffic to the Xray Shadowsocks server
	clientPort := getFreePort(t)
	clientConfigJSON := fmt.Sprintf(`{
		"log": {
			"level": "warn",
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
				"type": "shadowsocks",
				"tag": "ss-out",
				"server": "127.0.0.1",
				"server_port": %d,
				"method": "2022-blake3-aes-128-gcm",
				"password": "%s"
			}
		]
	}`, clientPort, serverPort, ssPassword)

	tmpClientConfig, err := os.CreateTemp("", "sb-xray-client-*.json")
	if err != nil {
		t.Fatalf("failed to create client config: %v", err)
	}
	defer os.Remove(tmpClientConfig.Name())
	_, _ = tmpClientConfig.WriteString(clientConfigJSON)
	tmpClientConfig.Close()

	clientCtx, clientCancel := context.WithCancel(context.Background())
	defer clientCancel()

	clientCmd := exec.CommandContext(clientCtx, sbBin, "run", "-c", tmpClientConfig.Name())
	var clientErrBuf bytes.Buffer
	clientCmd.Stderr = &clientErrBuf
	if err := clientCmd.Start(); err != nil {
		t.Fatalf("failed to start client: %v", err)
	}
	defer func() {
		clientCancel()
		_ = clientCmd.Process.Kill()
		_ = clientCmd.Wait()
	}()

	time.Sleep(400 * time.Millisecond)

	// 4. Send real traffic via client SOCKS5 proxy to trigger connection
	proxyURL, err := url.Parse(fmt.Sprintf("socks5://127.0.0.1:%d", clientPort))
	if err != nil {
		t.Fatalf("failed to parse proxy URL: %v", err)
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
		Timeout: 2 * time.Second,
	}

	go func() {
		_, _ = httpClient.Get("http://example.com:80")
	}()

	// 5. Verify Sentinel Core SessionTracker captured the real Xray session
	var matchedSession *supervisor.SessionInfo
	deadline := time.Now().Add(3 * time.Second)

	for time.Now().Before(deadline) {
		active := st.GetActiveSessions()
		for _, s := range active {
			if s.Email == userEmail && s.Core == "xray" {
				matchedSession = s
				break
			}
		}
		if matchedSession != nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	if matchedSession == nil {
		logs := pm.GetInMemoryLogs(coreName, 50)
		t.Fatalf("SessionTracker failed to detect real Xray session for %s. Logs:\n%s", userEmail, logs)
	}

	t.Logf("✅ Verified real Xray active session in Sentinel Core: User=%s, IP=%s, Core=%s",
		matchedSession.Email, matchedSession.IP, matchedSession.Core)
}

// TestE2E_RealHysteria2_ClientTrafficAndSessionTracking starts a real Hysteria 2 server,
// passes real traffic from a real client, and verifies session tracking in sentinel-core.
func TestE2E_RealHysteria2_ClientTrafficAndSessionTracking(t *testing.T) {
	hyBin := findBinary("hysteria")
	sbBin := findBinary("sing-box")
	if hyBin == "" || sbBin == "" {
		t.Skip("hysteria or sing-box binary not found, skipping real Hysteria e2e traffic test")
		return
	}

	pm := supervisor.GetProcessManager()
	st := supervisor.GetSessionTracker()
	st.Clear()

	coreName := "hysteria2"
	pm.ClearInMemoryLogs(coreName)

	serverPort := getFreePort(t)
	userEmail := "hy_client_gamma"
	userPassword := "hy_secret_pwd_99"

	certPath := `C:\Users\black\PycharmProjects\panel\bin\hysteria.crt`
	keyPath := `C:\Users\black\PycharmProjects\panel\bin\hysteria.key`

	serverConfigJSON := fmt.Sprintf(`{
  "listen": "127.0.0.1:%d",
  "tls": {
    "cert": %q,
    "key": %q
  },
  "auth": {
    "type": "userpass",
    "userpass": {
      %q: %q
    }
  }
}`, serverPort, certPath, keyPath, userEmail, userPassword)

	tmpServerConfig, err := os.CreateTemp("", "hy2-server-*.json")
	if err != nil {
		t.Fatalf("failed to create server config: %v", err)
	}
	defer os.Remove(tmpServerConfig.Name())
	_, _ = tmpServerConfig.WriteString(serverConfigJSON)
	tmpServerConfig.Close()

	// Start Hysteria 2 Server via sentinel-core ProcessManager
	err = pm.StartCore(coreName, hyBin, tmpServerConfig.Name())
	if err != nil {
		t.Fatalf("failed to start Hysteria 2 server via supervisor: %v", err)
	}
	defer pm.StopCore(coreName)

	time.Sleep(400 * time.Millisecond)

	// Configure Sing-box client with Hysteria 2 outbound
	clientPort := getFreePort(t)
	clientConfigJSON := fmt.Sprintf(`{
		"log": {
			"level": "warn",
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
				"type": "hysteria2",
				"tag": "hy2-out",
				"server": "127.0.0.1",
				"server_port": %d,
				"password": "%s:%s",
				"tls": {
					"enabled": true,
					"insecure": true
				}
			}
		]
	}`, clientPort, serverPort, userEmail, userPassword)

	tmpClientConfig, err := os.CreateTemp("", "sb-hy2-client-*.json")
	if err != nil {
		t.Fatalf("failed to create client config: %v", err)
	}
	defer os.Remove(tmpClientConfig.Name())
	_, _ = tmpClientConfig.WriteString(clientConfigJSON)
	tmpClientConfig.Close()

	clientCtx, clientCancel := context.WithCancel(context.Background())
	defer clientCancel()

	clientCmd := exec.CommandContext(clientCtx, sbBin, "run", "-c", tmpClientConfig.Name())
	if err := clientCmd.Start(); err != nil {
		t.Fatalf("failed to start client: %v", err)
	}
	defer func() {
		clientCancel()
		_ = clientCmd.Process.Kill()
		_ = clientCmd.Wait()
	}()

	time.Sleep(400 * time.Millisecond)

	// Send traffic through proxy
	proxyURL, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", clientPort))
	httpClient := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
		Timeout: 2 * time.Second,
	}

	go func() {
		_, _ = httpClient.Get("http://example.com:80")
	}()

	// Verify Sentinel Core SessionTracker captured the real Hysteria session
	var matchedSession *supervisor.SessionInfo
	deadline := time.Now().Add(3 * time.Second)

	for time.Now().Before(deadline) {
		active := st.GetActiveSessions()
		for _, s := range active {
			if s.Email == userEmail && (s.Core == "hysteria2" || s.Core == "hysteria") {
				matchedSession = s
				break
			}
		}
		if matchedSession != nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	if matchedSession == nil {
		logs := pm.GetInMemoryLogs(coreName, 50)
		t.Fatalf("SessionTracker failed to detect real Hysteria session for %s. Logs:\n%s", userEmail, logs)
	}

	t.Logf("✅ Verified real Hysteria 2 active session in Sentinel Core: User=%s, IP=%s, Core=%s",
		matchedSession.Email, matchedSession.IP, matchedSession.Core)
}
