package supervisor

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/blackalex1/sentinel-core/pkg/i18n"
)

func TestController_Configure_And_GetStatus(t *testing.T) {
	// Start a mock SingBox clash API listener
	sbMux := http.NewServeMux()
	sbMux.HandleFunc("/connections", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"connections": []any{},
		})
	})
	sbServer := httptest.NewServer(sbMux)
	defer sbServer.Close()

	sbAddr := sbServer.Listener.Addr().String()

	// Start a mock Hysteria listener on 127.0.0.1
	hyListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create hysteria listener: %v", err)
	}
	hyPort := hyListener.Addr().(*net.TCPAddr).Port

	hyMux := http.NewServeMux()
	hyMux.HandleFunc("/traffic", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"user1@test.com": map[string]int64{"tx": 1000, "rx": 500},
		})
	})
	hyMux.HandleFunc("/online", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]int{
			"user1@test.com": 1,
		})
	})
	hyServer := &http.Server{Handler: hyMux}
	go func() { _ = hyServer.Serve(hyListener) }()
	defer hyServer.Close()

	ctrl := GetController()
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "sb.log")
	_ = os.WriteFile(logFile, []byte("test singbox log line\n"), 0644)

	ctrl.Configure(sbAddr, []int{hyPort}, map[string]string{
		"sing-box": logFile,
	})

	status := ctrl.GetStatus()
	if status == nil {
		t.Fatalf("expected non-nil status")
	}

	sbStatus, ok := status["sing-box"]
	if !ok || !sbStatus.Running {
		t.Errorf("expected sing-box to be running via clash API check, got: %+v", sbStatus)
	}

	hyStatus, ok := status["hysteria2"]
	if !ok || !hyStatus.Running {
		t.Errorf("expected hysteria2 to be running via traffic check, got: %+v", hyStatus)
	}

	xrayStatus, ok := status["xray"]
	if !ok {
		t.Errorf("expected xray status entry")
	}
	_ = xrayStatus

	// Test GetLogs
	logs, err := ctrl.GetLogs("sing-box", 10)
	if err != nil || len(logs) != 1 {
		t.Errorf("expected 1 log line, got %v (err: %v)", logs, err)
	}

	emptyLogs, err := ctrl.GetLogs("non-existent-core", 10)
	if err != nil || len(emptyLogs) != 0 {
		t.Errorf("expected 0 log lines for non-existent core, got %v", emptyLogs)
	}
}

func TestController_GetUnifiedTraffic(t *testing.T) {
	// SingBox server
	sbMux := http.NewServeMux()
	sbMux.HandleFunc("/connections", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"connections": []map[string]any{
				{
					"download": 2000,
					"upload":   1000,
					"metadata": map[string]string{
						"user":     "shared@test.com",
						"sourceIP": "192.168.1.100",
					},
				},
				{
					"download": 500,
					"upload":   250,
					"metadata": map[string]string{
						"user":     "sb-only@test.com",
						"sourceIP": "192.168.1.101",
					},
				},
			},
		})
	})
	sbServer := httptest.NewServer(sbMux)
	defer sbServer.Close()
	sbAddr := sbServer.Listener.Addr().String()

	// Hysteria server
	hyListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create hysteria listener: %v", err)
	}
	hyPort := hyListener.Addr().(*net.TCPAddr).Port

	hyMux := http.NewServeMux()
	hyMux.HandleFunc("/traffic", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"shared@test.com": map[string]int64{"tx": 3000, "rx": 1500},
			"hy-only@test.com": map[string]int64{"tx": 4000, "rx": 2000},
		})
	})
	hyMux.HandleFunc("/online", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]int{
			"shared@test.com": 2,
			"hy-only@test.com": 1,
		})
	})
	hyServer := &http.Server{Handler: hyMux}
	go func() { _ = hyServer.Serve(hyListener) }()
	defer hyServer.Close()

	ctrl := GetController()
	ctrl.Configure(sbAddr, []int{hyPort}, nil)

	traffic, err := ctrl.GetUnifiedTraffic()
	if err != nil {
		t.Fatalf("unexpected error fetching unified traffic: %v", err)
	}

	// Verify shared@test.com aggregation
	shared, ok := traffic["shared@test.com"]
	if !ok {
		t.Fatalf("expected shared@test.com in traffic")
	}
	if shared.DownBytes != 5000 || shared.UpBytes != 2500 {
		t.Errorf("expected 5000 down / 2500 up for shared, got down=%d up=%d", shared.DownBytes, shared.UpBytes)
	}
	if !shared.Online {
		t.Errorf("expected shared client to be online")
	}

	// Verify sb-only
	sbOnly, ok := traffic["sb-only@test.com"]
	if !ok || sbOnly.DownBytes != 500 {
		t.Errorf("expected sb-only to have 500 down, got: %+v", sbOnly)
	}

	// Verify hy-only
	hyOnly, ok := traffic["hy-only@test.com"]
	if !ok || hyOnly.DownBytes != 4000 {
		t.Errorf("expected hy-only to have 4000 down, got: %+v", hyOnly)
	}
}

func TestController_KickClient(t *testing.T) {
	var sbClosedID string
	var hyKickedEmail string

	sbMux := http.NewServeMux()
	sbMux.HandleFunc("/connections", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"connections": []map[string]any{
				{
					"id": "conn-123",
					"metadata": map[string]string{
						"user": "target@test.com",
					},
				},
			},
		})
	})
	sbMux.HandleFunc("/connections/conn-123", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			sbClosedID = "conn-123"
			w.WriteHeader(http.StatusOK)
		}
	})
	sbServer := httptest.NewServer(sbMux)
	defer sbServer.Close()
	sbAddr := sbServer.Listener.Addr().String()

	hyListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	hyPort := hyListener.Addr().(*net.TCPAddr).Port

	hyMux := http.NewServeMux()
	hyMux.HandleFunc("/kick", func(w http.ResponseWriter, r *http.Request) {
		var emails []string
		_ = json.NewDecoder(r.Body).Decode(&emails)
		if len(emails) > 0 {
			hyKickedEmail = emails[0]
		}
		w.WriteHeader(http.StatusOK)
	})
	hyServer := &http.Server{Handler: hyMux}
	go func() { _ = hyServer.Serve(hyListener) }()
	defer hyServer.Close()

	ctrl := GetController()
	ctrl.Configure(sbAddr, []int{hyPort}, nil)

	err = ctrl.KickClient("target@test.com")
	if err != nil {
		t.Fatalf("unexpected kick error: %v", err)
	}

	if sbClosedID != "conn-123" {
		t.Errorf("expected SingBox conn-123 to be deleted, got: %s", sbClosedID)
	}
	if hyKickedEmail != "target@test.com" {
		t.Errorf("expected Hysteria target@test.com to be kicked, got: %s", hyKickedEmail)
	}
}

func TestKickHysteriaClient_Errors(t *testing.T) {
	// Invalid port
	err := KickHysteriaClient(0, "user@test.com")
	if err == nil {
		t.Errorf("expected error for adminPort <= 0")
	}

	// Server returning 500
	hyListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listener error: %v", err)
	}
	hyPort := hyListener.Addr().(*net.TCPAddr).Port

	hyMux := http.NewServeMux()
	hyMux.HandleFunc("/kick", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	hyServer := &http.Server{Handler: hyMux}
	go func() { _ = hyServer.Serve(hyListener) }()
	defer hyServer.Close()

	err = KickHysteriaClient(hyPort, "user@test.com")
	if err == nil || !strings.Contains(err.Error(), "500") {
		t.Errorf("expected 500 error, got: %v", err)
	}

	// Non-existent server
	err = KickHysteriaClient(59999, "user@test.com")
	if err == nil {
		t.Errorf("expected connection error on closed port")
	}
}

func TestCloseSingBoxConnections_Errors(t *testing.T) {
	// Closed address
	err := CloseSingBoxConnections("127.0.0.1:59998", "user@test.com")
	if err == nil {
		t.Errorf("expected error connecting to closed address")
	}

	// Invalid JSON response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("invalid json response"))
	}))
	defer server.Close()

	err = CloseSingBoxConnections(server.Listener.Addr().String(), "user@test.com")
	if err == nil {
		t.Errorf("expected JSON decode error")
	}
}

func TestFetchHysteriaTraffic_EdgeCases(t *testing.T) {
	// Port <= 0
	res, err := FetchHysteriaTraffic(-1)
	if err != nil || len(res) != 0 {
		t.Errorf("expected empty result, got %v, err=%v", res, err)
	}

	// Server returning invalid JSON for /traffic
	hyListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listener error: %v", err)
	}
	hyPort := hyListener.Addr().(*net.TCPAddr).Port

	hyMux := http.NewServeMux()
	hyMux.HandleFunc("/traffic", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("not json"))
	})
	hyMux.HandleFunc("/online", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"user1@test.com": 3}`))
	})
	hyServer := &http.Server{Handler: hyMux}
	go func() { _ = hyServer.Serve(hyListener) }()
	defer hyServer.Close()

	res, err = FetchHysteriaTraffic(hyPort)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if u1, ok := res["user1@test.com"]; !ok || u1.Connections != 3 || !u1.Online {
		t.Errorf("expected user1 to be online with 3 conns, got: %+v", u1)
	}
}

func TestFetchSingBoxTraffic_EdgeCases(t *testing.T) {
	// Connection error
	_, err := FetchSingBoxTraffic("127.0.0.1:59997")
	if err == nil {
		t.Errorf("expected connection error")
	}

	// Invalid JSON
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("{invalid-json"))
	}))
	defer server.Close()

	_, err = FetchSingBoxTraffic(server.Listener.Addr().String())
	if err == nil {
		t.Errorf("expected JSON error")
	}

	// Empty user metadata skipped
	server2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"connections": []map[string]any{
				{
					"download": 100,
					"upload":   100,
					"metadata": map[string]string{
						"user":     "   ",
						"sourceIP": "1.2.3.4",
					},
				},
			},
		})
	}))
	defer server2.Close()

	res, err := FetchSingBoxTraffic(server2.Listener.Addr().String())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res) != 0 {
		t.Errorf("expected empty result for empty user string, got: %v", res)
	}
}

func TestReadCoreLogs_Advanced(t *testing.T) {
	// Non-existent file
	lines, err := ReadCoreLogs("non_existent_file_path_12345.log", 10)
	if err != nil || len(lines) != 0 {
		t.Errorf("expected empty lines on non-existent file, got %v, err: %v", lines, err)
	}

	// Negative maxLines defaults to 100
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "many_lines.log")
	var sb strings.Builder
	for i := 1; i <= 250; i++ {
		sb.WriteString(fmt.Sprintf("log line %d\n", i))
	}
	_ = os.WriteFile(logFile, []byte(sb.String()), 0644)

	lines, err = ReadCoreLogs(logFile, -5)
	if err != nil {
		t.Fatalf("failed reading logs: %v", err)
	}
	if len(lines) != 100 {
		t.Errorf("expected 100 lines default, got %d", len(lines))
	}
	if lines[len(lines)-1] != "log line 250" {
		t.Errorf("expected last line to be 'log line 250', got '%s'", lines[len(lines)-1])
	}

	// Reading fewer lines than file contains
	lines, err = ReadCoreLogs(logFile, 15)
	if err != nil || len(lines) != 15 {
		t.Errorf("expected 15 lines, got %d, err: %v", len(lines), err)
	}
	if lines[0] != "log line 236" || lines[14] != "log line 250" {
		t.Errorf("expected lines 236..250, got start='%s', end='%s'", lines[0], lines[14])
	}
}

func TestProcessManager_BasicAndEdgeCases(t *testing.T) {
	pm := GetProcessManager()
	if pm == nil {
		t.Fatalf("expected non-nil ProcessManager")
	}

	// Binary not found
	err := pm.StartCore("xray", "non_existent_binary_xyz.exe", "")
	if err == nil || !strings.Contains(err.Error(), "binary not found") {
		t.Errorf("expected binary not found error, got: %v", err)
	}

	// Config not found
	selfExe, err := os.Executable()
	if err != nil {
		t.Fatalf("failed to get executable path: %v", err)
	}

	err = pm.StartCore("sing-box", selfExe, "non_existent_config_xyz.json")
	if err == nil || !strings.Contains(err.Error(), "config file not found") {
		t.Errorf("expected config file not found error, got: %v", err)
	}

	// Stop non-running core
	err = pm.StopCore("hysteria2")
	if err != nil {
		t.Errorf("expected no error stopping non-running core, got: %v", err)
	}

	// Check IsRunning
	running := pm.IsRunning("non-existent-core-123")
	if running {
		t.Errorf("expected non-existent core not to be running")
	}
}

func TestProcessManager_ValidateCoreConfig(t *testing.T) {
	pm := GetProcessManager()

	// Non-existent binary
	valid, _, err := pm.ValidateCoreConfig("xray", "no_bin.exe", "no_cfg.json")
	if err == nil || valid {
		t.Errorf("expected error for non-existent binary")
	}

	// Non-existent config
	selfExe, _ := os.Executable()
	valid, _, err = pm.ValidateCoreConfig("xray", selfExe, "no_cfg.json")
	if err == nil || valid {
		t.Errorf("expected error for non-existent config")
	}

	// Valid and empty JSON configs for default engine
	tmpDir := t.TempDir()
	emptyCfg := filepath.Join(tmpDir, "empty.json")
	_ = os.WriteFile(emptyCfg, []byte("   \n"), 0644)

	valid, out, err := pm.ValidateCoreConfig("hysteria2", selfExe, emptyCfg)
	if err != nil || valid || out != "empty config" {
		t.Errorf("expected invalid empty config, got valid=%v, out=%s, err=%v", valid, out, err)
	}

	validCfg := filepath.Join(tmpDir, "valid.json")
	_ = os.WriteFile(validCfg, []byte(`{"listen": ":443"}`), 0644)

	valid, out, err = pm.ValidateCoreConfig("hysteria2", selfExe, validCfg)
	if err != nil || !valid || out != "OK" {
		t.Errorf("expected valid config OK, got valid=%v, out=%s, err=%v", valid, out, err)
	}
}

func TestProcessManager_DetectCoreVersion(t *testing.T) {
	pm := GetProcessManager()

	// Non-existent binary
	v := pm.DetectCoreVersion("xray", "non_existent_binary_xyz.exe")
	if v != "Not Installed" {
		t.Errorf("expected 'Not Installed', got '%s'", v)
	}

	// Existing binary (self executable or go binary)
	goPath, err := exec.LookPath("go")
	if err == nil {
		v = pm.DetectCoreVersion("sing-box", goPath)
		if v == "" || v == "Not Installed" {
			t.Errorf("expected detected version or unknown, got: %s", v)
		}
	}
}

func TestNormalizeAndBinBaseName(t *testing.T) {
	cases := []struct {
		input       string
		expectedNorm string
		expectedBin  string
	}{
		{"singbox", "sing-box", "sing-box"},
		{"sing-box", "sing-box", "sing-box"},
		{"hysteria", "hysteria2", "hysteria"},
		{"hysteria2", "hysteria2", "hysteria"},
		{"xray", "xray", "xray"},
		{"xray-core", "xray", "xray"},
		{"other-custom", "other-custom", "other-custom"},
	}

	for _, tc := range cases {
		norm := normalizeCoreName(tc.input)
		if norm != tc.expectedNorm {
			t.Errorf("normalizeCoreName(%q) = %q, expected %q", tc.input, norm, tc.expectedNorm)
		}
		bin := getBinBaseName(norm)
		if bin != tc.expectedBin {
			t.Errorf("getBinBaseName(%q) = %q, expected %q", norm, bin, tc.expectedBin)
		}
	}
}

func TestProcessManager_StartStopLifecycle(t *testing.T) {
	pm := GetProcessManager()
	tmpDir := t.TempDir()

	// Use powershell or cmd as a dummy long-lived child process
	var dummyBin string
	var dummyConfig string
	var err error

	dummyBin, err = exec.LookPath("powershell")
	if err != nil {
		dummyBin, err = exec.LookPath("cmd")
	}
	if err != nil {
		t.Skip("neither powershell nor cmd available for process start test")
	}

	dummyConfig = filepath.Join(tmpDir, "dummy_config.json")
	_ = os.WriteFile(dummyConfig, []byte(`{"test": true}`), 0644)

	// Start dummy core
	coreName := "test-core-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	err = pm.StartCore(coreName, dummyBin, dummyConfig)
	if err != nil {
		t.Fatalf("failed to start core: %v", err)
	}

	// Verify it is recognized as running
	if !pm.IsRunning(coreName) {
		t.Errorf("expected core %s to be running", coreName)
	}

	// Restart
	err = pm.RestartCore(coreName, dummyBin, dummyConfig)
	if err != nil {
		t.Errorf("failed to restart core: %v", err)
	}

	// Stop
	err = pm.StopCore(coreName)
	if err != nil {
		t.Errorf("failed to stop core: %v", err)
	}

	time.Sleep(150 * time.Millisecond)
	if pm.IsRunning(coreName) {
		t.Errorf("expected core %s to be stopped", coreName)
	}
}

func TestLogBroadcaster_And_ProcessMemoryLogs(t *testing.T) {
	lb := GetLogBroadcaster()
	core := "xray-stream-test"

	ch := lb.Subscribe(core)
	defer lb.Unsubscribe(core, ch)

	// Push lines
	lb.PushLine(core, "line 1")
	lb.PushLine(core, "line 2")
	lb.PushLine(core, "line 3")

	// Check channel receive
	select {
	case l := <-ch:
		if l != "line 1" {
			t.Errorf("expected 'line 1', got %s", l)
		}
	case <-time.After(100 * time.Millisecond):
		t.Errorf("timeout waiting for broadcast line 1")
	}

	// Check history
	hist := lb.GetHistory(core, 5)
	if len(hist) != 3 || hist[2] != "line 3" {
		t.Errorf("unexpected history: %v", hist)
	}

	// Test PopLine
	line := lb.PopLine(core, 50*time.Millisecond)
	if line != "line 1" {
		t.Errorf("expected popped line 1, got %s", line)
	}

	// Test StreamPipe with io.Reader
	r := strings.NewReader("pipe line A\npipe line B\n")
	StreamPipe(core, r)

	histAfter := lb.GetHistory(core, 10)
	if len(histAfter) < 5 {
		t.Errorf("expected history to contain piped lines, got %v", histAfter)
	}

	// Test ProcessManager in-memory methods
	pm := GetProcessManager()
	pm.ClearInMemoryLogs(core)
	GetLogBroadcaster().PushLine(core, "pm in-memory line")
	pmHist := pm.GetInMemoryLogs(core, 5)
	if len(pmHist) != 1 || pmHist[0] != "pm in-memory line" {
		t.Errorf("expected pm history to have 'pm in-memory line', got %v", pmHist)
	}

	popped := pm.PopLogLine(core, 50*time.Millisecond)
	if popped != "pm in-memory line" {
		t.Errorf("expected popped 'pm in-memory line', got %s", popped)
	}
}

func TestSessionTracker_SingBoxTwoStageLog(t *testing.T) {
	st := GetSessionTracker()
	line1 := "+0000 2026-08-25 19:55:12 INFO [1978868683 0ms] inbound/vless[inbound-8]: inbound connection from 198.51.100.42:27073"
	line2 := "+0000 2026-08-25 19:55:12 INFO [1978868683 155ms] inbound/vless[inbound-8]: [test_client] inbound connection to 198.51.100.1:443"

	st.ProcessLogLine("singbox", line1)
	st.ProcessLogLine("singbox", line2)

	sessions := st.GetActiveSessions()
	found := false
	for _, s := range sessions {
		if s.Email == "test_client" && s.IP == "198.51.100.42" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected session for test_client with IP 198.51.100.42, got: %+v", sessions)
	}

	events := st.GetRecentEvents(0, 10)
	if len(events) == 0 {
		t.Fatalf("expected at least 1 connect event")
	}
	ev := events[0]
	if ev.Email != "test_client" || ev.IP != "198.51.100.42" || ev.Action != "connect" {
		t.Fatalf("unexpected event: %+v", ev)
	}
}

func TestSessionTracker_XrayLogs(t *testing.T) {
	st := GetSessionTracker()

	// 1. Standard Xray access log (without 'from')
	line1 := "2026/08/27 17:00:00 203.0.113.55:54321 accepted tcp:1.1.1.1:443 [vless-in -> direct] email: xray_user_1@domain.com"
	st.ProcessLogLine("xray", line1)

	// 2. Xray log with 'from tcp:'
	line2 := "2026/08/27 17:00:01 [Info] [12345] proxy/vless/inbound: from tcp:198.51.100.77:43210 accepted tcp:example.com:443 [vless-in -> direct] email: xray_user_2@domain.com"
	st.ProcessLogLine("xray", line2)

	events := st.GetRecentEvents(0, 50)
	found1, found2 := false, false
	for _, ev := range events {
		if ev.Email == "xray_user_1@domain.com" && ev.IP == "203.0.113.55" {
			found1 = true
		}
		if ev.Email == "xray_user_2@domain.com" && ev.IP == "198.51.100.77" {
			found2 = true
		}
	}
	if !found1 {
		t.Errorf("expected connect event for xray_user_1@domain.com from 203.0.113.55")
	}
	if !found2 {
		t.Errorf("expected connect event for xray_user_2@domain.com from 198.51.100.77")
	}
}

func TestSessionTracker_Hysteria2Logs(t *testing.T) {
	st := GetSessionTracker()

	// 1. JSON format
	jsonLine := `{"time":"2026-08-27T17:00:00Z","level":"info","msg":"client authenticated","id":"hy_user_json@domain.com","addr":"198.51.100.99:50000"}`
	st.ProcessLogLine("hysteria2", jsonLine)

	// 2. [TCP] forwarding format
	tcpLine := `2026-08-27T17:00:01Z [INFO] [TCP] 198.51.100.88:51234 -> 1.1.1.1:443 (user: hy_user_tcp@domain.com)`
	st.ProcessLogLine("hysteria2", tcpLine)

	// 3. Text auth format
	textLine := `2026-08-27T17:00:02Z [INFO] client authenticated as hy_user_text@domain.com (198.51.100.66:52345)`
	st.ProcessLogLine("hysteria2", textLine)

	events := st.GetRecentEvents(0, 50)
	foundJSON, foundTCP, foundText := false, false, false
	for _, ev := range events {
		if ev.Email == "hy_user_json@domain.com" && ev.IP == "198.51.100.99" {
			foundJSON = true
		}
		if ev.Email == "hy_user_tcp@domain.com" && ev.IP == "198.51.100.88" {
			foundTCP = true
		}
		if ev.Email == "hy_user_text@domain.com" && ev.IP == "198.51.100.66" {
			foundText = true
		}
	}
	if !foundJSON {
		t.Errorf("expected connect event for hy_user_json@domain.com from 198.51.100.99")
	}
	if !foundTCP {
		t.Errorf("expected connect event for hy_user_tcp@domain.com from 198.51.100.88")
	}
	if !foundText {
		t.Errorf("expected connect event for hy_user_text@domain.com from 198.51.100.66")
	}
}

func TestSessionTracker_SingBoxSpecialEmails(t *testing.T) {
	st := GetSessionTracker()
	line1 := "+0000 2026-08-25 19:55:12 INFO [88889999 0ms] inbound/vless[inbound-8]: inbound connection from 198.51.100.123:33445"
	line2 := "+0000 2026-08-25 19:55:12 INFO [88889999 155ms] inbound/vless[inbound-8]: [user_test+vpn.1@domain.com] inbound connection to 198.51.100.1:443"

	st.ProcessLogLine("singbox", line1)
	st.ProcessLogLine("singbox", line2)

	events := st.GetRecentEvents(0, 50)
	found := false
	for _, ev := range events {
		if ev.Email == "user_test+vpn.1@domain.com" && ev.IP == "198.51.100.123" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected session/event for user_test+vpn.1@domain.com with IP 198.51.100.123")
	}
}

func TestSessionTracker_NetworkRoamingSwitch(t *testing.T) {
	st := GetSessionTracker()

	// 1. User connects from Wi-Fi IP
	st.RegisterExternalConnect("sing-box", "roaming_user", "192.168.1.55")
	active := st.GetActiveSessions()
	var wifiActive bool
	for _, s := range active {
		if s.Email == "roaming_user" && s.IP == "192.168.1.55" {
			wifiActive = true
		}
	}
	if !wifiActive {
		t.Fatalf("expected active session on wifi IP")
	}

	// 2. User switches to Mobile IP
	st.RegisterExternalConnect("sing-box", "roaming_user", "198.51.100.88")
	active2 := st.GetActiveSessions()
	var mobileActive bool
	for _, s := range active2 {
		if s.Email == "roaming_user" && s.IP == "198.51.100.88" {
			mobileActive = true
		}
		if s.Email == "roaming_user" && s.IP == "192.168.1.55" {
			t.Fatalf("old wifi IP session should have been disconnected and removed")
		}
	}
	if !mobileActive {
		t.Fatalf("expected active session on mobile IP")
	}

	// 3. User switches back to Wi-Fi IP
	st.RegisterExternalConnect("sing-box", "roaming_user", "192.168.1.55")
	active3 := st.GetActiveSessions()
	var wifiActiveAgain bool
	for _, s := range active3 {
		if s.Email == "roaming_user" && s.IP == "192.168.1.55" {
			wifiActiveAgain = true
		}
		if s.Email == "roaming_user" && s.IP == "198.51.100.88" {
			t.Fatalf("old mobile IP session should have been disconnected and removed")
		}
	}
	if !wifiActiveAgain {
		t.Fatalf("expected active session on wifi IP after roaming back")
	}
}

func TestFormatDuration(t *testing.T) {
	fromPkgI18n := func(loc string) {
		if loc == "en" {
			i18n.SetLocale(i18n.LocaleEN)
		} else {
			i18n.SetLocale(i18n.LocaleRU)
		}
	}
	defer fromPkgI18n("ru")

	fromPkgI18n("ru")
	casesRU := []struct {
		inputSec int64
		expected string
	}{
		{-5, "1 сек"},
		{0, "1 сек"},
		{1, "1 сек"},
		{45, "45 сек"},
		{60, "1 мин"},
		{75, "1 мин 15 сек"},
		{3600, "1 ч"},
		{3665, "1 ч 1 мин"},
		{7320, "2 ч 2 мин"},
	}

	for _, tc := range casesRU {
		res := formatDuration(tc.inputSec)
		if res != tc.expected {
			t.Errorf("RU formatDuration(%d) = %q, expected %q", tc.inputSec, res, tc.expected)
		}
	}

	fromPkgI18n("en")
	casesEN := []struct {
		inputSec int64
		expected string
	}{
		{-5, "1s"},
		{0, "1s"},
		{1, "1s"},
		{45, "45s"},
		{60, "1m"},
		{75, "1m 15s"},
		{3600, "1h"},
		{3665, "1h 1m"},
		{7320, "2h 2m"},
	}

	for _, tc := range casesEN {
		res := formatDuration(tc.inputSec)
		if res != tc.expected {
			t.Errorf("EN formatDuration(%d) = %q, expected %q", tc.inputSec, res, tc.expected)
		}
	}
}

func TestSessionTracker_SingBoxAnonymizedStream(t *testing.T) {
	st := GetSessionTracker()

	anonymizedLogs := []string{
		"+0000 2026-08-31 10:00:01 INFO [10000001 0ms] inbound/vless[inbound-8]: inbound connection from 198.51.100.50:5019",
		"+0000 2026-08-31 10:00:01 INFO [10000001 79ms] inbound/vless[inbound-8]: [client_alpha] inbound connection to www.example.com:443",
		"+0000 2026-08-31 10:00:01 INFO [10000001 79ms] outbound/hysteria2[primary]: outbound connection to www.example.com:443",
		"+0000 2026-08-31 10:00:02 INFO [10000002 0ms] inbound/vless[inbound-8]: inbound connection from 198.51.100.50:18611",
		"+0000 2026-08-31 10:00:02 INFO [10000002 89ms] inbound/vless[inbound-8]: [client_alpha] inbound connection to [2001:db8::a]:443",
		"+0000 2026-08-31 10:00:03 INFO [20000001 0ms] inbound/vless[inbound-8]: inbound connection from 203.0.113.88:28658",
		"+0000 2026-08-31 10:00:03 INFO [20000002 0ms] inbound/vless[inbound-8]: inbound connection from 203.0.113.88:31042",
		"+0000 2026-08-31 10:00:03 INFO [20000001 80ms] inbound/vless[inbound-8]: [client_beta] inbound connection to [2001:db8::a]:443",
		"+0000 2026-08-31 10:00:03 INFO [20000002 77ms] inbound/vless[inbound-8]: [client_beta] inbound connection to www.example.com:443",
		"+0000 2026-08-31 10:00:04 INFO [30000001 0ms] inbound/vless[inbound-8]: inbound connection from 192.0.2.77:14959",
		"+0000 2026-08-31 10:00:04 INFO [30000001 96ms] inbound/vless[inbound-8]: [user.gamma@domain.com] route to outbound/hysteria2[primary]",
	}

	for _, line := range anonymizedLogs {
		st.ProcessLogLine("singbox", line)
	}

	active := st.GetActiveSessions()
	alphaFound := false
	betaFound := false
	for _, s := range active {
		if s.Email == "client_alpha" && s.IP == "198.51.100.50" {
			alphaFound = true
		}
		if s.Email == "client_beta" && s.IP == "203.0.113.88" {
			betaFound = true
		}
	}

	if !alphaFound {
		t.Errorf("expected active session for client_alpha with IP 198.51.100.50, active=%+v", active)
	}
	if !betaFound {
		t.Errorf("expected active session for client_beta with IP 203.0.113.88, active=%+v", active)
	}

	events := st.GetRecentEvents(0, 100)
	var hasAlphaEvent, hasBetaEvent bool
	for _, ev := range events {
		if ev.Email == "client_alpha" && ev.IP == "198.51.100.50" && ev.Action == "connect" {
			hasAlphaEvent = true
		}
		if ev.Email == "client_beta" && ev.IP == "203.0.113.88" && ev.Action == "connect" {
			hasBetaEvent = true
		}
	}

	if !hasAlphaEvent {
		t.Errorf("expected connect event for client_alpha from 198.51.100.50")
	}
	if !hasBetaEvent {
		t.Errorf("expected connect event for client_beta from 203.0.113.88")
	}
}

func TestSessionTracker_MultiClientGoogleTraffic(t *testing.T) {
	st := GetSessionTracker()

	// Interleaved stream from 3 distinct clients making concurrent requests to Google DNS (8.8.8.8:53/853) & Google Web (443)
	concurrentLogs := []string{
		// Client 1 (mobile_user1 from 198.51.100.10) connects to 8.8.8.8:853
		"+0000 2026-08-31 12:00:01 INFO [11111111 0ms] inbound/vless[inbound-8]: inbound connection from 198.51.100.10:32402",
		// Client 2 (mobile_user2 from 203.0.113.20) connects to 8.8.8.8:53
		"+0000 2026-08-31 12:00:01 INFO [22222222 0ms] inbound/vless[inbound-8]: inbound connection from 203.0.113.20:41150",
		// Client 3 (pc_user from 192.0.2.30) connects to www.google.com:443
		"+0000 2026-08-31 12:00:01 INFO [33333333 0ms] inbound/vless[inbound-8]: inbound connection from 192.0.2.30:52110",

		// Interleaved authentications & routings
		"+0000 2026-08-31 12:00:01 INFO [11111111 45ms] inbound/vless[inbound-8]: [mobile_user1] inbound connection to 8.8.8.8:853",
		"+0000 2026-08-31 12:00:01 INFO [11111111 45ms] outbound/direct[direct]: outbound connection to 8.8.8.8:853",
		"+0000 2026-08-31 12:00:01 INFO [22222222 50ms] inbound/vless[inbound-8]: [mobile_user2] inbound connection to 8.8.8.8:53",
		"+0000 2026-08-31 12:00:01 INFO [22222222 50ms] outbound/hysteria2[primary]: outbound connection to 8.8.8.8:53",
		"+0000 2026-08-31 12:00:01 INFO [33333333 80ms] inbound/vless[inbound-8]: [pc_user] inbound connection to www.google.com:443",
		"+0000 2026-08-31 12:00:01 INFO [33333333 80ms] outbound/hysteria2[primary]: outbound connection to www.google.com:443",

		// Subsequent requests from same users (different ports / connection IDs)
		"+0000 2026-08-31 12:00:02 INFO [11111112 0ms] inbound/vless[inbound-8]: inbound connection from 198.51.100.10:32408",
		"+0000 2026-08-31 12:00:02 INFO [11111112 40ms] inbound/vless[inbound-8]: [mobile_user1] inbound connection to dns.google:443",
	}

	for _, line := range concurrentLogs {
		st.ProcessLogLine("sing-box", line)
	}

	// 1. Verify Active Sessions
	active := st.GetActiveSessions()
	expected := map[string]string{
		"mobile_user1": "198.51.100.10",
		"mobile_user2": "203.0.113.20",
		"pc_user":      "192.0.2.30",
	}

	for expUser, expIP := range expected {
		found := false
		for _, s := range active {
			if s.Email == expUser && s.IP == expIP {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("active session not found for %s (%s), current active: %+v", expUser, expIP, active)
		}
	}

	// 2. Verify Online Emails
	emails := st.GetOnlineEmails()
	for expUser := range expected {
		found := false
		for _, e := range emails {
			if e == expUser {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("online email not found for %s, current: %+v", expUser, emails)
		}
	}

	// 3. Verify JSON C-FFI output
	jsonActive := st.GetActiveSessionsJSON()
	if !strings.Contains(jsonActive, "mobile_user1") || !strings.Contains(jsonActive, "198.51.100.10") {
		t.Errorf("GetActiveSessionsJSON missing mobile_user1: %s", jsonActive)
	}

	eventsJSON := st.GetRecentEventsJSON(0, 100)
	if !strings.Contains(eventsJSON, "mobile_user1") || !strings.Contains(eventsJSON, "198.51.100.10") {
		t.Errorf("GetRecentEventsJSON missing mobile_user1: %s", eventsJSON)
	}
}

func TestProcessManager_PureStdoutPipeStreaming_ZeroDiskIO(t *testing.T) {
	broadcaster := GetLogBroadcaster()
	tracker := GetSessionTracker()

	line1 := "+0000 2026-08-31 15:00:01 INFO [77777777 0ms] inbound/vless[inbound-8]: inbound connection from 188.170.74.53:30276"
	line2 := "+0000 2026-08-31 15:00:01 INFO [77777777 82ms] inbound/vless[inbound-8]: [phone] inbound connection to www.google.com:443"
	line3 := "+0000 2026-08-31 15:00:01 INFO [77777777 84ms] outbound/hysteria2[primary]: outbound connection to www.google.com:443"

	// 1. Create in-memory pipe simulator (io.Pipe) - pure RAM, zero disk IO
	pr, pw := io.Pipe()

	streamDone := make(chan struct{})
	go func() {
		StreamPipe("sing-box", pr)
		close(streamDone)
	}()

	// 2. Stream real Sing-box lines into pipe
	go func() {
		fmt.Fprintln(pw, line1)
		time.Sleep(10 * time.Millisecond)
		fmt.Fprintln(pw, line2)
		time.Sleep(10 * time.Millisecond)
		fmt.Fprintln(pw, line3)
		pw.Close()
	}()

	<-streamDone

	// 3. Verify LogBroadcaster in-memory history
	history := broadcaster.GetHistory("sing-box", 50)
	foundL1 := false
	foundL2 := false
	for _, l := range history {
		if strings.Contains(l, "188.170.74.53:30276") {
			foundL1 = true
		}
		if strings.Contains(l, "[phone] inbound connection to www.google.com:443") {
			foundL2 = true
		}
	}
	if !foundL1 {
		t.Errorf("stdout pipe line 1 was not captured in LogBroadcaster memory: %+v", history)
	}
	if !foundL2 {
		t.Errorf("stdout pipe line 2 was not captured in LogBroadcaster memory: %+v", history)
	}

	// 4. Verify SessionTracker pure RAM state
	active := tracker.GetActiveSessions()
	var phoneSession *SessionInfo
	for _, s := range active {
		if s.Email == "phone" && s.IP == "188.170.74.53" {
			phoneSession = s
			break
		}
	}
	if phoneSession == nil {
		t.Fatalf("expected active session for phone with IP 188.170.74.53 captured purely from stdout pipe, got: %+v", active)
	}

	events := tracker.GetRecentEvents(0, 100)
	var phoneConnectEvent *SessionEvent
	for _, ev := range events {
		if ev.Email == "phone" && ev.IP == "188.170.74.53" && ev.Action == "connect" {
			phoneConnectEvent = ev
			break
		}
	}
	if phoneConnectEvent == nil {
		t.Fatalf("expected connect event for phone with IP 188.170.74.53 captured purely from stdout pipe, events: %+v", events)
	}
}



