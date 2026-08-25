package supervisor

import (
	"encoding/json"
	"fmt"
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

func TestSessionTracker_SingBoxRealLog(t *testing.T) {
	st := GetSessionTracker()
	line1 := "+0000 2026-08-25 19:55:12 INFO [1978868683 0ms] inbound/vless[inbound-8]: inbound connection from 178.178.248.163:27073"
	line2 := "+0000 2026-08-25 19:55:12 INFO [1978868683 155ms] inbound/vless[inbound-8]: [phone] inbound connection to 149.154.167.41:443"

	st.ProcessLogLine("singbox", line1)
	st.ProcessLogLine("singbox", line2)

	sessions := st.GetActiveSessions()
	found := false
	for _, s := range sessions {
		if s.Email == "phone" && s.IP == "178.178.248.163" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected session for phone with IP 178.178.248.163, got: %+v", sessions)
	}

	events := st.GetRecentEvents(0, 10)
	if len(events) == 0 {
		t.Fatalf("expected at least 1 connect event")
	}
	ev := events[0]
	if ev.Email != "phone" || ev.IP != "178.178.248.163" || ev.Action != "connect" {
		t.Fatalf("unexpected event: %+v", ev)
	}
}


