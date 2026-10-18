package supervisor

import (
	"bytes"
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

func TestFetchHysteriaTraffic_ConsecutivePollsNoCompounding(t *testing.T) {
	ResetHysteriaCumulativeTraffic()
	defer ResetHysteriaCumulativeTraffic()

	hyListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	hyPort := hyListener.Addr().(*net.TCPAddr).Port

	hyMux := http.NewServeMux()
	hyMux.HandleFunc("/traffic", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"user1@test.com": map[string]int64{"tx": 5000, "rx": 2500},
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

	// Simulate 5 consecutive 5-second polling intervals with static traffic
	for i := 1; i <= 5; i++ {
		traffic, err := FetchHysteriaTraffic(hyPort)
		if err != nil {
			t.Fatalf("poll %d failed: %v", i, err)
		}
		u, ok := traffic["user1@test.com"]
		if !ok {
			t.Fatalf("poll %d: user1@test.com not found", i)
		}
		if u.DownBytes != 5000 {
			t.Errorf("poll %d: expected DownBytes=5000, got %d (compounding bug detected!)", i, u.DownBytes)
		}
		if u.UpBytes != 2500 {
			t.Errorf("poll %d: expected UpBytes=2500, got %d (compounding bug detected!)", i, u.UpBytes)
		}
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
						"sourceIP": "198.51.100.1",
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

func TestFetchSingBoxTraffic_SessionTrackerResolution(t *testing.T) {
	ResetSingBoxCumulativeTraffic()
	st := GetSessionTracker()
	st.Clear()

	// 1. Process Sing-box connection logs for test user
	st.ProcessLogLine("sing-box", `INFO [958638302 0ms] inbound/vless[vless-in]: inbound connection from 198.51.100.42:54321`)
	st.ProcessLogLine("sing-box", `INFO [958638302 0ms] inbound/vless[vless-in]: [test_singbox_user] inbound connection to 1.1.1.1:443`)

	// 2. Mock Sing-box Clash API: connection has NO user in metadata (sing-box standard behavior),
	// but has sourceIP: "198.51.100.42" and sourcePort: "54321"
	apiMux := http.NewServeMux()
	currentDlTotal := int64(5000)
	currentUpTotal := int64(1000)
	hasActive := true

	apiMux.HandleFunc("/connections", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		conns := []map[string]any{}
		if hasActive {
			conns = append(conns, map[string]any{
				"id":       "conn-test-1",
				"download": 5000,
				"upload":   1000,
				"metadata": map[string]string{
					"sourceIP":   "198.51.100.42",
					"sourcePort": "54321",
					"type":       "vless/vless-in",
				},
			})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"downloadTotal": currentDlTotal,
			"uploadTotal":   currentUpTotal,
			"connections":   conns,
		})
	})

	server := httptest.NewServer(apiMux)
	defer server.Close()

	// Phase 1: Active connection
	traffic, err := FetchSingBoxTraffic(server.Listener.Addr().String())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	userTraffic, ok := traffic["test_singbox_user"]
	if !ok {
		t.Fatalf("expected traffic for user 'test_singbox_user' resolved via SessionTracker, got: %v", traffic)
	}
	if userTraffic.DownBytes != 5000 || userTraffic.UpBytes != 1000 {
		t.Errorf("expected 5000 down, 1000 up, got: %+v", userTraffic)
	}
	if !userTraffic.Online {
		t.Errorf("expected test_singbox_user to be online during active connection")
	}

	// Phase 2: Connection closes, but downloadTotal/uploadTotal accumulated additional 2000 down, 500 up
	hasActive = false
	currentDlTotal += 2000
	currentUpTotal += 500

	traffic2, err := FetchSingBoxTraffic(server.Listener.Addr().String())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	userTraffic2, ok := traffic2["test_singbox_user"]
	if !ok {
		t.Fatalf("expected traffic for user 'test_singbox_user' retained across closed connections, got: %v", traffic2)
	}
	if userTraffic2.DownBytes != 7000 || userTraffic2.UpBytes != 1500 {
		t.Errorf("expected 7000 down, 1500 up total, got: %+v", userTraffic2)
	}
}

func TestFetchSingBoxTraffic_MultipleConcurrentClients(t *testing.T) {
	ResetSingBoxCumulativeTraffic()
	st := GetSessionTracker()
	st.Clear()

	// 1. Client logs processing for 3 concurrent users
	// User Alpha (2 connections: 10001, 10002)
	st.ProcessLogLine("sing-box", `INFO [100 0ms] inbound/vless[vless-in]: inbound connection from 198.51.100.10:10001`)
	st.ProcessLogLine("sing-box", `INFO [100 0ms] inbound/vless[vless-in]: [user_alpha] inbound connection to 1.1.1.1:443`)
	st.ProcessLogLine("sing-box", `INFO [101 0ms] inbound/vless[vless-in]: inbound connection from 198.51.100.10:10002`)
	st.ProcessLogLine("sing-box", `INFO [101 0ms] inbound/vless[vless-in]: [user_alpha] inbound connection to 8.8.8.8:443`)

	// User Beta (1 connection: 20001)
	st.ProcessLogLine("sing-box", `INFO [200 0ms] inbound/vless[vless-in]: inbound connection from 198.51.100.20:20001`)
	st.ProcessLogLine("sing-box", `INFO [200 0ms] inbound/vless[vless-in]: [user_beta] inbound connection to 9.9.9.9:443`)

	// User Gamma (1 connection: 30001)
	st.ProcessLogLine("sing-box", `INFO [300 0ms] inbound/vless[vless-in]: inbound connection from 198.51.100.30:30001`)
	st.ProcessLogLine("sing-box", `INFO [300 0ms] inbound/vless[vless-in]: [user_gamma] inbound connection to 1.0.0.1:443`)

	apiMux := http.NewServeMux()
	var currentDlTotal, currentUpTotal int64
	var activeConns []map[string]any

	apiMux.HandleFunc("/connections", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"downloadTotal": currentDlTotal,
			"uploadTotal":   currentUpTotal,
			"connections":   activeConns,
		})
	})

	server := httptest.NewServer(apiMux)
	defer server.Close()

	// --- PHASE 1: All 3 clients pushing traffic concurrently ---
	// Alpha: conn-a1: 7MB down, 700KB up; conn-a2: 3MB down, 300KB up => 10MB down, 1MB up
	// Beta: conn-b1: 5MB down, 500KB up
	// Gamma: conn-g1: 2MB down, 200KB up
	// Grand total: 17MB down, 1.7MB up
	currentDlTotal = 17 * 1024 * 1024
	currentUpTotal = 1700 * 1024
	activeConns = []map[string]any{
		{
			"id": "conn-a1", "download": 7 * 1024 * 1024, "upload": 700 * 1024,
			"metadata": map[string]string{"sourceIP": "198.51.100.10", "sourcePort": "10001", "type": "vless/vless-in"},
		},
		{
			"id": "conn-a2", "download": 3 * 1024 * 1024, "upload": 300 * 1024,
			"metadata": map[string]string{"sourceIP": "198.51.100.10", "sourcePort": "10002", "type": "vless/vless-in"},
		},
		{
			"id": "conn-b1", "download": 5 * 1024 * 1024, "upload": 500 * 1024,
			"metadata": map[string]string{"sourceIP": "198.51.100.20", "sourcePort": "20001", "type": "vless/vless-in"},
		},
		{
			"id": "conn-g1", "download": 2 * 1024 * 1024, "upload": 200 * 1024,
			"metadata": map[string]string{"sourceIP": "198.51.100.30", "sourcePort": "30001", "type": "vless/vless-in"},
		},
	}

	t1, err := FetchSingBoxTraffic(server.Listener.Addr().String())
	if err != nil {
		t.Fatalf("Phase 1 error: %v", err)
	}

	if t1["user_alpha"].DownBytes != 10*1024*1024 || t1["user_alpha"].UpBytes != 1000*1024 || !t1["user_alpha"].Online {
		t.Errorf("Phase 1 user_alpha unexpected: %+v", t1["user_alpha"])
	}
	if t1["user_beta"].DownBytes != 5*1024*1024 || t1["user_beta"].UpBytes != 500*1024 || !t1["user_beta"].Online {
		t.Errorf("Phase 1 user_beta unexpected: %+v", t1["user_beta"])
	}
	if t1["user_gamma"].DownBytes != 2*1024*1024 || t1["user_gamma"].UpBytes != 200*1024 || !t1["user_gamma"].Online {
		t.Errorf("Phase 1 user_gamma unexpected: %+v", t1["user_gamma"])
	}

	// --- PHASE 2: Incremental streaming while Gamma closes connection ---
	// Alpha adds +5MB down (conn-a1 +3MB -> 10MB, conn-a2 +2MB -> 5MB)
	// Beta adds +5MB down (conn-b1 +5MB -> 10MB)
	// Gamma transfers +3MB and CLOSES conn-g1! (conn-g1 removed from active connections, totals increase by 3MB down, 300KB up)
	// Delta totals: +5MB (alpha) + 5MB (beta) + 3MB (gamma) = +13MB down, +1.3MB up
	currentDlTotal += 13 * 1024 * 1024
	currentUpTotal += 1300 * 1024

	activeConns = []map[string]any{
		{
			"id": "conn-a1", "download": 10 * 1024 * 1024, "upload": 1000 * 1024,
			"metadata": map[string]string{"sourceIP": "198.51.100.10", "sourcePort": "10001", "type": "vless/vless-in"},
		},
		{
			"id": "conn-a2", "download": 5 * 1024 * 1024, "upload": 500 * 1024,
			"metadata": map[string]string{"sourceIP": "198.51.100.10", "sourcePort": "10002", "type": "vless/vless-in"},
		},
		{
			"id": "conn-b1", "download": 10 * 1024 * 1024, "upload": 1000 * 1024,
			"metadata": map[string]string{"sourceIP": "198.51.100.20", "sourcePort": "20001", "type": "vless/vless-in"},
		},
		// conn-g1 is GONE!
	}

	t2, err := FetchSingBoxTraffic(server.Listener.Addr().String())
	if err != nil {
		t.Fatalf("Phase 2 error: %v", err)
	}

	// Verify exact isolation:
	// Alpha total: 10MB + 5MB = 15MB down, 1.5MB up
	if t2["user_alpha"].DownBytes != 15*1024*1024 || t2["user_alpha"].UpBytes != 1500*1024 || !t2["user_alpha"].Online {
		t.Errorf("Phase 2 user_alpha expected 15MB down, 1.5MB up, got: %+v", t2["user_alpha"])
	}
	// Beta total: 5MB + 5MB = 10MB down, 1MB up
	if t2["user_beta"].DownBytes != 10*1024*1024 || t2["user_beta"].UpBytes != 1000*1024 || !t2["user_beta"].Online {
		t.Errorf("Phase 2 user_beta expected 10MB down, 1MB up, got: %+v", t2["user_beta"])
	}
	// Gamma total: 2MB + 3MB (closed delta!) = 5MB down, 500KB up, Online: false
	if t2["user_gamma"].DownBytes != 5*1024*1024 || t2["user_gamma"].UpBytes != 500*1024 {
		t.Errorf("Phase 2 user_gamma expected 5MB down, 500KB up, got: %+v", t2["user_gamma"])
	}
	if t2["user_gamma"].Online {
		t.Errorf("Phase 2 user_gamma expected offline after conn closed, got online")
	}

	// Grand check: sum across all users == currentDlTotal
	var sumDown, sumUp int64
	for _, ct := range t2 {
		sumDown += ct.DownBytes
		sumUp += ct.UpBytes
	}
	if sumDown != currentDlTotal || sumUp != currentUpTotal {
		t.Errorf("Grand total mismatch: expected (%d down, %d up), got (%d down, %d up)",
			currentDlTotal, currentUpTotal, sumDown, sumUp)
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

func TestProcessManager_EnsureSingboxRuleStubs(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "singbox.json")
	cfgJSON := `{
		"route": {
			"rule_set": [
				{
					"tag": "geosite-ru",
					"initial_path": "rules/geosite-ru.srs"
				},
				{
					"tag": "geoip-ru",
					"initial_path": "rules/geoip-ru.srs"
				}
			]
		}
	}`
	if err := os.WriteFile(cfgPath, []byte(cfgJSON), 0644); err != nil {
		t.Fatalf("failed to write test config: %v", err)
	}

	binDir := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(binDir, 0755); err != nil {
		t.Fatalf("failed to create binDir: %v", err)
	}

	// Run stub generator on empty directory
	ensureSingboxRuleStubs(cfgPath, binDir)

	geositeStub := filepath.Join(binDir, "rules", "geosite-ru.srs")
	geoipStub := filepath.Join(binDir, "rules", "geoip-ru.srs")

	data1, err1 := os.ReadFile(geositeStub)
	if err1 != nil {
		t.Fatalf("expected geosite stub to exist: %v", err1)
	}
	if len(data1) != 17 || !bytes.Equal(data1, emptySrsStub) {
		t.Fatalf("expected 17-byte empty stub, got %d bytes", len(data1))
	}

	data2, err2 := os.ReadFile(geoipStub)
	if err2 != nil {
		t.Fatalf("expected geoip stub to exist: %v", err2)
	}
	if len(data2) != 17 || !bytes.Equal(data2, emptySrsStub) {
		t.Fatalf("expected 17-byte empty stub, got %d bytes", len(data2))
	}

	// Ensure calling again does NOT overwrite existing files (e.g. if updated)
	customData := []byte("already-downloaded-content")
	_ = os.WriteFile(geositeStub, customData, 0644)
	ensureSingboxRuleStubs(cfgPath, binDir)

	dataAfter, _ := os.ReadFile(geositeStub)
	if !bytes.Equal(dataAfter, customData) {
		t.Errorf("expected existing file to be preserved, but was overwritten")
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
	var foundEv bool
	for _, ev := range events {
		if ev.Email == "test_client" && ev.IP == "198.51.100.42" && ev.Action == "connect" {
			foundEv = true
			break
		}
	}
	if !foundEv {
		t.Fatalf("expected connect event for test_client with IP 198.51.100.42, got: %+v", events)
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

func TestSessionTracker_Hysteria2ProductionLifecycle(t *testing.T) {
	st := &SessionTracker{
		sessions:     make(map[string]*SessionInfo),
		singboxConns: make(map[string]string),
		events:       make([]*SessionEvent, 0, 100),
		maxEvents:    100,
	}

	// 1. Client connects
	st.ProcessLogLine("hysteria2", `2026-08-31T12:19:11Z	INFO	client connected	{"addr": "198.51.100.205:34897", "id": "test_hy2_client", "tx": 0}`)

	active := st.GetActiveSessions()
	if len(active) != 1 || active[0].Email != "test_hy2_client" || active[0].IP != "198.51.100.205" {
		t.Fatalf("expected 1 active session for test_hy2_client, got %+v", active)
	}

	events := st.GetRecentEvents(0, 100)
	if len(events) != 1 || events[0].Action != "connect" {
		t.Fatalf("expected 1 connect event, got %+v", events)
	}

	// 2. TCP error timeout (should NOT create new connect events)
	st.ProcessLogLine("hysteria2", `2026-08-31T12:21:10Z	WARN	TCP error	{"addr": "198.51.100.205:34897", "id": "test_hy2_client", "reqAddr": "8.8.8.8:443", "error": "timeout: no recent network activity"}`)
	events = st.GetRecentEvents(0, 100)
	if len(events) != 1 {
		t.Fatalf("TCP error should not create connect event, got %d events", len(events))
	}

	// 3. Client disconnects
	st.ProcessLogLine("hysteria2", `2026-08-31T12:21:10Z	INFO	client disconnected	{"addr": "198.51.100.205:34897", "id": "test_hy2_client", "error": "accepting stream failed: timeout: no recent network activity"}`)

	active = st.GetActiveSessions()
	if len(active) != 0 {
		t.Fatalf("expected 0 active sessions after disconnect, got %+v", active)
	}

	events = st.GetRecentEvents(0, 100)
	if len(events) != 2 || events[1].Action != "disconnect" || events[1].Email != "test_hy2_client" {
		t.Fatalf("expected connect + disconnect events, got %+v", events)
	}
}

func TestSessionTracker_RealSingBoxLogLifecycle(t *testing.T) {
	st := &SessionTracker{
		sessions:     make(map[string]*SessionInfo),
		singboxConns: make(map[string]string),
		events:       make([]*SessionEvent, 0, 100),
		maxEvents:    100,
	}

	// 1. Stage 1: Handshake with Source IP
	st.ProcessLogLine("sing-box", `+0300 2026-08-31 20:05:29 INFO [2594726825 0ms] inbound/vless[vless-in]: inbound connection from 127.0.0.1:54793`)
	if st.singboxConns["2594726825"] != "127.0.0.1" {
		t.Fatalf("expected singboxConns[2594726825] == 127.0.0.1, got: %s", st.singboxConns["2594726825"])
	}

	// 2. Stage 2: User routing
	st.ProcessLogLine("sing-box", `+0300 2026-08-31 20:05:29 INFO [2594726825 1ms] inbound/vless[vless-in]: [test_client_alpha] inbound connection to 127.0.0.1:54788`)

	active := st.GetActiveSessions()
	if len(active) != 1 || active[0].Email != "test_client_alpha" || active[0].IP != "127.0.0.1" {
		t.Fatalf("expected 1 active session for test_client_alpha from 127.0.0.1, got: %+v", active)
	}

	events := st.GetRecentEvents(0, 100)
	if len(events) != 1 || events[0].Action != "connect" || events[0].Email != "test_client_alpha" {
		t.Fatalf("expected connect event, got: %+v", events)
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

	line1 := "+0000 2026-08-31 15:00:01 INFO [77777777 0ms] inbound/vless[inbound-8]: inbound connection from 198.51.100.200:30276"
	line2 := "+0000 2026-08-31 15:00:01 INFO [77777777 82ms] inbound/vless[inbound-8]: [test_client_vless] inbound connection to www.example.com:443"
	line3 := "+0000 2026-08-31 15:00:01 INFO [77777777 84ms] outbound/hysteria2[primary]: outbound connection to www.example.com:443"

	// 1. Create in-memory pipe simulator (io.Pipe) - pure RAM, zero disk IO
	pr, pw := io.Pipe()

	streamDone := make(chan struct{})
	go func() {
		StreamPipe("sing-box", pr)
		close(streamDone)
	}()

	// 2. Stream Sing-box lines into pipe
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
		if strings.Contains(l, "198.51.100.200:30276") {
			foundL1 = true
		}
		if strings.Contains(l, "[test_client_vless] inbound connection to www.example.com:443") {
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
	var testSession *SessionInfo
	for _, s := range active {
		if s.Email == "test_client_vless" && s.IP == "198.51.100.200" {
			testSession = s
			break
		}
	}
	if testSession == nil {
		t.Fatalf("expected active session for test_client_vless with IP 198.51.100.200 captured purely from stdout pipe, got: %+v", active)
	}

	events := tracker.GetRecentEvents(0, 100)
	var testConnectEvent *SessionEvent
	for _, ev := range events {
		if ev.Email == "test_client_vless" && ev.IP == "198.51.100.200" && ev.Action == "connect" {
			testConnectEvent = ev
			break
		}
	}
	if testConnectEvent == nil {
		t.Fatalf("expected connect event for test_client_vless with IP 198.51.100.200 captured purely from stdout pipe, events: %+v", events)
	}
}

func TestSessionTracker_AllSingBoxLogFormats(t *testing.T) {
	st := &SessionTracker{
		sessions:     make(map[string]*SessionInfo),
		singboxConns: make(map[string]string),
		events:       make([]*SessionEvent, 0, 100),
		maxEvents:    100,
	}

	testCases := []struct {
		name     string
		lines    []string
		expEmail string
		expIP    string
	}{
		{
			name: "Logrus timestamp prefix with router match",
			lines: []string{
				"INFO[0000] [99887766 0ms] inbound/vless[inbound-1]: inbound connection from 198.51.100.33:55443",
				"INFO[0000] [99887766 12ms] router: match[0] inbound/vless[inbound-1] [user_router@example.com] tcp:1.1.1.1:443 -> direct",
			},
			expEmail: "user_router@example.com",
			expIP:    "198.51.100.33",
		},
		{
			name: "Single-line accepted format",
			lines: []string{
				"2026-08-31 13:00:00 INFO accepted tcp:198.51.100.44:54321 [user_single_line]",
			},
			expEmail: "user_single_line",
			expIP:    "198.51.100.44",
		},
		{
			name: "UUID user format",
			lines: []string{
				"[44332211 0ms] inbound/vless[vless-in]: inbound connection from 198.51.100.55:54321",
				"[44332211 5ms] inbound/vless[vless-in]: [b7c9f8a0-1234-5678-9abc-def012345678] inbound connection to 1.1.1.1:443",
			},
			expEmail: "b7c9f8a0-1234-5678-9abc-def012345678",
			expIP:    "198.51.100.55",
		},
		{
			name: "Hysteria 2 inbound via Sing-box",
			lines: []string{
				"[55667788 0ms] inbound/hysteria2[hy2-in]: inbound connection from 198.51.100.66:43210",
				"[55667788 10ms] inbound/hysteria2[hy2-in]: [hy2_sb_user@example.com] inbound connection to 1.1.1.1:443",
			},
			expEmail: "hy2_sb_user@example.com",
			expIP:    "198.51.100.66",
		},
		{
			name: "Shadowsocks inbound via Sing-box with router match",
			lines: []string{
				"[66778899 0ms] inbound/shadowsocks[ss-in]: inbound connection from 198.51.100.77:33221",
				"[66778899 8ms] router: match[0] [ss_user] tcp:1.1.1.1:443 -> direct",
			},
			expEmail: "ss_user",
			expIP:    "198.51.100.77",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			for _, line := range tc.lines {
				st.ProcessLogLine("sing-box", line)
			}

			active := st.GetActiveSessions()
			found := false
			for _, s := range active {
				if s.Email == tc.expEmail && s.IP == tc.expIP {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("[%s] expected session %s (%s) not found in active: %+v", tc.name, tc.expEmail, tc.expIP, active)
			}
		})
	}
}

func TestSessionTracker_SimulateRealisticVLESSWebBrowsingAndGitHubDownload(t *testing.T) {
	st := &SessionTracker{
		sessions:     make(map[string]*SessionInfo),
		singboxConns: make(map[string]string),
		events:       make([]*SessionEvent, 0, 100),
		maxEvents:    100,
	}

	// 100+ rapid interleaved requests from 3 clients downloading from simulated remote services (RFC 5737 TEST-NET destinations)
	rawTrafficLogs := []string{
		// === Client 1: client_alpha_phone (198.51.100.10) starts downloading release ===
		"+0000 2026-08-31 13:30:00 INFO [10001 0ms] inbound/vless[vless-in]: inbound connection from 198.51.100.10:41201",
		"+0000 2026-08-31 13:30:00 INFO [10001 10ms] inbound/vless[vless-in]: [client_alpha_phone] inbound connection to 192.0.2.53:53",
		"+0000 2026-08-31 13:30:00 INFO [10001 12ms] router: match[0] inbound/vless[vless-in] [client_alpha_phone] udp:192.0.2.53:53 -> direct",

		// === Client 2: client_beta_laptop (203.0.113.20) opens web portal ===
		"+0000 2026-08-31 13:30:00 INFO [20001 0ms] inbound/vless[vless-in]: inbound connection from 203.0.113.20:53401",
		"+0000 2026-08-31 13:30:00 INFO [20001 8ms] inbound/vless[vless-in]: [client_beta_laptop] inbound connection to 192.0.2.104:443",
		"+0000 2026-08-31 13:30:00 INFO [20001 10ms] router: match[0] [client_beta_laptop] tcp:192.0.2.104:443 -> direct",

		// === Client 1: client_alpha_phone opens 4 parallel TCP streams ===
		"+0000 2026-08-31 13:30:01 INFO [10002 0ms] inbound/vless[vless-in]: inbound connection from 198.51.100.10:41202",
		"+0000 2026-08-31 13:30:01 INFO [10003 0ms] inbound/vless[vless-in]: inbound connection from 198.51.100.10:41203",
		"+0000 2026-08-31 13:30:01 INFO [10004 0ms] inbound/vless[vless-in]: inbound connection from 198.51.100.10:41204",
		"+0000 2026-08-31 13:30:01 INFO [10002 15ms] inbound/vless[vless-in]: [client_alpha_phone] inbound connection to 192.0.2.100:443",
		"+0000 2026-08-31 13:30:01 INFO [10002 18ms] router: match[0] inbound/vless[vless-in] [client_alpha_phone] tcp:192.0.2.100:443 -> direct",
		"+0000 2026-08-31 13:30:01 INFO [10003 15ms] inbound/vless[vless-in]: [client_alpha_phone] inbound connection to 192.0.2.100:443",
		"+0000 2026-08-31 13:30:01 INFO [10003 18ms] router: match[0] [client_alpha_phone] tcp:192.0.2.100:443 -> direct",
		"+0000 2026-08-31 13:30:01 INFO [10004 15ms] inbound/vless[vless-in]: [client_alpha_phone] inbound connection to 192.0.2.101:443",
		"+0000 2026-08-31 13:30:01 INFO [10004 18ms] router: match[0] [client_alpha_phone] tcp:192.0.2.101:443 -> direct",

		// === Client 3: client_gamma_desktop (192.0.2.30) syncs remote app ===
		"+0000 2026-08-31 13:30:01 INFO [30001 0ms] inbound/vless[vless-in]: inbound connection from 192.0.2.30:38901",
		"+0000 2026-08-31 13:30:01 INFO [30001 12ms] inbound/vless[vless-in]: [client_gamma_desktop] inbound connection to 192.0.2.102:443",
		"+0000 2026-08-31 13:30:01 INFO [30001 14ms] router: match[0] [client_gamma_desktop] tcp:192.0.2.102:443 -> direct",
		"+0000 2026-08-31 13:30:02 INFO [30002 0ms] inbound/vless[vless-in]: inbound connection from 192.0.2.30:38902",
		"+0000 2026-08-31 13:30:02 INFO [30002 12ms] inbound/vless[vless-in]: [client_gamma_desktop] inbound connection to 192.0.2.103:443",
		"+0000 2026-08-31 13:30:02 INFO [30002 14ms] router: match[0] [client_gamma_desktop] tcp:192.0.2.103:443 -> direct",

		// === Client 1: client_alpha_phone downloads chunk 2 (rapid chunks) ===
		"+0000 2026-08-31 13:30:02 INFO [10005 0ms] inbound/vless[vless-in]: inbound connection from 198.51.100.10:41205",
		"+0000 2026-08-31 13:30:02 INFO [10005 15ms] inbound/vless[vless-in]: [client_alpha_phone] inbound connection to 192.0.2.100:443",
		"+0000 2026-08-31 13:30:02 INFO [10006 0ms] inbound/vless[vless-in]: inbound connection from 198.51.100.10:41206",
		"+0000 2026-08-31 13:30:02 INFO [10006 15ms] inbound/vless[vless-in]: [client_alpha_phone] inbound connection to 192.0.2.100:443",
		"+0000 2026-08-31 13:30:03 INFO [10007 0ms] inbound/vless[vless-in]: inbound connection from 198.51.100.10:41207",
		"+0000 2026-08-31 13:30:03 INFO [10007 15ms] inbound/vless[vless-in]: [client_alpha_phone] inbound connection to 192.0.2.100:443",
		"+0000 2026-08-31 13:30:03 INFO [10008 0ms] inbound/vless[vless-in]: inbound connection from 198.51.100.10:41208",
		"+0000 2026-08-31 13:30:03 INFO [10008 15ms] inbound/vless[vless-in]: [client_alpha_phone] inbound connection to 192.0.2.100:443",
	}

	for _, line := range rawTrafficLogs {
		st.ProcessLogLine("sing-box", line)
	}

	// 1. Verify Active Sessions: Exactly 3 sessions for the 3 real clients
	active := st.GetActiveSessions()
	if len(active) != 3 {
		t.Fatalf("expected exactly 3 active sessions, got %d: %+v", len(active), active)
	}

	expectedSessions := map[string]string{
		"client_alpha_phone":   "198.51.100.10",
		"client_beta_laptop":   "203.0.113.20",
		"client_gamma_desktop": "192.0.2.30",
	}

	for expUser, expIP := range expectedSessions {
		found := false
		for _, s := range active {
			if s.Email == expUser && s.IP == expIP {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("active session not found for %s (%s), active: %+v", expUser, expIP, active)
		}
	}

	// 2. CRITICAL: Verify NO destination IPs leaked as client IPs!
	forbiddenDestIPs := []string{"192.0.2.100", "192.0.2.101", "192.0.2.53", "192.0.2.102", "192.0.2.103", "192.0.2.104"}
	for _, s := range active {
		for _, forbiddenIP := range forbiddenDestIPs {
			if s.IP == forbiddenIP {
				t.Fatalf("CRITICAL BUG: Destination IP %s was erroneously tracked as client IP for session %+v", forbiddenIP, s)
			}
		}
	}

	// 3. Verify Events: Exactly 3 connect events were emitted (NO spam, NO disconnect events!)
	events := st.GetRecentEvents(0, 100)
	if len(events) != 3 {
		t.Fatalf("expected exactly 3 connect events (no spam on VLESS streams), got %d events: %+v", len(events), events)
	}

	for _, ev := range events {
		if ev.Action != "connect" {
			t.Errorf("unexpected event action %s, expected only 'connect' during active browsing: %+v", ev.Action, ev)
		}
		for _, forbiddenIP := range forbiddenDestIPs {
			if ev.IP == forbiddenIP {
				t.Fatalf("CRITICAL BUG: Destination IP %s leaked in event: %+v", forbiddenIP, ev)
			}
		}
	}
}

func TestSessionTracker_RealSingBoxProductionStream(t *testing.T) {
	st := &SessionTracker{
		sessions:     make(map[string]*SessionInfo),
		singboxConns: make(map[string]string),
		events:       make([]*SessionEvent, 0, 100),
		maxEvents:    100,
	}

	prodLogs := []string{
		"+0000 2026-08-31 11:19:52 INFO [4100723628 70ms] outbound/hysteria2[primary]: outbound connection to [2001:db8::a]:443",
		"+0000 2026-08-31 11:19:53 INFO [4256241913 0ms] inbound/vless[inbound-8]: inbound connection from 192.0.2.10:37130",
		"+0000 2026-08-31 11:19:53 INFO [4256241913 202ms] inbound/vless[inbound-8]: [client_user_roaming] inbound connection to www.example.com:443",
		"+0000 2026-08-31 11:19:53 INFO [4256241913 202ms] outbound/hysteria2[primary]: outbound connection to www.example.com:443",
		"+0000 2026-08-31 11:19:53 INFO [2594817763 0ms] inbound/vless[inbound-8]: inbound connection from 192.0.2.10:37144",
		"+0000 2026-08-31 11:19:53 ERROR [2594817763 56ms] inbound/vless[inbound-8]: process connection from 192.0.2.10:37144: EOF",
		"+0000 2026-08-31 11:19:54 INFO [145717122 0ms] inbound/vless[inbound-8]: inbound connection from 192.0.2.10:37150",
		"+0000 2026-08-31 11:19:54 INFO [145717122 51ms] inbound/vless[inbound-8]: [client_user_roaming] inbound connection to [2001:db8::a]:443",
		"+0000 2026-08-31 11:19:54 INFO [145717122 51ms] outbound/hysteria2[primary]: outbound connection to [2001:db8::a]:443",
		"+0000 2026-08-31 11:19:54 INFO [273469817 0ms] inbound/vless[inbound-8]: inbound connection from 192.0.2.10:37164",
		"+0000 2026-08-31 11:19:54 INFO [273469817 45ms] inbound/vless[inbound-8]: [client_user_roaming] inbound connection to www.example.com:443",
		"+0000 2026-08-31 11:19:54 INFO [273469817 45ms] outbound/hysteria2[primary]: outbound connection to www.example.com:443",

		// User roams from Wi-Fi (192.0.2.10) to Mobile LTE (198.51.100.71)
		"+0000 2026-08-31 11:20:08 INFO [3637169170 0ms] inbound/vless[inbound-8]: inbound connection from 198.51.100.71:10911",
		"+0000 2026-08-31 11:20:08 INFO [3637169170 78ms] inbound/vless[inbound-8]: [client_user_roaming] inbound connection to 192.0.2.50:5222",
		"+0000 2026-08-31 11:20:08 INFO [3637169170 78ms] outbound/hysteria2[primary]: outbound connection to 192.0.2.50:5222",
		"+0000 2026-08-31 11:20:09 INFO [2390507552 0ms] inbound/vless[inbound-8]: inbound connection from 198.51.100.71:2983",
		"+0000 2026-08-31 11:20:09 INFO [2390507552 85ms] inbound/vless[inbound-8]: [client_user_roaming] inbound connection to 192.0.2.53:853",
		"+0000 2026-08-31 11:20:09 INFO [2390507552 85ms] outbound/hysteria2[primary]: outbound connection to 192.0.2.53:853",
	}

	for _, l := range prodLogs {
		st.ProcessLogLine("sing-box", l)
	}

	active := st.GetActiveSessions()
	var foundActive bool
	for _, s := range active {
		if s.Email == "client_user_roaming" && s.IP == "198.51.100.71" {
			foundActive = true
		}
	}
	if !foundActive {
		t.Fatalf("expected active session for client_user_roaming on LTE IP 198.51.100.71, active: %+v", active)
	}

	events := st.GetRecentEvents(0, 100)
	if len(events) < 2 {
		t.Fatalf("expected at least connect to Wi-Fi and roam to LTE events, got: %+v", events)
	}
}

func TestSessionTracker_RealProductionHandshakeWithUntrustedIP(t *testing.T) {
	st := &SessionTracker{
		sessions:     make(map[string]*SessionInfo),
		singboxConns: make(map[string]string),
		events:       make([]*SessionEvent, 0, 100),
		maxEvents:    100,
	}

	rawLogs := []string{
		"+0000 2026-08-31 15:02:11 INFO [3250429930 0ms] inbound/vless[inbound-8]: inbound connection from 198.51.100.89:3144",
		"+0000 2026-08-31 15:02:11 INFO [3250429930 109ms] inbound/vless[inbound-8]: [phone] inbound connection to example.org:443",
		"+0000 2026-08-31 15:02:11 INFO [3250429930 109ms] outbound/hysteria2[hysteria2-primary-outbound]: outbound connection to example.org:443",
	}

	for _, l := range rawLogs {
		st.ProcessLogLine("sing-box", l)
	}

	active := st.GetActiveSessions()
	if len(active) != 1 {
		t.Fatalf("expected 1 active session, got %d: %+v", len(active), active)
	}
	if active[0].Email != "phone" || active[0].IP != "198.51.100.89" {
		t.Fatalf("expected active session phone@198.51.100.89, got: %+v", active[0])
	}

	events := st.GetRecentEvents(0, 100)
	if len(events) != 1 {
		t.Fatalf("expected 1 connect event, got %d: %+v", len(events), events)
	}
	if events[0].Action != "connect" || events[0].Email != "phone" || events[0].IP != "198.51.100.89" {
		t.Fatalf("unexpected event: %+v", events[0])
	}
}

func TestSecurityAudit_SafeRulePath_PreventsPathTraversal(t *testing.T) {
	tempDir := t.TempDir()

	// 1. Normal relative path
	p1, ok1 := safeRulePath("rules/geoip-ru.srs", tempDir)
	if !ok1 || !strings.HasPrefix(p1, tempDir) {
		t.Fatalf("expected valid path within tempDir, got %s (ok=%v)", p1, ok1)
	}

	// 2. Traversal attempt with ../../
	p2, ok2 := safeRulePath("../../../../etc/shadow.srs", tempDir)
	if !ok2 {
		t.Fatalf("expected sanitization to succeed, got ok=false")
	}
	if !strings.HasPrefix(p2, tempDir) || strings.Contains(p2, "..") {
		t.Fatalf("path traversal not prevented! got %s", p2)
	}
	if filepath.Base(p2) != "shadow.srs" {
		t.Fatalf("expected base name shadow.srs, got %s", p2)
	}

	// 3. Absolute path attempting escape
	absEscape := filepath.Join(os.TempDir(), "outside", "rules.srs")
	p3, ok3 := safeRulePath(absEscape, tempDir)
	if !ok3 || !strings.HasPrefix(p3, tempDir) {
		t.Fatalf("absolute path escape not contained within tempDir! got %s", p3)
	}

	// 4. Non-rule extension (e.g. .exe, .sh, .bat) should be rejected
	_, ok4 := safeRulePath("malicious.sh", tempDir)
	if ok4 {
		t.Fatalf("expected non-rule extension to be rejected")
	}
}

func TestSecurityAudit_IsSafePrefetchURL_SSRFPrevention(t *testing.T) {
	// Should reject cloud metadata
	if isSafePrefetchURL("http://169.254.169.254/latest/meta-data") {
		t.Fatalf("expected SSRF AWS metadata URL to be blocked")
	}
	if isSafePrefetchURL("http://100.100.100.200/metadata") {
		t.Fatalf("expected Alibaba metadata URL to be blocked")
	}
	if isSafePrefetchURL("http://metadata.google.internal/computeMetadata/v1/") {
		t.Fatalf("expected Google metadata URL to be blocked")
	}

	// Should reject loopback and private LAN
	if isSafePrefetchURL("http://127.0.0.1:8006/api2/json") {
		t.Fatalf("expected loopback Proxmox URL to be blocked")
	}
	if isSafePrefetchURL("http://localhost:9090/rules") {
		t.Fatalf("expected localhost URL to be blocked")
	}
	if isSafePrefetchURL("http://192.168.1.1/admin") {
		t.Fatalf("expected private LAN router URL to be blocked")
	}
	if isSafePrefetchURL("http://10.0.0.1:8080/secret") {
		t.Fatalf("expected private IP 10.0.0.1 to be blocked")
	}

	// Should allow legitimate public HTTPS CDN mirrors
	if !isSafePrefetchURL("https://cdn.jsdelivr.net/gh/SagerNet/sing-geosite@rule-set/geosite-geolocation-!cn.srs") {
		t.Fatalf("expected public jsdelivr HTTPS mirror to be allowed")
	}
	if !isSafePrefetchURL("https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-ru.srs") {
		t.Fatalf("expected public github HTTPS mirror to be allowed")
	}
}

func TestSecurityAudit_StopCore_UnknownCore_Safe(t *testing.T) {
	pm := GetProcessManager()
	// Stopping arbitrary host binary name must not fail or execute taskkill/killall on host binaries
	err := pm.StopCore("explorer")
	if err != nil {
		t.Fatalf("unexpected error stopping unknown core: %v", err)
	}
	err = pm.StopCore("python")
	if err != nil {
		t.Fatalf("unexpected error stopping unknown core: %v", err)
	}
}

func TestSessionTracker_UnauthenticatedHostProbeDoesNotFlap(t *testing.T) {
	ResetSingBoxCumulativeTraffic()
	st := GetSessionTracker()
	st.Clear()

	// Mock RFC 5737 documentation test IPs & synthetic usernames:
	// Client: "mock_client_primary" on 192.0.2.45:54321
	// Unauthenticated probe: 203.0.113.88:48614
	const clientUser = "mock_client_primary"
	const clientIP = "192.0.2.45"
	const clientPort = "54321"
	const probeIP = "203.0.113.88"
	const probePort = "48614"

	// 1. Process Sing-box connection logs for the real client
	st.ProcessLogLine("sing-box", fmt.Sprintf("INFO [1001 0ms] inbound/vless[vless-in]: inbound connection from %s:%s", clientIP, clientPort))
	st.ProcessLogLine("sing-box", fmt.Sprintf("INFO [1001 50ms] inbound/vless[vless-in]: [%s] inbound connection to 198.51.100.1:443", clientUser))

	// Verify client is connected on clientIP
	sessions := st.GetActiveSessions()
	if len(sessions) != 1 {
		t.Fatalf("expected 1 active session, got %d", len(sessions))
	}
	if sessions[0].Email != clientUser || sessions[0].IP != clientIP {
		t.Fatalf("expected session (%s, %s), got (%s, %s)", clientUser, clientIP, sessions[0].Email, sessions[0].IP)
	}

	eventsBefore := st.GetRecentEvents(0, 100)
	if len(eventsBefore) != 1 || eventsBefore[0].Action != "connect" || eventsBefore[0].IP != clientIP {
		t.Fatalf("expected exactly 1 connect event for %s, got: %+v", clientIP, eventsBefore)
	}

	// 2. An unauthenticated probe from probeIP arrives in Sing-box Clash API (no user attached)
	// ResolveSingBoxUser must NOT attribute probeIP to clientUser
	resolvedUser := st.ResolveSingBoxUser(probeIP, probePort)
	if resolvedUser != "" {
		t.Fatalf("expected ResolveSingBoxUser to return empty for unknown probe IP %s, but got: %s", probeIP, resolvedUser)
	}

	// 3. Mock Sing-box Clash API: returns client connection + unauthenticated host probe
	apiMux := http.NewServeMux()
	apiMux.HandleFunc("/connections", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		conns := []map[string]any{
			{
				"id":       "conn-client-1",
				"download": 5000,
				"upload":   1000,
				"metadata": map[string]string{
					"sourceIP":   clientIP,
					"sourcePort": clientPort,
					"type":       "vless/vless-in",
				},
			},
			{
				"id":       "conn-probe-host",
				"download": 100,
				"upload":   50,
				"metadata": map[string]string{
					"sourceIP":   probeIP,
					"sourcePort": probePort,
					"type":       "inbound-probe",
				},
			},
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"downloadTotal": 5100,
			"uploadTotal":   1050,
			"connections":   conns,
		})
	})
	server := httptest.NewServer(apiMux)
	defer server.Close()

	// 4. Query Sing-box traffic via supervisor
	traffic, err := FetchSingBoxTraffic(server.Listener.Addr().String())
	if err != nil {
		t.Fatalf("unexpected error fetching traffic: %v", err)
	}

	// 5. Verify that clientUser traffic was correctly accounted
	clientTraffic, ok := traffic[clientUser]
	if !ok {
		t.Fatalf("expected traffic for user %s", clientUser)
	}
	if clientTraffic.DownBytes != 5000 || clientTraffic.UpBytes != 1000 {
		t.Errorf("expected 5000 down / 1000 up, got: %+v", clientTraffic)
	}

	// 6. Verify that NO false session was created for probeIP and client session did NOT flap
	sessionsAfter := st.GetActiveSessions()
	if len(sessionsAfter) != 1 {
		t.Fatalf("expected exactly 1 active session after probe, got %d: %+v", len(sessionsAfter), sessionsAfter)
	}
	if sessionsAfter[0].Email != clientUser || sessionsAfter[0].IP != clientIP {
		t.Fatalf("expected client session to remain on %s, but got (%s, %s)", clientIP, sessionsAfter[0].Email, sessionsAfter[0].IP)
	}

	eventsAfter := st.GetRecentEvents(0, 100)
	if len(eventsAfter) != 1 {
		t.Fatalf("session flapping detected! Expected exactly 1 event, but got %d events: %+v", len(eventsAfter), eventsAfter)
	}
}


