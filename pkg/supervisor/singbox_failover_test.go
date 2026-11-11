package supervisor

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestSingBoxFailover_HysteresisAndFailback(t *testing.T) {
	var mu sync.Mutex
	active := "hy2-main-primary"
	health := map[string]bool{
		"hy2-main-primary": true,
		"vless-backup":     true,
	}
	delays := map[string]int{
		"hy2-main-primary": 260, // slower than backup to prove strict priority isn't ping-based
		"vless-backup":     15,
	}
	deletedConns := []string{}

	mux := http.NewServeMux()
	mux.HandleFunc("/proxies", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		cur := active
		mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{
			"proxies": map[string]any{
				"hy2-main": map[string]any{
					"type": "Selector",
					"name": "hy2-main",
					"now":  cur,
					"all":  []string{"hy2-main-primary", "vless-backup"},
				},
			},
		})
	})
	mux.HandleFunc("/proxies/hy2-main-primary/delay", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		ok := health["hy2-main-primary"]
		d := delays["hy2-main-primary"]
		mu.Unlock()
		if !ok {
			http.Error(w, "timeout", http.StatusGatewayTimeout)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]int{"delay": d})
	})
	mux.HandleFunc("/proxies/vless-backup/delay", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		ok := health["vless-backup"]
		d := delays["vless-backup"]
		mu.Unlock()
		if !ok {
			http.Error(w, "timeout", http.StatusGatewayTimeout)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]int{"delay": d})
	})
	mux.HandleFunc("/proxies/hy2-main", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		var body struct {
			Name string `json:"name"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		mu.Lock()
		active = body.Name
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/connections", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"connections": []map[string]any{
				{"id": "conn-primary", "chains": []string{"inbound-1", "hy2-main", "hy2-main-primary"}},
				{"id": "conn-direct", "chains": []string{"inbound-1", "direct"}},
			},
		})
	})
	mux.HandleFunc("/connections/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			mu.Lock()
			deletedConns = append(deletedConns, strings.TrimPrefix(r.URL.Path, "/connections/"))
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		}
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	fc := newSingBoxFailoverController()
	fc.minInterval = time.Millisecond
	fc.SetGroups([]SingBoxFailoverGroup{
		{
			Tag:           "hy2-main",
			Primary:       "hy2-main-primary",
			Outbounds:     []string{"hy2-main-primary", "vless-backup"},
			ProbeURL:      "https://www.gstatic.com/generate_204",
			ProbeInterval: 1,
			Strategy:      "priority",
		},
	})

	addr := strings.TrimPrefix(srv.URL, "http://")
	now := time.Now()

	getActive := func() string {
		mu.Lock()
		defer mu.Unlock()
		return active
	}

	// Step 1: Healthy primary -> stays on primary
	if err := fc.Step(addr, now); err != nil {
		t.Fatalf("step 1 err: %v", err)
	}
	if got := getActive(); got != "hy2-main-primary" {
		t.Fatalf("expected initial active hy2-main-primary, got %s", got)
	}

	// Drop primary; 1st failure must stay on primary (anti-flap hysteresis)
	mu.Lock()
	health["hy2-main-primary"] = false
	mu.Unlock()

	now = now.Add(2 * time.Second)
	_ = fc.Step(addr, now)
	if got := getActive(); got != "hy2-main-primary" {
		t.Fatalf("expected 1st primary failure to debounce and keep primary, got %s", got)
	}

	// 2nd failure -> failover to vless-backup & close stale primary connection (not direct)
	now = now.Add(2 * time.Second)
	_ = fc.Step(addr, now)
	mu.Lock()
	gotActive := active
	gotClosed := append([]string(nil), deletedConns...)
	mu.Unlock()
	if gotActive != "vless-backup" {
		t.Fatalf("expected failover to vless-backup after 2 failures, got %s", gotActive)
	}
	if len(gotClosed) != 1 || gotClosed[0] != "conn-primary" {
		t.Fatalf("expected only conn-primary closed on failover, got %v", gotClosed)
	}

	// Recover primary (still slower 260ms vs 15ms); 1st recovery probe stays on backup (hysteresis)
	mu.Lock()
	health["hy2-main-primary"] = true
	deletedConns = nil
	mu.Unlock()

	now = now.Add(2 * time.Second)
	_ = fc.Step(addr, now)
	mu.Lock()
	gotActive = active
	mu.Unlock()
	if gotActive != "vless-backup" {
		t.Fatalf("expected 1st recovery probe to debounce before failback, got %s", gotActive)
	}

	// 2nd recovery probe -> automatic failback to hy2-main-primary WITHOUT killing healthy backup connections
	now = now.Add(2 * time.Second)
	_ = fc.Step(addr, now)
	mu.Lock()
	gotActive = active
	gotClosed = append([]string(nil), deletedConns...)
	mu.Unlock()
	if gotActive != "hy2-main-primary" {
		t.Fatalf("expected failback to slower hy2-main-primary after 2 passes, got %s", gotActive)
	}
	if len(gotClosed) != 0 {
		t.Fatalf("expected graceful failback without closing healthy backup connections, closed=%v", gotClosed)
	}
}

func startSlowHTTPProxy(t *testing.T, label string, delay time.Duration) (port int, hits *atomic.Int64, stopFn func(), startFn func()) {
	t.Helper()
	hits = &atomic.Int64{}
	var mu sync.Mutex
	var ln net.Listener
	var srv *http.Server

	startAt := func(addr string) int {
		mu.Lock()
		defer mu.Unlock()
		var err error
		ln, err = net.Listen("tcp", addr)
		if err != nil {
			t.Fatalf("failed to listen %s: %v", label, err)
		}
		assignedPort := ln.Addr().(*net.TCPAddr).Port
		srv = &http.Server{
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				if delay > 0 {
					time.Sleep(delay)
				}
				if r.Method == http.MethodConnect {
					upstream, err := net.DialTimeout("tcp", r.Host, 3*time.Second)
					if err != nil {
						http.Error(w, err.Error(), http.StatusBadGateway)
						return
					}
					hj, ok := w.(http.Hijacker)
					if !ok {
						_ = upstream.Close()
						http.Error(w, "hijack unsupported", http.StatusInternalServerError)
						return
					}
					clientConn, _, err := hj.Hijack()
					if err != nil {
						_ = upstream.Close()
						return
					}
					_, _ = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
					go func() {
						defer upstream.Close()
						defer clientConn.Close()
						_, _ = io.Copy(upstream, clientConn)
					}()
					go func() {
						defer upstream.Close()
						defer clientConn.Close()
						_, _ = io.Copy(clientConn, upstream)
					}()
					return
				}
				target := r.RequestURI
				if !strings.HasPrefix(target, "http://") {
					target = "http://" + r.Host + r.URL.RequestURI()
				}
				req, err := http.NewRequestWithContext(r.Context(), r.Method, target, r.Body)
				if err != nil {
					http.Error(w, err.Error(), http.StatusBadGateway)
					return
				}
				resp, err := (&http.Client{Timeout: 3 * time.Second}).Do(req)
				if err != nil {
					http.Error(w, err.Error(), http.StatusBadGateway)
					return
				}
				defer resp.Body.Close()
				for k, vs := range resp.Header {
					for _, v := range vs {
						w.Header().Add(k, v)
					}
				}
				w.WriteHeader(resp.StatusCode)
				_, _ = io.Copy(w, resp.Body)
			}),
		}
		go func(s *http.Server, l net.Listener) {
			_ = s.Serve(l)
		}(srv, ln)
		return assignedPort
	}

	port = startAt("127.0.0.1:0")
	fixedAddr := fmt.Sprintf("127.0.0.1:%d", port)
	stopFn = func() {
		mu.Lock()
		defer mu.Unlock()
		if srv != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
			_ = srv.Shutdown(ctx)
			cancel()
			_ = srv.Close()
			srv = nil
		}
		if ln != nil {
			_ = ln.Close()
			ln = nil
		}
	}
	startFn = func() {
		stopFn()
		_ = startAt(fixedAddr)
	}
	return port, hits, stopFn, startFn
}

func freeTCPPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to allocate port: %v", err)
	}
	p := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return p
}

func findSingBoxBinary() string {
	candidates := []string{
		filepath.Join("..", "..", "..", "panel", "bin", "sing-box.exe"),
		filepath.Join("..", "..", "..", "panel", "bin", "sing-box"),
	}
	for _, c := range candidates {
		if fi, err := os.Stat(c); err == nil && !fi.IsDir() {
			abs, err := filepath.Abs(c)
			if err == nil {
				return abs
			}
			return c
		}
	}
	return ""
}

func TestSingBoxFailover_LiveBinary_PriorityAndFailback(t *testing.T) {
	sbBin := findSingBoxBinary()
	if sbBin == "" {
		t.Skip("panel/bin/sing-box binary not found; skipping live binary failover test")
	}

	// Target server returning HTTP 204
	targetSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer targetSrv.Close()
	probeURL := targetSrv.URL + "/generate_204"

	// Slow primary upstream (200ms) vs fast backup upstream (0ms)
	primaryPort, primaryHits, stopPrimary, restartPrimary := startSlowHTTPProxy(t, "primary", 200*time.Millisecond)
	defer stopPrimary()
	backupPort, backupHits, stopBackup, _ := startSlowHTTPProxy(t, "backup", 0)
	defer stopBackup()

	inboundPort := freeTCPPort(t)
	clashPort := freeTCPPort(t)
	clashAddr := fmt.Sprintf("127.0.0.1:%d", clashPort)

	cfg := map[string]any{
		"log": map[string]any{"level": "error"},
		"experimental": map[string]any{
			"clash_api": map[string]any{"external_controller": clashAddr},
		},
		"inbounds": []any{
			map[string]any{
				"type":        "http",
				"tag":         "http-in",
				"listen":      "127.0.0.1",
				"listen_port": inboundPort,
			},
		},
		"outbounds": []any{
			map[string]any{
				"type":                        "selector",
				"tag":                         "hy2-sim",
				"outbounds":                   []string{"hy2-sim-primary", "vless-backup"},
				"default":                     "hy2-sim-primary",
				"interrupt_exist_connections": false,
			},
			map[string]any{
				"type":        "http",
				"tag":         "hy2-sim-primary",
				"server":      "127.0.0.1",
				"server_port": primaryPort,
			},
			map[string]any{
				"type":        "http",
				"tag":         "vless-backup",
				"server":      "127.0.0.1",
				"server_port": backupPort,
			},
			map[string]any{"type": "direct", "tag": "direct"},
		},
		"route": map[string]any{"final": "hy2-sim"},
	}

	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "sb-failover.json")
	rawCfg, _ := json.MarshalIndent(cfg, "", "  ")
	if err := os.WriteFile(cfgPath, rawCfg, 0644); err != nil {
		t.Fatalf("write cfg failed: %v", err)
	}

	if out, err := exec.Command(sbBin, "check", "-c", cfgPath).CombinedOutput(); err != nil {
		t.Fatalf("sing-box check failed: %v\n%s", err, string(out))
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd := exec.CommandContext(ctx, sbBin, "run", "-c", cfgPath)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start sing-box failed: %v", err)
	}
	defer func() {
		cancel()
		_ = cmd.Wait()
	}()

	// Wait for Clash API ready
	deadline := time.Now().Add(6 * time.Second)
	ready := false
	for time.Now().Before(deadline) {
		resp, err := (&http.Client{Timeout: 300 * time.Millisecond}).Get("http://" + clashAddr + "/proxies")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				ready = true
				break
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !ready {
		t.Fatalf("sing-box clash API did not come up on %s", clashAddr)
	}

	fc := newSingBoxFailoverController()
	fc.minInterval = 10 * time.Millisecond
	fc.probeTimeout = 2 * time.Second
	fc.SetGroups([]SingBoxFailoverGroup{
		{
			Tag:           "hy2-sim",
			Primary:       "hy2-sim-primary",
			Outbounds:     []string{"hy2-sim-primary", "vless-backup"},
			ProbeURL:      probeURL,
			ProbeInterval: 1,
			Strategy:      "priority",
		},
	})

	getSelected := func() string {
		proxies, err := fc.fetchProxies("http://" + clashAddr)
		if err != nil {
			t.Fatalf("fetchProxies failed: %v", err)
		}
		return proxies["hy2-sim"].Now
	}

	httpRequestViaHTTPProxy := func(proxyAddr, targetURL string) (int, error) {
		parsedProxy, err := url.Parse(proxyAddr)
		if err != nil {
			return 0, err
		}
		client := &http.Client{
			Timeout: 3 * time.Second,
			Transport: &http.Transport{
				Proxy:             http.ProxyURL(parsedProxy),
				DisableKeepAlives: true,
			},
		}
		resp, err := client.Get(targetURL)
		if err != nil {
			return 0, err
		}
		defer resp.Body.Close()
		return resp.StatusCode, nil
	}

	// Phase 1: Initial check keeps slow primary active
	ts := time.Now()
	_ = fc.Step(clashAddr, ts)
	if got := getSelected(); got != "hy2-sim-primary" {
		t.Fatalf("phase 1: expected hy2-sim-primary, got %s", got)
	}
	if resp, err := httpRequestViaHTTPProxy(fmt.Sprintf("http://127.0.0.1:%d", inboundPort), probeURL); err != nil || resp != http.StatusNoContent {
		t.Fatalf("phase 1: proxy request through primary failed: status=%d err=%v", resp, err)
	}
	if primaryHits.Load() == 0 {
		t.Fatalf("phase 1: expected primary proxy to handle traffic")
	}

	// Phase 2: Kill slow primary -> 2 probes failover to fast backup
	stopPrimary()
	ts = ts.Add(2 * time.Second)
	_ = fc.Step(clashAddr, ts)
	if got := getSelected(); got != "hy2-sim-primary" {
		t.Fatalf("phase 2 debounce: expected still hy2-sim-primary after 1 fail, got %s", got)
	}

	ts = ts.Add(2 * time.Second)
	_ = fc.Step(clashAddr, ts)
	if got := getSelected(); got != "vless-backup" {
		t.Fatalf("phase 2 failover: expected vless-backup after 2 fails, got %s", got)
	}
	beforeBackupHits := backupHits.Load()
	if resp, err := httpRequestViaHTTPProxy(fmt.Sprintf("http://127.0.0.1:%d", inboundPort), probeURL); err != nil || resp != http.StatusNoContent {
		t.Fatalf("phase 2: proxy request through backup failed: status=%d err=%v", resp, err)
	}
	if backupHits.Load() <= beforeBackupHits {
		t.Fatalf("phase 2: expected backup proxy to handle traffic")
	}

	// Phase 3: Restore slow primary -> 2 probes failback to primary EVEN THOUGH backup is 200ms faster!
	restartPrimary()
	ts = ts.Add(2 * time.Second)
	_ = fc.Step(clashAddr, ts)
	if got := getSelected(); got != "vless-backup" {
		t.Fatalf("phase 3 debounce: expected still vless-backup after 1 recovery pass, got %s", got)
	}

	ts = ts.Add(2 * time.Second)
	_ = fc.Step(clashAddr, ts)
	if got := getSelected(); got != "hy2-sim-primary" {
		t.Fatalf("phase 3 failback: expected automatic return to hy2-sim-primary despite 200ms slower ping, got %s", got)
	}
	beforePrimaryHits := primaryHits.Load()
	if resp, err := httpRequestViaHTTPProxy(fmt.Sprintf("http://127.0.0.1:%d", inboundPort), probeURL); err != nil || resp != http.StatusNoContent {
		t.Fatalf("phase 3: proxy request after failback failed: status=%d err=%v", resp, err)
	}
	if primaryHits.Load() <= beforePrimaryHits {
		t.Fatalf("phase 3: expected traffic to return to primary proxy after failback")
	}
}

func TestController_ExplicitClashAddrBeatsStaleFile(t *testing.T) {
	tmp := t.TempDir()
	binDir := filepath.Join(tmp, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatalf("mkdir bin: %v", err)
	}
	staleCfg := `{"experimental":{"clash_api":{"external_controller":"127.0.0.1:9090"}}}`
	if err := os.WriteFile(filepath.Join(binDir, "singbox.json"), []byte(staleCfg), 0o600); err != nil {
		t.Fatalf("write stale singbox.json: %v", err)
	}

	origWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(tmp); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(origWD) })

	ctrl := &Controller{
		clashAPIAddr: "127.0.0.1:9090",
		logPaths:     make(map[string]string),
	}
	if got := ctrl.getActiveClashAddr(); got != "127.0.0.1:9090" {
		t.Fatalf("expected disk fallback 127.0.0.1:9090 before explicit configure, got %s", got)
	}

	ctrl.ConfigureSingBoxFailover("127.0.0.1:49999", nil)
	if got := ctrl.getActiveClashAddr(); got != "127.0.0.1:49999" {
		t.Fatalf("expected explicit ConfigureSingBoxFailover addr 127.0.0.1:49999 to beat stale bin/singbox.json, got %s", got)
	}
}
