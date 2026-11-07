package supervisor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/blackalex1/sentinel-core/pkg/compiler/singbox"
	"github.com/blackalex1/sentinel-core/pkg/i18n"
)

// ProcessManager manages child processes of proxy engines
type ProcessManager struct {
	mu          sync.Mutex
	processes   map[string]*exec.Cmd
	binPaths    map[string]string
	configPaths map[string]string
}

var defaultPM = &ProcessManager{
	processes:   make(map[string]*exec.Cmd),
	binPaths:    make(map[string]string),
	configPaths: make(map[string]string),
}

// GetProcessManager returns the global ProcessManager instance
func GetProcessManager() *ProcessManager {
	return defaultPM
}

// GetBinaryPath returns the registered executable path for a core
func (pm *ProcessManager) GetBinaryPath(coreName string) string {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	return pm.binPaths[normalizeCoreName(coreName)]
}

// GetConfigPath returns the registered config path for a core
func (pm *ProcessManager) GetConfigPath(coreName string) string {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	return pm.configPaths[normalizeCoreName(coreName)]
}

var allowedSupervisorBinaries = map[string]bool{
	"sing-box": true, "sing-box.exe": true,
	"singbox": true, "singbox.exe": true,
	"xray": true, "xray.exe": true,
	"hysteria": true, "hysteria.exe": true,
	"hysteria2": true, "hysteria2.exe": true,
}

func isAllowedCoreBinary(binPath string) bool {
	base := strings.ToLower(filepath.Base(binPath))
	base = strings.TrimSuffix(base, ".exe")
	if allowedSupervisorBinaries[base] || allowedSupervisorBinaries[base+".exe"] {
		return true
	}
	if strings.HasPrefix(base, "hysteria") || strings.HasPrefix(base, "sing-box") || strings.HasPrefix(base, "singbox") || strings.HasPrefix(base, "xray") {
		return true
	}
	return false
}

var ignoredSupervisorExtensions = map[string]bool{
	".go": true, ".json": true, ".log": true, ".txt": true,
	".md": true, ".tmp": true, ".dat": true, ".srs": true,
	".crt": true, ".key": true, ".gz": true, ".zip": true,
	".tar": true, ".db": true, ".sqlite": true,
}

func isValidCoreCandidate(fileName, normName string) bool {
	ext := strings.ToLower(filepath.Ext(fileName))
	if ignoredSupervisorExtensions[ext] {
		return false
	}
	name := strings.ToLower(fileName)
	base := strings.TrimSuffix(name, ".exe")

	switch normName {
	case "hysteria2":
		return base == "hysteria" || base == "hysteria2" || strings.HasPrefix(base, "hysteria-") || strings.HasPrefix(base, "hysteria2-")
	case "sing-box":
		return base == "sing-box" || base == "singbox" || strings.HasPrefix(base, "sing-box-") || strings.HasPrefix(base, "singbox-")
	case "xray":
		return base == "xray" || base == "xray-core" || strings.HasPrefix(base, "xray-")
	default:
		return base == normName || strings.HasPrefix(base, normName+"-")
	}
}

func ensureExecutablePermissions(filePath string) {
	if runtime.GOOS == "windows" {
		return
	}
	if fi, err := os.Stat(filePath); err == nil {
		if fi.Mode()&0111 == 0 {
			_ = os.Chmod(filePath, fi.Mode()|0755)
		}
	}
}

// resolveCoreBinaryPath finds the actual executable path for a core, checking aliases in the directory if binPath does not exist.
func resolveCoreBinaryPath(coreName, binPath string) (string, error) {
	if binPath == "" {
		return "", os.ErrNotExist
	}
	cleanBin := filepath.Clean(binPath)
	if fi, err := os.Stat(cleanBin); err == nil && !fi.IsDir() {
		ensureExecutablePermissions(cleanBin)
		return cleanBin, nil
	}

	normName := normalizeCoreName(coreName)
	base := filepath.Base(cleanBin)

	// Only search aliases or PATH if the specified binary name is a known alias/pattern of this core
	if !isValidCoreCandidate(base, normName) {
		return "", os.ErrNotExist
	}

	dir := filepath.Dir(cleanBin)
	hasDir := base != cleanBin && dir != "."

	if hasDir {
		if entries, err := os.ReadDir(dir); err == nil {
			for _, e := range entries {
				if e.IsDir() {
					continue
				}
				if isValidCoreCandidate(e.Name(), normName) {
					cand := filepath.Join(dir, e.Name())
					ensureExecutablePermissions(cand)
					return cand, nil
				}
			}
		}
	}

	// PATH lookup fallback
	var pathCandidates []string
	switch normName {
	case "hysteria2":
		pathCandidates = []string{"hysteria2", "hysteria"}
	case "sing-box":
		pathCandidates = []string{"sing-box", "singbox"}
	case "xray":
		pathCandidates = []string{"xray"}
	default:
		pathCandidates = []string{normName}
	}

	for _, cand := range pathCandidates {
		if lp, err := exec.LookPath(cand); err == nil {
			ensureExecutablePermissions(lp)
			return lp, nil
		}
	}

	return "", os.ErrNotExist
}

// StartCore starts a proxy engine process
func (pm *ProcessManager) StartCore(coreName, binPath, configPath string) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	normName := normalizeCoreName(coreName)

	resolvedBin, err := resolveCoreBinaryPath(coreName, binPath)
	if err != nil {
		return fmt.Errorf("binary not found: %s", binPath)
	}
	binPath = resolvedBin

	pm.binPaths[normName] = binPath
	pm.configPaths[normName] = configPath

	// Verify config exists
	if configPath != "" {
		if _, err := os.Stat(configPath); os.IsNotExist(err) {
			return fmt.Errorf("config file not found: %s", configPath)
		}
	}

	// Stop existing process if running
	if cmd, exists := pm.processes[normName]; exists && cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Kill()
		delete(pm.processes, normName)
	}

	var args []string
	switch normName {
	case "xray":
		args = []string{"run", "-config", configPath}
	case "sing-box", "singbox":
		args = []string{"run", "-c", configPath}
	case "hysteria", "hysteria2":
		args = []string{"server", "-c", configPath}
	default:
		args = []string{"-c", configPath}
	}

	binDir := filepath.Dir(binPath)
	if normName == "sing-box" {
		ensureSingboxRuleStubs(configPath, binDir)
		go prefetchRuleSets(configPath, binDir)
	}

	cleanBin := filepath.Clean(binPath)
	if strings.ContainsAny(cleanBin, "\x00\r\n`|;&$") || !isAllowedCoreBinary(cleanBin) {
		return fmt.Errorf("invalid or unauthorized binary path: %q", binPath)
	}

	// nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command
	cmd := exec.Command(cleanBin, args...)
	cmd.Dir = binDir
	cmd.Env = append(os.Environ(),
		"XRAY_LOCATION_ASSET="+binDir,
		"V2RAY_LOCATION_ASSET="+binDir,
	)
	stdoutPipe, errOut := cmd.StdoutPipe()
	stderrPipe, errErr := cmd.StderrPipe()
	setSysProcAttr(cmd)

	if err := cmd.Start(); err != nil {
		log.Printf("[sentinel-core] %s", i18n.TGlobal("LOG_SUPERVISOR_FAILED_START", normName, err))
		return fmt.Errorf("failed to start %s: %w", normName, err)
	}

	pm.processes[normName] = cmd
	log.Printf("[sentinel-core] %s", i18n.TGlobal("LOG_SUPERVISOR_STARTED", normName, cmd.Process.Pid, binPath))

	// Auto-register telemetry endpoints and tail log files from config
	stopCh := make(chan struct{})
	var logFileToTail string

	if configPath != "" {
		if data, err := os.ReadFile(configPath); err == nil {
			if normName == "hysteria2" {
				var hCfg struct {
					TrafficStats struct {
						Listen string `json:"listen"`
					} `json:"trafficStats"`
				}
				if err := json.Unmarshal(data, &hCfg); err == nil && hCfg.TrafficStats.Listen != "" {
					parts := strings.Split(hCfg.TrafficStats.Listen, ":")
					if len(parts) >= 2 {
						var p int
						if n, _ := fmt.Sscanf(parts[len(parts)-1], "%d", &p); n == 1 && p > 0 {
							GetController().RegisterHysteriaPort(p)
						}
					}
				}
			} else if normName == "sing-box" {
				var sbCfg struct {
					Log struct {
						Output string `json:"output"`
					} `json:"log"`
					Experimental struct {
						ClashAPI struct {
							ExternalController string `json:"external_controller"`
						} `json:"clash_api"`
					} `json:"experimental"`
				}
				if err := json.Unmarshal(data, &sbCfg); err == nil {
					if sbCfg.Log.Output != "" {
						logFileToTail = sbCfg.Log.Output
					}
					if sbCfg.Experimental.ClashAPI.ExternalController != "" {
						GetController().Configure(sbCfg.Experimental.ClashAPI.ExternalController, nil, nil)
					}
				}
			} else if normName == "xray" {
				var xCfg struct {
					Log struct {
						Access string `json:"access"`
						Error  string `json:"error"`
					} `json:"log"`
				}
				if err := json.Unmarshal(data, &xCfg); err == nil {
					if xCfg.Log.Access != "" {
						logFileToTail = xCfg.Log.Access
					}
				}
			}
		}
	}

	if logFileToTail != "" {
		go TailFile(normName, logFileToTail, stopCh)
	}
	defaultLogPath := filepath.Join(filepath.Dir(binPath), normName+".log")
	if defaultLogPath != logFileToTail && defaultLogPath != "" {
		go TailFile(normName, defaultLogPath, stopCh)
	}

	// Stream stdout & stderr lines directly into in-memory broadcaster
	if errOut == nil && stdoutPipe != nil {
		go StreamPipe(normName, stdoutPipe)
	}
	if errErr == nil && stderrPipe != nil {
		go StreamPipe(normName, stderrPipe)
	}

	// Track process completion in background
	go func(name string, proc *exec.Cmd, stopTail chan struct{}) {
		err := proc.Wait()
		close(stopTail)
		pm.mu.Lock()
		if current, exists := pm.processes[name]; exists && current == proc {
			delete(pm.processes, name)
		}
		pm.mu.Unlock()
		log.Printf("[sentinel-core] %s", i18n.TGlobal("LOG_SUPERVISOR_FINISHED", name, err))
	}(normName, cmd, stopCh)

	return nil
}

// GetInMemoryLogs returns recent log lines from the in-memory ring buffer
func (pm *ProcessManager) GetInMemoryLogs(coreName string, maxLines int) []string {
	return defaultBroadcaster.GetHistory(coreName, maxLines)
}

// PopLogLine pops next log line from in-memory queue
func (pm *ProcessManager) PopLogLine(coreName string, timeout time.Duration) string {
	return defaultBroadcaster.PopLine(coreName, timeout)
}

// ClearInMemoryLogs clears in-memory buffer
func (pm *ProcessManager) ClearInMemoryLogs(coreName string) {
	defaultBroadcaster.Clear(coreName)
}

// StopCore terminates a running proxy engine process
func (pm *ProcessManager) StopCore(coreName string) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	normName := normalizeCoreName(coreName)

	if cmd, exists := pm.processes[normName]; exists && cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Kill()
		delete(pm.processes, normName)
		log.Printf("[sentinel-core] %s", i18n.TGlobal("LOG_SUPERVISOR_STOPPED", normName, cmd.Process.Pid))
	}

	// Also perform safety OS process cleanup ONLY for recognized cores
	allowedCores := map[string]bool{
		"sing-box":  true,
		"xray":      true,
		"hysteria2": true,
	}
	if allowedCores[normName] {
		binBase := getBinBaseName(normName)
		if runtime.GOOS == "windows" {
			_ = exec.Command("taskkill", "/F", "/IM", binBase+".exe").Run()
			_ = exec.Command("taskkill", "/F", "/IM", binBase+"-windows-*.exe").Run()
		} else {
			_ = exec.Command("killall", "-9", binBase).Run()
			_ = exec.Command("pkill", "-9", "-x", binBase).Run()
		}
	}
	if normName == "hysteria2" {
		ResetHysteriaCumulativeTraffic()
	}
	time.Sleep(100 * time.Millisecond)

	return nil
}

// RestartCore stops and starts a proxy engine
func (pm *ProcessManager) RestartCore(coreName, binPath, configPath string) error {
	_ = pm.StopCore(coreName)
	time.Sleep(200 * time.Millisecond)
	return pm.StartCore(coreName, binPath, configPath)
}

// ReloadCore reloads or gracefully restarts a running core using its stored binary and config paths.
func (pm *ProcessManager) ReloadCore(coreName string) error {
	pm.mu.Lock()
	normName := normalizeCoreName(coreName)
	bin := pm.binPaths[normName]
	cfg := pm.configPaths[normName]
	pm.mu.Unlock()

	if bin == "" || cfg == "" {
		return fmt.Errorf("core %s paths not registered for reload", coreName)
	}

	return pm.RestartCore(coreName, bin, cfg)
}

// ReloadAllRunningCores reloads all currently registered and running proxy engines.
func (pm *ProcessManager) ReloadAllRunningCores() map[string]error {
	results := make(map[string]error)
	for _, name := range []string{"xray", "sing-box", "hysteria2"} {
		if pm.IsRunning(name) {
			results[name] = pm.ReloadCore(name)
		}
	}
	return results
}

// IsRunning checks if a core process is actively running
func (pm *ProcessManager) IsRunning(coreName string) bool {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	normName := normalizeCoreName(coreName)
	if cmd, exists := pm.processes[normName]; exists && cmd != nil && cmd.Process != nil {
		if cmd.ProcessState == nil || !cmd.ProcessState.Exited() {
			return true
		}
	}

	binBase := getBinBaseName(normName)
	if runtime.GOOS == "windows" {
		out, err := exec.Command("tasklist").Output()
		if err == nil {
			outStr := strings.ToLower(string(out))
			baseLower := strings.ToLower(binBase)
			lines := strings.Split(outStr, "\n")
			for _, line := range lines {
				f := strings.Fields(line)
				if len(f) > 0 && strings.Contains(f[0], baseLower) && strings.HasSuffix(f[0], ".exe") {
					return true
				}
			}
		}
	} else {
		err := exec.Command("pgrep", "-f", binBase).Run()
		if err == nil {
			return true
		}
	}

	return false
}

// ValidateCoreConfig checks configuration syntax using core engine test flags
func (pm *ProcessManager) ValidateCoreConfig(coreName, binPath, configPath string) (bool, string, error) {
	resolvedBin, err := resolveCoreBinaryPath(coreName, binPath)
	if err != nil {
		return false, "", fmt.Errorf("binary not found: %s", binPath)
	}
	binPath = resolvedBin

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return false, "", fmt.Errorf("config not found: %s", configPath)
	}

	normName := normalizeCoreName(coreName)
	binDir := filepath.Dir(binPath)
	var args []string
	switch normName {
	case "xray":
		args = []string{"run", "-config", configPath, "-test"}
	case "sing-box", "singbox":
		ensureSingboxRuleStubs(configPath, binDir)
		args = []string{"check", "-c", configPath}
	default:
		// For hysteria or others, read and validate JSON
		data, err := os.ReadFile(configPath)
		if err != nil {
			return false, "", err
		}
		if len(bytes.TrimSpace(data)) == 0 {
			return false, "empty config", nil
		}
		return true, "OK", nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cleanBin := filepath.Clean(binPath)
	if strings.ContainsAny(cleanBin, "\x00\r\n`|;&$") || !isAllowedCoreBinary(cleanBin) {
		return false, "", fmt.Errorf("invalid or unauthorized binary path: %q", binPath)
	}

	// nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command
	cmd := exec.CommandContext(ctx, cleanBin, args...)
	cmd.Dir = binDir
	cmd.Env = append(os.Environ(),
		"XRAY_LOCATION_ASSET="+binDir,
		"V2RAY_LOCATION_ASSET="+binDir,
	)
	out, err := cmd.CombinedOutput()
	outStr := string(out)

	if err != nil {
		return false, outStr, fmt.Errorf("validation failed: %s", outStr)
	}
	return true, outStr, nil
}

var (
	versionColonRegex     = regexp.MustCompile(`(?i)version[:\s]+v?([0-9]+(?:\.[0-9]+)+(?:-[a-zA-Z0-9.]+)?|app\/[0-9]+(?:\.[0-9]+)+)`)
	coreNamedVersionRegex = regexp.MustCompile(`(?i)(?:hysteria|sing-box|singbox|xray)(?:[\s/]+version)?[\s/]+v?([0-9]+(?:\.[0-9]+)+(?:-[a-zA-Z0-9.]+)?|app\/[0-9]+(?:\.[0-9]+)+)`)
	generalSemverRegex    = regexp.MustCompile(`v?([0-9]+(?:\.[0-9]+)+(?:-[a-zA-Z0-9.]+)?)\b`)
)

func parseCoreVersionOutput(raw string) string {
	lines := strings.Split(raw, "\n")
	for _, l := range lines {
		lTrim := strings.TrimSpace(l)
		if lTrim == "" {
			continue
		}
		if m := versionColonRegex.FindStringSubmatch(lTrim); len(m) > 1 {
			v := strings.TrimPrefix(m[1], "app/")
			if !strings.HasPrefix(v, "v") {
				return "v" + v
			}
			return v
		}
		if m := coreNamedVersionRegex.FindStringSubmatch(lTrim); len(m) > 1 {
			v := strings.TrimPrefix(m[1], "app/")
			if !strings.HasPrefix(v, "v") {
				return "v" + v
			}
			return v
		}
	}

	for _, l := range lines {
		lTrim := strings.TrimSpace(l)
		if lTrim == "" || strings.HasPrefix(lTrim, "░") || strings.Contains(lTrim, "http") || strings.Contains(lTrim, "quic-go") {
			continue
		}
		if m := generalSemverRegex.FindStringSubmatch(lTrim); len(m) > 1 {
			v := m[1]
			if !strings.HasPrefix(v, "v") {
				return "v" + v
			}
			return v
		}
	}

	return "Unknown"
}

// DetectCoreVersion queries the binary for its version string
func (pm *ProcessManager) DetectCoreVersion(coreName, binPath string) string {
	resolvedBin, err := resolveCoreBinaryPath(coreName, binPath)
	if err != nil {
		return "Not Installed"
	}

	normName := normalizeCoreName(coreName)
	cleanBin := filepath.Clean(resolvedBin)
	if strings.ContainsAny(cleanBin, "\x00\r\n`|;&$") || !isAllowedCoreBinary(cleanBin) {
		return "Unknown"
	}

	var argsList [][]string
	switch normName {
	case "xray":
		argsList = [][]string{{"version"}, {"-version"}}
	default:
		argsList = [][]string{{"version"}}
	}

	binDir := filepath.Dir(cleanBin)
	var output []byte
	for _, args := range argsList {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		cmd := exec.CommandContext(ctx, cleanBin, args...)
		cmd.Dir = binDir
		cmd.Env = append(os.Environ(),
			"XRAY_LOCATION_ASSET="+binDir,
			"V2RAY_LOCATION_ASSET="+binDir,
		)
		out, runErr := cmd.CombinedOutput()
		cancel()
		if runErr == nil && len(out) > 0 {
			output = out
			break
		}
		if len(out) > 0 && output == nil {
			output = out
		}
	}

	if len(output) == 0 {
		return "Unknown"
	}

	return parseCoreVersionOutput(string(output))
}

func normalizeCoreName(name string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	switch n {
	case "singbox", "sing-box":
		return "sing-box"
	case "hysteria", "hysteria2":
		return "hysteria2"
	case "xray", "xray-core":
		return "xray"
	default:
		return n
	}
}

func getBinBaseName(normName string) string {
	switch normName {
	case "sing-box":
		return "sing-box"
	case "hysteria2":
		return "hysteria"
	case "xray":
		return "xray"
	default:
		return normName
	}
}

// Minimal valid 17-byte compiled sing-box binary rule-set (.srs)
// Magic bytes: SRS\x01 + zlib-compressed empty rule list.
var emptySrsStub = []byte{0x53, 0x52, 0x53, 0x01, 0x78, 0xda, 0x62, 0x00, 0x04, 0x00, 0x00, 0xff, 0xff, 0x00, 0x01, 0x00, 0x01}

// safeRulePath sanitizes and restricts rule-set target filepaths strictly to binDir.
// Prevents path traversal vulnerabilities (CWE-22) like writing to /etc or system folders.
func safeRulePath(initialPath, binDir string) (string, bool) {
	if initialPath == "" {
		return "", false
	}
	clean := filepath.Clean(initialPath)
	var target string
	if filepath.IsAbs(clean) {
		rel, err := filepath.Rel(binDir, clean)
		if err != nil || strings.HasPrefix(rel, "..") {
			target = filepath.Join(binDir, filepath.Base(clean))
		} else {
			target = clean
		}
	} else {
		target = filepath.Join(binDir, clean)
		rel, err := filepath.Rel(binDir, target)
		if err != nil || strings.HasPrefix(rel, "..") {
			target = filepath.Join(binDir, filepath.Base(clean))
		}
	}

	ext := strings.ToLower(filepath.Ext(target))
	if ext != ".srs" && ext != ".json" && ext != ".db" {
		return "", false
	}
	return target, true
}

// isSafePrefetchURL ensures candidate URLs do not target cloud metadata endpoints or private LAN/loopback (SSRF protection).
func isSafePrefetchURL(rawURL string) bool {
	parsed, err := url.Parse(rawURL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return false
	}
	host := parsed.Hostname()
	if host == "" {
		return false
	}
	lowerHost := strings.ToLower(host)
	if lowerHost == "metadata.google.internal" || lowerHost == "metadata.goog" || lowerHost == "instance-data" || lowerHost == "localhost" {
		return false
	}
	ip := net.ParseIP(host)
	if ip != nil {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			return false
		}
		if v4 := ip.To4(); v4 != nil {
			if v4[0] == 100 && (v4[1]&0xC0) == 64 {
				return false
			}
			if v4[0] == 169 && v4[1] == 254 {
				return false
			}
		}
	}
	return true
}

// ensureSingboxRuleStubs ensures that all local rule-set files referenced by initial_path
// exist on disk before sing-box starts or validates config.
// On clean/empty servers where remote rule-sets are not yet downloaded,
// this allows sing-box to start immediately (in ~0.04s) and avoid FATAL startup timeouts
// while updating rules asynchronously in the background.
func ensureSingboxRuleStubs(configPath, binDir string) {
	if configPath == "" {
		return
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		return
	}
	var parsed struct {
		Route struct {
			RuleSet []struct {
				InitialPath string `json:"initial_path"`
			} `json:"rule_set"`
		} `json:"route"`
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		return
	}
	for _, rs := range parsed.Route.RuleSet {
		targetPath, ok := safeRulePath(rs.InitialPath, binDir)
		if !ok || targetPath == "" {
			continue
		}
		if _, err := os.Stat(targetPath); os.IsNotExist(err) {
			_ = os.MkdirAll(filepath.Dir(targetPath), 0755)
			_ = os.WriteFile(targetPath, emptySrsStub, 0644)
			log.Printf("[sentinel-core] %s", i18n.TGlobal("LOG_RULES_STUB_CREATED", filepath.Base(targetPath)))
		}
	}
}

// prefetchRuleSets asynchronously downloads full binary .srs files in the background
// to replace the 17-byte stubs on disk with real rules once network connectivity is available.
// It implements a two-phase fallback:
// Phase 1: Probes and downloads via direct CDN mirrors.
// Phase 2: If direct downloads fail, verifies outbounds via Sing-box Clash API and waits for tunnel rules download.
func prefetchRuleSets(configPath, binDir string) {
	if configPath == "" {
		return
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		return
	}
	var parsed struct {
		Route struct {
			RuleSet []struct {
				InitialPath string `json:"initial_path"`
				URL         string `json:"url"`
			} `json:"rule_set"`
		} `json:"route"`
		Outbounds []struct {
			Tag  string `json:"tag"`
			Type string `json:"type"`
		} `json:"outbounds"`
		Experimental struct {
			ClashAPI struct {
				ExternalController string `json:"external_controller"`
			} `json:"clash_api"`
		} `json:"experimental"`
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		return
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	activeMirror := singbox.GetActiveRuleMirror()
	hasMissingRules := false

	for _, rs := range parsed.Route.RuleSet {
		targetPath, ok := safeRulePath(rs.InitialPath, binDir)
		if !ok || targetPath == "" {
			continue
		}

		// Only download if it's currently a stub (<= 17 bytes) or missing
		st, err := os.Stat(targetPath)
		if err == nil && st.Size() > int64(len(emptySrsStub)) {
			continue // Already a full rule-set
		}

		baseFileName := filepath.Base(targetPath)
		ruleTag := strings.TrimSuffix(baseFileName, ".srs")
		isGeoIP := strings.HasPrefix(ruleTag, "geoip-")

		// Phase 1: Build candidate URLs (active mirror, configured URL, then other mirrors)
		var urlsToTry []string
		if rs.URL != "" && isSafePrefetchURL(rs.URL) {
			urlsToTry = append(urlsToTry, rs.URL)
		}
		if isGeoIP {
			urlsToTry = append(urlsToTry, fmt.Sprintf(activeMirror.GeoipPattern, ruleTag))
		} else {
			urlsToTry = append(urlsToTry, fmt.Sprintf(activeMirror.GeositePattern, ruleTag))
		}
		for _, m := range singbox.DefaultMirrors {
			var candidate string
			if isGeoIP {
				candidate = fmt.Sprintf(m.GeoipPattern, ruleTag)
			} else {
				candidate = fmt.Sprintf(m.GeositePattern, ruleTag)
			}
			urlsToTry = append(urlsToTry, candidate)
		}

		var downloadedContent []byte
		for _, u := range urlsToTry {
			if !isSafePrefetchURL(u) {
				continue
			}
			resp, err := client.Get(u)
			if err != nil || resp.StatusCode != http.StatusOK {
				if resp != nil && resp.Body != nil {
					_ = resp.Body.Close()
				}
				continue
			}
			content, err := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if err == nil && len(content) > len(emptySrsStub) && len(content) > 4 && string(content[:3]) == "SRS" {
				downloadedContent = content
				break
			}
		}

		if len(downloadedContent) > 0 {
			_ = os.WriteFile(targetPath, downloadedContent, 0644)
			log.Printf("[sentinel-core] %s", i18n.TGlobal("LOG_RULES_DOWNLOADED_SUCCESS", ruleTag, len(downloadedContent)))
		} else {
			hasMissingRules = true
			log.Printf("[sentinel-core] %s", i18n.TGlobal("LOG_RULES_USING_SAFE_STUB", ruleTag))
		}
	}

	// Phase 2: If direct downloads across all mirrors failed, probe available outbounds via Clash API
	if hasMissingRules && parsed.Experimental.ClashAPI.ExternalController != "" {
		log.Printf("[sentinel-core] %s", i18n.TGlobal("LOG_RULES_DIRECT_MIRRORS_BLOCKED"))
		var proxyTags []string
		for _, ob := range parsed.Outbounds {
			if ob.Tag != "" && ob.Tag != "direct" && ob.Tag != "block" && ob.Type != "direct" && ob.Type != "block" {
				proxyTags = append(proxyTags, ob.Tag)
			}
		}
		if len(proxyTags) > 0 {
			log.Printf("[sentinel-core] %s", i18n.TGlobal("LOG_RULES_PROBING_OUTBOUNDS", len(proxyTags)))
			// Give Sing-box 1-2 seconds to establish upstream connections
			time.Sleep(2 * time.Second)
			workingOutbound := singbox.ProbeOutboundsViaClashAPI(
				parsed.Experimental.ClashAPI.ExternalController,
				proxyTags,
				activeMirror.ProbeURL,
				3*time.Second,
			)
			if workingOutbound != "" {
				log.Printf("[sentinel-core] %s", i18n.TGlobal("LOG_RULES_OUTBOUND_VERIFIED", workingOutbound, activeMirror.Name))
			}
		}
	}
}
