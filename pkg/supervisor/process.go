package supervisor

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
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

// StartCore starts a proxy engine process
func (pm *ProcessManager) StartCore(coreName, binPath, configPath string) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	normName := normalizeCoreName(coreName)
	pm.binPaths[normName] = binPath
	pm.configPaths[normName] = configPath

	// Verify binary exists
	if _, err := os.Stat(binPath); os.IsNotExist(err) {
		return fmt.Errorf("binary not found: %s", binPath)
	}

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

	cmd := exec.Command(binPath, args...)
	cmd.Dir = filepath.Dir(binPath)
	stdoutPipe, errOut := cmd.StdoutPipe()
	stderrPipe, errErr := cmd.StderrPipe()
	setSysProcAttr(cmd)

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start %s: %w", normName, err)
	}

	pm.processes[normName] = cmd

	// Stream stdout & stderr lines directly into in-memory broadcaster
	if errOut == nil && stdoutPipe != nil {
		go StreamPipe(normName, stdoutPipe)
	}
	if errErr == nil && stderrPipe != nil {
		go StreamPipe(normName, stderrPipe)
	}

	// Track process completion in background
	go func(name string, proc *exec.Cmd) {
		_ = proc.Wait()
		pm.mu.Lock()
		if current, exists := pm.processes[name]; exists && current == proc {
			delete(pm.processes, name)
		}
		pm.mu.Unlock()
	}(normName, cmd)

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
	}

	// Also perform safety OS process cleanup
	binBase := getBinBaseName(normName)
	if runtime.GOOS == "windows" {
		_ = exec.Command("taskkill", "/F", "/IM", binBase+".exe").Run()
		_ = exec.Command("taskkill", "/F", "/IM", binBase+"-windows-*.exe").Run()
		_ = exec.Command("taskkill", "/F", "/IM", binBase+"*").Run()
	} else {
		_ = exec.Command("killall", "-9", binBase).Run()
		_ = exec.Command("pkill", "-9", "-f", binBase).Run()
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
	if _, err := os.Stat(binPath); os.IsNotExist(err) {
		return false, "", fmt.Errorf("binary not found: %s", binPath)
	}
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return false, "", fmt.Errorf("config not found: %s", configPath)
	}

	normName := normalizeCoreName(coreName)
	var args []string
	switch normName {
	case "xray":
		args = []string{"run", "-config", configPath, "-test"}
	case "sing-box", "singbox":
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

	cmd := exec.CommandContext(ctx, binPath, args...)
	cmd.Dir = filepath.Dir(binPath)
	out, err := cmd.CombinedOutput()
	outStr := string(out)

	if err != nil {
		return false, outStr, fmt.Errorf("validation failed: %s", outStr)
	}
	return true, outStr, nil
}

// DetectCoreVersion queries the binary for its version string
func (pm *ProcessManager) DetectCoreVersion(coreName, binPath string) string {
	if _, err := os.Stat(binPath); os.IsNotExist(err) {
		return "Not Installed"
	}

	normName := normalizeCoreName(coreName)
	var args []string
	switch normName {
	case "hysteria2":
		args = []string{"version"}
	case "sing-box":
		args = []string{"version"}
	default:
		args = []string{"version"}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, binPath, args...)
	out, err := cmd.CombinedOutput()
	if err != nil && len(out) == 0 {
		return "Unknown"
	}

	lines := strings.Split(string(out), "\n")
	for _, l := range lines {
		lTrim := strings.TrimSpace(l)
		if lTrim == "" {
			continue
		}
		if strings.HasPrefix(strings.ToLower(lTrim), "version:") {
			parts := strings.SplitN(lTrim, ":", 2)
			if len(parts) == 2 {
				val := strings.TrimSpace(parts[1])
				if !strings.HasPrefix(val, "v") && len(val) > 0 && val[0] >= '0' && val[0] <= '9' {
					val = "v" + val
				}
				return val
			}
		}

		parts := strings.Fields(lTrim)
		for _, p := range parts {
			clean := strings.Trim(p, "v,()[]{}:")
			if len(clean) > 0 && clean[0] >= '0' && clean[0] <= '9' && strings.Contains(clean, ".") {
				return "v" + clean
			}
		}
	}
	return "Unknown"
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
