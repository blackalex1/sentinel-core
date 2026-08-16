package guard

import (
	"os"
	"strings"
	"sync"
)

// ProcessWhitelist handles self-protection to prevent accidental termination or blocking of critical binaries.
type ProcessWhitelist struct {
	mu              sync.RWMutex
	protectedNames  map[string]bool
	protectedIPs    map[string]bool
	ownPID          int
}

// NewProcessWhitelist creates a new whitelist with standard critical processes.
func NewProcessWhitelist(customProcesses []string, customIPs []string) *ProcessWhitelist {
	names := map[string]bool{
		"sentinel-core":     true,
		"sentinel-core.exe": true,
		"sing-box":          true,
		"sing-box.exe":      true,
		"xray":              true,
		"xray.exe":          true,
		"hysteria":          true,
		"hysteria.exe":      true,
		"ansible":           true,
		"ansible-playbook":  true,
		"pveproxy":          true,
		"sshd":              true,
		"dockerd":           true,
	}

	for _, p := range customProcesses {
		clean := strings.ToLower(strings.TrimSpace(p))
		if clean != "" {
			names[clean] = true
		}
	}

	ips := map[string]bool{
		"127.0.0.1": true,
		"::1":       true,
		"localhost": true,
	}

	for _, ip := range customIPs {
		clean := strings.ToLower(strings.TrimSpace(ip))
		if clean != "" {
			ips[clean] = true
		}
	}

	return &ProcessWhitelist{
		protectedNames: names,
		protectedIPs:   ips,
		ownPID:         os.Getpid(),
	}
}

// IsProcessProtected checks if a process name or PID is protected by the whitelist.
func (w *ProcessWhitelist) IsProcessProtected(procName string, pid int) bool {
	w.mu.RLock()
	defer w.mu.RUnlock()

	// 1. Suicide prevention: never allow killing own PID
	if pid > 0 && pid == w.ownPID {
		return true
	}

	// 2. Check process name against protected dictionary
	clean := strings.ToLower(strings.TrimSpace(procName))
	if w.protectedNames[clean] {
		return true
	}

	// Substring checks for wrapped binaries (e.g. /usr/bin/sentinel-core)
	for protected := range w.protectedNames {
		if strings.Contains(clean, protected) {
			return true
		}
	}

	return false
}

// IsIPProtected checks if an IP is in the self-protection whitelist.
func (w *ProcessWhitelist) IsIPProtected(ipStr string) bool {
	w.mu.RLock()
	defer w.mu.RUnlock()

	clean := strings.ToLower(strings.TrimSpace(ipStr))
	return w.protectedIPs[clean]
}

// AddProcess adds a process name to the runtime whitelist.
func (w *ProcessWhitelist) AddProcess(procName string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	clean := strings.ToLower(strings.TrimSpace(procName))
	if clean != "" {
		w.protectedNames[clean] = true
	}
}

// AddIP adds an IP to the runtime whitelist.
func (w *ProcessWhitelist) AddIP(ipStr string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	clean := strings.ToLower(strings.TrimSpace(ipStr))
	if clean != "" {
		w.protectedIPs[clean] = true
	}
}
