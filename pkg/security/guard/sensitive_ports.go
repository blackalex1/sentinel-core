package guard

import (
	"fmt"
	"sync"
	"time"
)

// PortViolationRecord stores recent port access attempts per IP.
type PortViolationRecord struct {
	AttemptedPorts map[int]time.Time
	FirstAttempt   time.Time
}

// SensitivePortMonitor tracks connections to protected ports and detects port scans.
type SensitivePortMonitor struct {
	mu                sync.Mutex
	enabled           bool
	sensitivePorts    map[int]bool
	action            string // "alert", "block", "kill"
	scanThreshold     int
	scanWindow        time.Duration
	autoBanScanner    bool
	ipProbes          map[string]*PortViolationRecord
	bannedIPs         map[string]time.Time
	banDuration       time.Duration
	whitelist         *ProcessWhitelist
}

// NewSensitivePortMonitor initializes the sensitive port IPS monitor.
func NewSensitivePortMonitor(
	enabled bool,
	ports []int,
	action string,
	scanThreshold int,
	scanWindowSec int,
	autoBanScanner bool,
	whitelist *ProcessWhitelist,
) *SensitivePortMonitor {
	if scanThreshold <= 0 {
		scanThreshold = 5
	}
	if scanWindowSec <= 0 {
		scanWindowSec = 10
	}
	if action == "" {
		action = "block"
	}

	portMap := make(map[int]bool)
	for _, p := range ports {
		portMap[p] = true
	}

	return &SensitivePortMonitor{
		enabled:        enabled,
		sensitivePorts: portMap,
		action:         action,
		scanThreshold:  scanThreshold,
		scanWindow:     time.Duration(scanWindowSec) * time.Second,
		autoBanScanner: autoBanScanner,
		ipProbes:       make(map[string]*PortViolationRecord),
		bannedIPs:      make(map[string]time.Time),
		banDuration:    10 * time.Minute,
		whitelist:      whitelist,
	}
}

// CheckPortAccess evaluates a connection attempt to targetPort from sourceIP.
// Returns (isBlocked, isScanDetected, reason).
func (m *SensitivePortMonitor) CheckPortAccess(sourceIP string, targetPort int) (bool, bool, string) {
	if !m.enabled {
		return false, false, ""
	}

	if m.whitelist != nil && m.whitelist.IsIPProtected(sourceIP) {
		return false, false, ""
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()

	// 1. Check if IP is currently banned
	if bannedUntil, isBanned := m.bannedIPs[sourceIP]; isBanned {
		if now.Before(bannedUntil) {
			return true, false, fmt.Sprintf("IP %s is banned until %s due to port security violation", sourceIP, bannedUntil.Format(time.RFC3339))
		}
		// Ban expired
		delete(m.bannedIPs, sourceIP)
	}

	// 2. Check if the destination port is sensitive
	if !m.sensitivePorts[targetPort] {
		return false, false, ""
	}

	// 3. Record probe for scan detection
	record, exists := m.ipProbes[sourceIP]
	if !exists || now.Sub(record.FirstAttempt) > m.scanWindow {
		record = &PortViolationRecord{
			AttemptedPorts: make(map[int]time.Time),
			FirstAttempt:   now,
		}
		m.ipProbes[sourceIP] = record
	}
	record.AttemptedPorts[targetPort] = now

	isScan := len(record.AttemptedPorts) >= m.scanThreshold
	if isScan && m.autoBanScanner {
		m.bannedIPs[sourceIP] = now.Add(m.banDuration)
	}

	reason := fmt.Sprintf("Access to sensitive port %d from %s", targetPort, sourceIP)
	if isScan {
		reason = fmt.Sprintf("Port scan detected from %s across %d sensitive ports", sourceIP, len(record.AttemptedPorts))
	}

	isBlocked := (m.action == "block" || m.action == "kill" || isScan)
	return isBlocked, isScan, reason
}

// IsSensitivePort returns true if the port is in the sensitive list.
func (m *SensitivePortMonitor) IsSensitivePort(port int) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sensitivePorts[port]
}

// AddSensitivePort dynamically adds a port to monitor.
func (m *SensitivePortMonitor) AddSensitivePort(port int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sensitivePorts[port] = true
}

// Unban removes an IP from the ban list.
func (m *SensitivePortMonitor) Unban(sourceIP string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.bannedIPs, sourceIP)
	delete(m.ipProbes, sourceIP)
}
