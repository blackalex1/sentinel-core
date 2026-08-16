package guard

import (
	"sync"
)

// Guard acts as the centralized IPS & Connection Protection Controller.
type Guard struct {
	mu           sync.RWMutex
	enabled      bool
	whitelist    *ProcessWhitelist
	portMonitor  *SensitivePortMonitor
	rateLimiter  *RateLimiter
}

// New creates a new Guard instance coordinating whitelists, rate limiting, and port monitors.
func New(
	enabled bool,
	sensitivePorts []int,
	portAction string,
	scanThreshold int,
	scanWindowSec int,
	autoBanScanner bool,
	rps float64,
	burst int,
	banThreshold int,
	banDurationSec int,
	customProcesses []string,
	customIPs []string,
) *Guard {
	whitelist := NewProcessWhitelist(customProcesses, customIPs)
	portMonitor := NewSensitivePortMonitor(
		enabled,
		sensitivePorts,
		portAction,
		scanThreshold,
		scanWindowSec,
		autoBanScanner,
		whitelist,
	)
	rateLimiter := NewRateLimiter(
		enabled,
		rps,
		burst,
		banThreshold,
		banDurationSec,
		whitelist,
	)

	return &Guard{
		enabled:     enabled,
		whitelist:   whitelist,
		portMonitor: portMonitor,
		rateLimiter: rateLimiter,
	}
}

// Whitelist returns the process & IP whitelist.
func (g *Guard) Whitelist() *ProcessWhitelist {
	return g.whitelist
}

// PortMonitor returns the sensitive port monitoring engine.
func (g *Guard) PortMonitor() *SensitivePortMonitor {
	return g.portMonitor
}

// RateLimiter returns the rate limiter engine.
func (g *Guard) RateLimiter() *RateLimiter {
	return g.rateLimiter
}

// CheckInbound evaluates an incoming connection from remoteIP to targetPort.
func (g *Guard) CheckInbound(remoteIP string, targetPort int) (allowed bool, reason string) {
	if !g.enabled {
		return true, ""
	}

	// 1. Rate limiter check
	if !g.rateLimiter.Allow(remoteIP) {
		return false, "Rate limit exceeded or IP is temporarily banned"
	}

	// 2. Sensitive port check
	isBlocked, isScan, portReason := g.portMonitor.CheckPortAccess(remoteIP, targetPort)
	if isBlocked {
		return false, portReason
	}
	if isScan {
		return false, portReason
	}

	return true, ""
}

// Stop cleanly terminates internal workers.
func (g *Guard) Stop() {
	if g.rateLimiter != nil {
		g.rateLimiter.Stop()
	}
}
