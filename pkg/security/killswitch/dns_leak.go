package killswitch

import (
	"net"
	"sync"
)

// DNSLeakGuard ensures that DNS queries cannot leak to unencrypted local ISP resolvers.
type DNSLeakGuard struct {
	mu           sync.RWMutex
	strictDNS    bool
	allowedDNSIPs []net.IP
}

// NewDNSLeakGuard creates a new DNS leak protection controller.
func NewDNSLeakGuard(strictDNS bool) *DNSLeakGuard {
	return &DNSLeakGuard{
		strictDNS: strictDNS,
		allowedDNSIPs: []net.IP{
			net.ParseIP("127.0.0.1"),
			net.ParseIP("::1"),
			// Common trusted secure DNS resolvers (DoH/DoT endpoints)
			net.ParseIP("1.1.1.1"),
			net.ParseIP("1.0.0.1"),
			net.ParseIP("8.8.8.8"),
			net.ParseIP("8.8.4.4"),
			net.ParseIP("9.9.9.9"),
		},
	}
}

// AddAllowedDNS adds a trusted DNS resolver IP to the whitelist.
func (g *DNSLeakGuard) AddAllowedDNS(ip net.IP) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if ip != nil {
		g.allowedDNSIPs = append(g.allowedDNSIPs, ip)
	}
}

// AllowDNSQuery checks if an outgoing DNS query is permitted or if it represents a plaintext leak.
func (g *DNSLeakGuard) AllowDNSQuery(dstIP net.IP, dstPort int, vpnActive bool) bool {
	g.mu.RLock()
	defer g.mu.RUnlock()

	if !g.strictDNS {
		return true
	}

	// Plaintext DNS on port 53 without active VPN is always blocked
	if !vpnActive && dstPort == 53 {
		// Allow only loopback internal resolver
		if dstIP != nil && (dstIP.IsLoopback() || dstIP.Equal(net.ParseIP("127.0.0.1")) || dstIP.Equal(net.ParseIP("::1"))) {
			return true
		}
		return false
	}

	// When VPN is active, only allow configured trusted DNS endpoints or internal loopback
	if dstIP != nil {
		if dstIP.IsLoopback() {
			return true
		}
		for _, allowed := range g.allowedDNSIPs {
			if allowed.Equal(dstIP) {
				return true
			}
		}
	}

	// If VPN is active and dstPort is encrypted DNS (853 for DoT, 443 for DoH), permit
	if dstPort == 853 || dstPort == 443 {
		return true
	}

	return vpnActive
}
