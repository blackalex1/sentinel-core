package killswitch

import (
	"net"
	"sync"
)

// IPv6Blocker manages IPv6 leak containment when the proxy tunnel only handles IPv4.
type IPv6Blocker struct {
	mu        sync.RWMutex
	blockIPv6 bool
}

// NewIPv6Blocker initializes the IPv6 leak blocker.
func NewIPv6Blocker(blockIPv6 bool) *IPv6Blocker {
	return &IPv6Blocker{
		blockIPv6: blockIPv6,
	}
}

// AllowIPv6 evaluates whether IPv6 packets to the target IP should be allowed.
func (b *IPv6Blocker) AllowIPv6(ip net.IP) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if !b.blockIPv6 {
		return true
	}

	if ip == nil {
		return false
	}

	// Always permit IPv6 loopback (::1)
	if ip.IsLoopback() || ip.Equal(net.ParseIP("::1")) {
		return true
	}

	// Block all public or external IPv6
	return false
}

// SetBlockIPv6 updates the blocking policy.
func (b *IPv6Blocker) SetBlockIPv6(block bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.blockIPv6 = block
}
