package killswitch

import (
	"net"
	"sync"
	"time"
)

// State represents the current status of the KillSwitch.
type State string

const (
	StateDisabled   State = "DISABLED"
	StateActive     State = "ACTIVE"       // VPN active, monitoring
	StateBlocking   State = "BLOCKING"     // VPN down, blocking all non-VPN/non-LAN traffic
	StateLANOnly    State = "LAN_ONLY"     // Only private LAN allowed
)

// PolicyDecision represents the verdict on whether a network packet/flow is permitted.
type PolicyDecision int

const (
	DecisionAllow PolicyDecision = iota
	DecisionDrop
	DecisionRedirectToTUN
)

// KillSwitch enforces fail-safe network isolation to prevent IP and traffic leaks.
type KillSwitch struct {
	mu             sync.RWMutex
	state          State
	enabled        bool
	blockIPv6      bool
	allowLocalLAN  bool
	strictDNS      bool
	allowedSubnets []*net.IPNet
	vpnActive      bool
	lastStateChange time.Time
	dnsLeakGuard   *DNSLeakGuard
	ipv6Blocker    *IPv6Blocker
	stateListeners []func(oldState, newState State)
}

// New creates a new KillSwitch instance with the given parameters.
func New(enabled, blockIPv6, allowLocalLAN, strictDNS bool, allowedCIDRs []string) *KillSwitch {
	subnets := make([]*net.IPNet, 0)
	for _, cidr := range allowedCIDRs {
		if _, ipnet, err := net.ParseCIDR(cidr); err == nil {
			subnets = append(subnets, ipnet)
		}
	}

	// Default fallback RFC1918 subnets if none provided
	if len(subnets) == 0 && allowLocalLAN {
		defaultCIDRs := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"}
		for _, cidr := range defaultCIDRs {
			if _, ipnet, err := net.ParseCIDR(cidr); err == nil {
				subnets = append(subnets, ipnet)
			}
		}
	}

	initialState := StateDisabled
	if enabled {
		initialState = StateBlocking // Safe by default: block until tunnel reports active
	}

	ks := &KillSwitch{
		state:           initialState,
		enabled:         enabled,
		blockIPv6:       blockIPv6,
		allowLocalLAN:   allowLocalLAN,
		strictDNS:       strictDNS,
		allowedSubnets:  subnets,
		vpnActive:       false,
		lastStateChange: time.Now(),
		dnsLeakGuard:    NewDNSLeakGuard(strictDNS),
		ipv6Blocker:     NewIPv6Blocker(blockIPv6),
		stateListeners:  make([]func(oldState, newState State), 0),
	}

	return ks
}

// OnStateChange registers a callback triggered when the KillSwitch transitions states.
func (ks *KillSwitch) OnStateChange(callback func(oldState, newState State)) {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	ks.stateListeners = append(ks.stateListeners, callback)
}

// SetVPNActive updates the tunnel connectivity state.
func (ks *KillSwitch) SetVPNActive(active bool) {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	ks.vpnActive = active
	oldState := ks.state

	if !ks.enabled {
		ks.state = StateDisabled
	} else if active {
		ks.state = StateActive
	} else {
		ks.state = StateBlocking
	}

	if oldState != ks.state {
		ks.lastStateChange = time.Now()
		for _, cb := range ks.stateListeners {
			cb(oldState, ks.state)
		}
	}
}

// GetState returns the current KillSwitch state.
func (ks *KillSwitch) GetState() State {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	return ks.state
}

// IsVPNActive returns true if the VPN tunnel is currently active.
func (ks *KillSwitch) IsVPNActive() bool {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	return ks.vpnActive
}

// EvaluatePacket determines if an outbound connection to dstIP:dstPort should be permitted.
func (ks *KillSwitch) EvaluatePacket(dstIP net.IP, dstPort int, isIPv6 bool, isDNS bool) PolicyDecision {
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	if !ks.enabled {
		return DecisionAllow
	}

	// 1. IPv6 leak protection check
	if isIPv6 && ks.blockIPv6 {
		if !ks.ipv6Blocker.AllowIPv6(dstIP) {
			return DecisionDrop
		}
	}

	// 2. DNS leak protection check
	if isDNS || dstPort == 53 {
		if !ks.dnsLeakGuard.AllowDNSQuery(dstIP, dstPort, ks.vpnActive) {
			return DecisionDrop
		}
	}

	// 3. If VPN tunnel is fully active, allow tunneled traffic
	if ks.vpnActive {
		return DecisionAllow
	}

	// 4. VPN is down and KillSwitch is ENABLED: check if destination is within allowed local LAN
	if ks.allowLocalLAN && dstIP != nil {
		for _, subnet := range ks.allowedSubnets {
			if subnet.Contains(dstIP) {
				return DecisionAllow
			}
		}
	}

	// Default drop when VPN is down to avoid data leakage
	return DecisionDrop
}

// IsLANIP checks if an IP belongs to one of the configured local LAN subnets.
func (ks *KillSwitch) IsLANIP(ip net.IP) bool {
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	if ip == nil {
		return false
	}
	for _, subnet := range ks.allowedSubnets {
		if subnet.Contains(ip) {
			return true
		}
	}
	return false
}
