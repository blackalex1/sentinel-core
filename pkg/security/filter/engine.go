package filter

import (
	"net"
	"strings"
	"sync"
)

// MatchResult details the verdict of domain/IP filtering.
type MatchResult struct {
	Blocked  bool
	Category ThreatCategory
	Reason   string
}

// ThreatEngine matches destination hosts/domains and IPs against security blocklists.
type ThreatEngine struct {
	mu            sync.RWMutex
	enabled       bool
	bloomFilter   *BloomFilter
	exactDomains  map[string]ThreatCategory
	suffixDomains map[string]ThreatCategory
	blockedIPNets []*net.IPNet
	allowedDomains map[string]bool
	allowedIPs    map[string]bool
}

// NewThreatEngine creates a new ThreatEngine with the given category policies.
func NewThreatEngine(
	enabled bool,
	blockMalware bool,
	blockPhishing bool,
	blockMiners bool,
	blockAds bool,
	customBlockedDomains []string,
	customAllowedDomains []string,
	customBlockedIPs []string,
) *ThreatEngine {
	engine := &ThreatEngine{
		enabled:        enabled,
		bloomFilter:    NewBloomFilter(131072, 4),
		exactDomains:   make(map[string]ThreatCategory),
		suffixDomains:  make(map[string]ThreatCategory),
		blockedIPNets:  make([]*net.IPNet, 0),
		allowedDomains: make(map[string]bool),
		allowedIPs:     make(map[string]bool),
	}

	if blockMalware {
		for _, d := range DefaultMalwareDomains {
			engine.addDomain(d, CategoryMalware)
		}
	}
	if blockPhishing {
		for _, d := range DefaultPhishingDomains {
			engine.addDomain(d, CategoryPhishing)
		}
	}
	if blockMiners {
		for _, d := range DefaultMinerDomains {
			engine.addDomain(d, CategoryMiner)
		}
	}
	if blockAds {
		for _, d := range DefaultAdTrackerDomains {
			engine.addDomain(d, CategoryAdware)
		}
	}

	for _, d := range customBlockedDomains {
		engine.addDomain(d, CategoryCustom)
	}

	for _, d := range customAllowedDomains {
		clean := strings.ToLower(strings.TrimSpace(d))
		if clean != "" {
			engine.allowedDomains[clean] = true
		}
	}

	for _, ipStr := range customBlockedIPs {
		clean := strings.TrimSpace(ipStr)
		if strings.Contains(clean, "/") {
			if _, ipnet, err := net.ParseCIDR(clean); err == nil {
				engine.blockedIPNets = append(engine.blockedIPNets, ipnet)
			}
		} else {
			if ip := net.ParseIP(clean); ip != nil {
				// /32 or /128
				mask := net.CIDRMask(32, 32)
				if ip.To4() == nil {
					mask = net.CIDRMask(128, 128)
				}
				engine.blockedIPNets = append(engine.blockedIPNets, &net.IPNet{IP: ip, Mask: mask})
			}
		}
	}

	return engine
}

func (e *ThreatEngine) addDomain(domain string, category ThreatCategory) {
	clean := strings.ToLower(strings.TrimSpace(domain))
	if clean == "" {
		return
	}
	clean = strings.TrimPrefix(clean, ".")

	e.exactDomains[clean] = category
	e.suffixDomains[clean] = category
	e.bloomFilter.Add(clean)
}

// CheckHost evaluates if a domain or IP address is considered malicious.
func (e *ThreatEngine) CheckHost(host string) MatchResult {
	if !e.enabled {
		return MatchResult{Blocked: false}
	}

	cleanHost := strings.ToLower(strings.TrimSpace(host))
	// Remove port if present
	if strings.Contains(cleanHost, ":") && !strings.Contains(cleanHost, "]:") && !strings.HasPrefix(cleanHost, "[") {
		parts := strings.Split(cleanHost, ":")
		if len(parts) == 2 {
			cleanHost = parts[0]
		}
	}

	e.mu.RLock()
	defer e.mu.RUnlock()

	// 1. Check Whitelist
	if e.allowedDomains[cleanHost] {
		return MatchResult{Blocked: false}
	}

	// 2. Check if host is IP address
	if ip := net.ParseIP(cleanHost); ip != nil {
		for _, ipnet := range e.blockedIPNets {
			if ipnet.Contains(ip) {
				return MatchResult{
					Blocked:  true,
					Category: CategoryCustom,
					Reason:   "IP address matches security threat blocklist",
				}
			}
		}
		return MatchResult{Blocked: false}
	}

	// 3. Fast Bloom Filter pre-check
	if !e.bloomFilter.MayContain(cleanHost) {
		// If not in bloom, check suffix components (e.g. sub.badsite.com -> badsite.com)
		hasSuffixCandidate := false
		parts := strings.Split(cleanHost, ".")
		for i := 1; i < len(parts)-1; i++ {
			subDomain := strings.Join(parts[i:], ".")
			if e.bloomFilter.MayContain(subDomain) {
				hasSuffixCandidate = true
				break
			}
		}
		if !hasSuffixCandidate {
			return MatchResult{Blocked: false}
		}
	}

	// 4. Exact domain match
	if cat, exists := e.exactDomains[cleanHost]; exists {
		return MatchResult{
			Blocked:  true,
			Category: cat,
			Reason:   "Domain matches " + string(cat) + " threat feed",
		}
	}

	// 5. Suffix domain match (e.g. *.coinhive.com)
	parts := strings.Split(cleanHost, ".")
	for i := 1; i < len(parts)-1; i++ {
		parentDomain := strings.Join(parts[i:], ".")
		if cat, exists := e.suffixDomains[parentDomain]; exists {
			return MatchResult{
				Blocked:  true,
				Category: cat,
				Reason:   "Subdomain matches " + string(cat) + " parent rule: " + parentDomain,
			}
		}
	}

	return MatchResult{Blocked: false}
}
