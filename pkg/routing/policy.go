package routing

// RoutingMode defines the global traffic routing behavior
type RoutingMode string

const (
	ModeSmartRule     RoutingMode = "smart_rule"     // Uses ads + ru presets by default
	ModeGlobalProxy   RoutingMode = "global_proxy"   // Route all traffic through proxy except LAN
	ModeDirectAll     RoutingMode = "direct_all"     // Direct all traffic
	ModeWhitelistOnly RoutingMode = "whitelist_only" // Only proxy explicitly listed domains/apps
)

// RoutingPolicy represents the high-level routing configuration.
// It is 100% dynamic: specify any preset IDs (e.g. ["ru", "ads", "bittorrent", "pt"])
// and optional target overrides (e.g. {"ru": "block", "cn": "warp"}).
type RoutingPolicy struct {
	Mode RoutingMode `json:"mode"`

	// Active preset IDs loaded dynamically from presets/*.json
	// (e.g. ["ru"], ["pt"], ["ads", "bittorrent"], etc.)
	EnabledPresets []string `json:"enabledPresets,omitempty"`

	// Outbound destination tag overrides per preset ID
	// (e.g. {"ru": "direct", "cn": "blocked", "bittorrent": "blocked", "pt": "warp"})
	PresetTargetOverrides map[string]string `json:"presetTargetOverrides,omitempty"`

	// Explicit rule rows (from the UI table or DB)
	CustomRules []RoutingRuleRow `json:"customRules,omitempty"`

	// Custom user domain/IP overrides
	CustomProxyDomains  []string `json:"customProxyDomains,omitempty"`
	CustomDirectDomains []string `json:"customDirectDomains,omitempty"`
	CustomBlockDomains  []string `json:"customBlockDomains,omitempty"`

	CustomProxyIPs  []string `json:"customProxyIps,omitempty"`
	CustomDirectIPs []string `json:"customDirectIps,omitempty"`
	CustomBlockIPs  []string `json:"customBlockIps,omitempty"`

	// Windows process-based routing (for x-pc)
	WindowsProcessProxy  []string `json:"windowsProcessProxy,omitempty"`
	WindowsProcessDirect []string `json:"windowsProcessDirect,omitempty"`

	// Android package-based routing (for x-prox)
	AndroidIncludePackages []string `json:"androidIncludePackages,omitempty"`
	AndroidExcludePackages []string `json:"androidExcludePackages,omitempty"`
	AndroidBlockedUIDs     []string `json:"androidBlockedUids,omitempty"`

	// Security & Threat Detection port blocks
	BlockedPorts []string `json:"blockedPorts,omitempty"`
}

// DefaultSmartPolicy returns standard Smart Rule routing policy (LAN direct, Ads block, RU direct)
func DefaultSmartPolicy() *RoutingPolicy {
	return &RoutingPolicy{
		Mode:           ModeSmartRule,
		EnabledPresets: []string{"ads", "ru"},
	}
}

// DefaultGlobalPolicy returns Global Proxy policy (LAN direct, rest proxy)
func DefaultGlobalPolicy() *RoutingPolicy {
	return &RoutingPolicy{
		Mode:           ModeGlobalProxy,
		EnabledPresets: []string{},
	}
}
