package ast

// RouteAction defines the outcome of matching a routing rule
type RouteAction string

const (
	ActionProxy  RouteAction = "proxy"
	ActionDirect RouteAction = "direct"
	ActionBlock  RouteAction = "block"
)

// RoutingRule defines a single traffic-routing matcher
type RoutingRule struct {
	Action      RouteAction `json:"action"`                // proxy, direct, block
	OutboundTag string      `json:"outboundTag,omitempty"`
	Enable      *bool       `json:"enable,omitempty"`
	Enabled     *bool       `json:"enabled,omitempty"` // alias for enable

	// Matchers
	Domains          []string `json:"domains,omitempty"`          // e.g. ["domain:google.com", "geosite:category-ads-all"]
	IPs              []string `json:"ips,omitempty"`              // e.g. ["geoip:private", "geoip:ru", "192.168.0.0/16"]
	Ports            []string `json:"ports,omitempty"`            // e.g. ["80", "443", "1000-2000"]
	Protocols        []string `json:"protocols,omitempty"`        // "bittorrent", "quic", "tcp", "udp"
	NetworkProtocols []string `json:"networkProtocols,omitempty"` // alias
	Users            []string `json:"users,omitempty"`            // Client emails or user IDs
	PackageUIDs      []string `json:"packageUids,omitempty"`      // Android user UIDs
	ProcessNames     []string `json:"processNames,omitempty"`     // Windows/Linux process binaries e.g. ["discord.exe"]
	InboundTags      []string `json:"inboundTags,omitempty"`
	IPVersion        int      `json:"ipVersion,omitempty"`
}

// IsEnabled returns true if the rule is not explicitly disabled
func (r *RoutingRule) IsEnabled() bool {
	if r.Enable != nil && !*r.Enable {
		return false
	}
	if r.Enabled != nil && !*r.Enabled {
		return false
	}
	return true
}

// RoutingSpec contains the full collection of routing rules and global route switches
type RoutingSpec struct {
	DefaultAction       RouteAction              `json:"defaultAction"` // Default outbound: proxy or direct
	Rules               []RoutingRule            `json:"rules"`
	Outbounds           []map[string]interface{} `json:"outbounds,omitempty"`
	AutoDetectInterface bool                     `json:"autoDetectInterface"`
	OverrideDNS         bool                     `json:"overrideDns"`
	RuleSets            []string                 `json:"ruleSets,omitempty"` // Remote rule-sets for Sing-box 1.12+
}
