package ast

// TargetCore represents the destination proxy binary
type TargetCore string

const (
	CoreSingBox   TargetCore = "singbox"
	CoreXray      TargetCore = "xray"
	CoreHysteria2 TargetCore = "hysteria2"
	CoreWireGuard TargetCore = "wireguard"
)

// ConfigSpec is the high-level input to the compiler pipelines.
type ConfigSpec struct {
	TargetCore    TargetCore         `json:"targetCore"`
	CoreVersion   string             `json:"coreVersion,omitempty"` // e.g. "1.11.4", "1.12.0", "1.8.16"
	StrictMode    bool               `json:"strictMode"`            // If true, fail on unsupported features instead of graceful fallback
	ServerNode    *ServerProfile     `json:"serverNode,omitempty"`  // Primary active outbound server
	ClientInbound *ClientInboundSpec `json:"clientInbound,omitempty"`
	ServerInbounds []ServerInboundSpec `json:"serverInbounds,omitempty"`
	Routing       *RoutingSpec       `json:"routing,omitempty"`
	DNS           *DNSSpec           `json:"dns,omitempty"`
	LogLevel      string             `json:"logLevel,omitempty"` // "trace", "debug", "info", "warn", "error"
	LogPath       string             `json:"logPath,omitempty"`
	ClashAPIAddress string           `json:"clashApiAddress,omitempty"` // e.g. "127.0.0.1:9090"
}
