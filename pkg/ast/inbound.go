package ast

// InboundMode defines the inbound operational mode
type InboundMode string

const (
	InboundModeDesktopTun  InboundMode = "desktop_tun"  // Windows Wintun VPN Adapter
	InboundModeMobileVpn   InboundMode = "mobile_vpn"   // Android VpnService Loopback
	InboundModeSystemProxy InboundMode = "system_proxy" // SOCKS5 + HTTP Local Proxy
	InboundModeServer      InboundMode = "server"       // Server Multi-Client Inbound
)

// ClientInboundSpec holds local inbound ports and TUN interface configuration
type ClientInboundSpec struct {
	Mode          InboundMode `json:"mode"`
	SocksPort     int         `json:"socksPort"`
	HTTPPort      int         `json:"httpPort"`
	ListenAddress string      `json:"listenAddress"` // e.g. "127.0.0.1" or "0.0.0.0"

	// SOCKS5 Authentication (for mobile loopback leak protection)
	AuthEnabled  bool   `json:"authEnabled,omitempty"`
	AuthUsername string `json:"authUsername,omitempty"`
	AuthPassword string `json:"authPassword,omitempty"`

	// TUN Settings
	TunInterfaceName string   `json:"tunInterfaceName,omitempty"` // e.g. "sentinel-tun"
	TunStack         string   `json:"tunStack,omitempty"`         // "mixed", "gvisor", "system"
	MTU              int      `json:"mtu,omitempty"`
	StrictRoute      bool     `json:"strictRoute,omitempty"`
	AutoRoute        bool     `json:"autoRoute,omitempty"`
	EndpointIP       string   `json:"endpointIp,omitempty"` // e.g. "172.19.0.1/30"
	Inet4Address     string   `json:"inet4Address,omitempty"`
	Inet6Address     string   `json:"inet6Address,omitempty"`
	IncludePackages  []string `json:"includePackages,omitempty"`
	ExcludePackages  []string `json:"excludePackages,omitempty"`
}

// ServerInboundClient represents an authenticated user on the server
type ServerInboundClient struct {
	ID       string `json:"id"`
	UUID     string `json:"uuid,omitempty"`
	Password string `json:"password,omitempty"`
	Email    string `json:"email,omitempty"`
	Flow     string `json:"flow,omitempty"`
}

// ServerInboundSpec defines a server listening port (for sentinel-panel)
type ServerInboundSpec struct {
	Tag           string                `json:"tag"`
	Protocol      string                `json:"protocol"` // "vless", "hysteria2", "trojan", etc.
	ListenAddress string                `json:"listenAddress"`
	Port          int                   `json:"port"`
	Transport     string                `json:"transport"`
	Security      string                `json:"security"`
	SNI           string                `json:"sni,omitempty"`
	CertPath      string                `json:"certPath,omitempty"`
	KeyPath       string                `json:"keyPath,omitempty"`
	PublicKey     string                `json:"publicKey,omitempty"`
	PrivateKey    string                `json:"privateKey,omitempty"`
	ShortIDs      []string              `json:"shortIds,omitempty"`
	Clients       []ServerInboundClient `json:"clients"`
	Multiplex     bool                  `json:"multiplex,omitempty"`

	// Hysteria 2 specific server options
	PortHop        string `json:"portHop,omitempty"`
	AdminPort      int    `json:"adminPort,omitempty"`
	AuthURL        string `json:"authUrl,omitempty"`
	ObfsType       string `json:"obfsType,omitempty"`
	ObfsPassword   string `json:"obfsPassword,omitempty"`
	BandwidthUp    string `json:"bandwidthUp,omitempty"`
	BandwidthDown  string `json:"bandwidthDown,omitempty"`
	MasqType       string `json:"masqType,omitempty"`
	MasqValue      string `json:"masqValue,omitempty"`
	MasqStatusCode int    `json:"masqStatusCode,omitempty"`
	SocksPort      int                      `json:"socksPort,omitempty"`
	SocksUsername  string                   `json:"socksUsername,omitempty"`
	SocksPassword  string                   `json:"socksPassword,omitempty"`
	Fallbacks      []map[string]interface{} `json:"fallbacks,omitempty"`
	RawSettings    map[string]interface{}   `json:"settings,omitempty"`
	StreamSettings map[string]interface{}   `json:"streamSettings,omitempty"`
	Sniffing       map[string]interface{}   `json:"sniffing,omitempty"`
}
