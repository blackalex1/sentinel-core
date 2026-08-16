package ast

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Protocol constants
const (
	ProtoVLESS       = "vless"
	ProtoVMess       = "vmess"
	ProtoTrojan      = "trojan"
	ProtoShadowsocks = "shadowsocks"
	ProtoShadowTLS   = "shadowtls"
	ProtoHysteria2   = "hysteria2"
	ProtoTUIC        = "tuic"
	ProtoWireGuard   = "wireguard"
	ProtoSocks       = "socks"
	ProtoHTTP        = "http"
	ProtoDirect      = "direct"
	ProtoBlock       = "block"
)

// Transport constants
const (
	TransportTCP         = "tcp"
	TransportGRPC        = "grpc"
	TransportWS          = "ws"
	TransportHTTP        = "http"
	TransportH2          = "h2"
	TransportQUIC        = "quic"
	TransportKCP         = "kcp"
	TransportXHTTP       = "xhttp"
	TransportSplitHTTP   = "splithttp"
	TransportHTTPUpgrade = "httpupgrade"
)

// Security constants
const (
	SecurityNone      = "none"
	SecurityTLS       = "tls"
	SecurityReality   = "reality"
	SecurityShadowTLS = "shadowtls"
)

// ServerProfile represents a fully typed, protocol-agnostic proxy endpoint specification.
type ServerProfile struct {
	ID        string `json:"id,omitempty"`
	Name      string `json:"name,omitempty"`
	Protocol  string `json:"protocol"`
	Address   string `json:"address"`
	Port      int    `json:"port"`
	Transport string `json:"transport,omitempty"`
	Security  string `json:"security,omitempty"`

	// Common credentials
	UUID     string `json:"uuid,omitempty"`
	Password string `json:"password,omitempty"`
	Username string `json:"username,omitempty"`

	// TLS & Reality settings
	SNI         string   `json:"sni,omitempty"`
	ALPN        []string `json:"alpn,omitempty"`
	Fingerprint string   `json:"fingerprint,omitempty"`
	Insecure    bool     `json:"insecure,omitempty"`

	// Reality specific
	PublicKey string `json:"publicKey,omitempty"`
	ShortID   string `json:"shortId,omitempty"`
	SpiderX   string `json:"spiderX,omitempty"`

	// Post-Quantum Cryptography flag (Kyber768 / ML-KEM)
	PostQuantum bool `json:"postQuantum,omitempty"`

	// Flow & Mux & VLESS Encryption
	Flow       string `json:"flow,omitempty"` // e.g. "xtls-rprx-vision"
	Encryption string `json:"encryption,omitempty"` // e.g. "mlkem768x25519plus.native.0rtt..."
	Mux        bool   `json:"mux,omitempty"`

	// Transport layer parameters
	Path        string            `json:"path,omitempty"`
	Host        string            `json:"host,omitempty"`
	ServiceName string            `json:"serviceName,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`

	// Shadowsocks / ShadowTLS parameters
	Cipher           string `json:"cipher,omitempty"`
	ShadowTLSVersion int    `json:"shadowTlsVersion,omitempty"`
	ShadowTLSPassword string `json:"shadowTlsPassword,omitempty"`
	ShadowTLSSNI     string `json:"shadowTlsSni,omitempty"`

	// Hysteria 2 specific parameters
	BandwidthUp   string `json:"bandwidthUp,omitempty"`
	BandwidthDown string `json:"bandwidthDown,omitempty"`
	ObfsType      string `json:"obfsType,omitempty"` // e.g. "salamander"
	ObfsPassword  string `json:"obfsPassword,omitempty"`
	PortHopping   string `json:"portHopping,omitempty"` // e.g. "20000-40000" or "443,1000-2000"

	// TUIC specific parameters
	CongestionControl string `json:"congestionControl,omitempty"` // bbr, cubic, new_reno
	UDPRelayMode      string `json:"udpRelayMode,omitempty"`      // native, quic
	ZeroRTTHandshake  bool   `json:"zeroRttHandshake,omitempty"`

	// WireGuard specific parameters
	PrivateKey    string   `json:"privateKey,omitempty"`
	PeerPublicKey string   `json:"peerPublicKey,omitempty"`
	PreSharedKey  string   `json:"preSharedKey,omitempty"`
	LocalAddress  []string `json:"localAddress,omitempty"` // e.g. ["10.0.0.2/32"]
	MTU           int      `json:"mtu,omitempty"`
	ReservedBytes []int    `json:"reservedBytes,omitempty"` // e.g. [0, 0, 0]

	// Dynamic extra parameters
	Extra map[string]interface{} `json:"extra,omitempty"`
}

// Normalize sanitizes and standardizes all string fields in the profile.
func (p *ServerProfile) Normalize() {
	p.Protocol = strings.ToLower(strings.TrimSpace(p.Protocol))
	p.Address = strings.TrimSpace(p.Address)
	if p.Transport == "" {
		p.Transport = TransportTCP
	} else {
		p.Transport = strings.ToLower(strings.TrimSpace(p.Transport))
	}

	if p.Security == "" {
		if p.PublicKey != "" {
			p.Security = SecurityReality
		} else if p.SNI != "" || p.Insecure {
			p.Security = SecurityTLS
		} else {
			p.Security = SecurityNone
		}
	} else {
		p.Security = strings.ToLower(strings.TrimSpace(p.Security))
	}

	if p.Fingerprint == "" && (p.Security == SecurityTLS || p.Security == SecurityReality) {
		p.Fingerprint = "chrome"
	}
}

// Validate checks if the minimal necessary fields are present.
func (p *ServerProfile) Validate() error {
	if p.Address == "" {
		return fmt.Errorf("server address cannot be empty")
	}
	if p.Port <= 0 || p.Port > 65535 {
		return fmt.Errorf("invalid port: %d", p.Port)
	}
	if p.Protocol == "" {
		return fmt.Errorf("protocol cannot be empty")
	}
	return nil
}

// ToJSON serializes the profile to pretty JSON string.
func (p *ServerProfile) ToJSON() (string, error) {
	bytes, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}
