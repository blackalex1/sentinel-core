package ast

type DNSSpec struct {
	RemoteServer string   `json:"remoteServer,omitempty"` // e.g. "https://dns.google/dns-query" or "tcp://8.8.8.8"
	DirectServer string   `json:"directServer,omitempty"` // e.g. "8.8.8.8" or "local"
	Strategy     string   `json:"strategy,omitempty"`     // "prefer_ipv4", "ipv4_only", "prefer_ipv6"
	FakeIP       bool     `json:"fakeIp"`
	FakeIPRange  string   `json:"fakeIpRange,omitempty"` // e.g. "198.18.0.0/15"
	Servers      []string `json:"servers,omitempty"`
	FinalServer  string   `json:"finalServer,omitempty"`
}

// DefaultDNSSpec returns a sensible default DNS specification
func DefaultDNSSpec() DNSSpec {
	return DNSSpec{
		RemoteServer: "https://dns.google/dns-query",
		DirectServer: "8.8.8.8",
		Strategy:     "ipv4_only",
		FakeIP:       false,
		Servers:      []string{"https://dns.google/dns-query", "8.8.8.8"},
		FinalServer:  "8.8.8.8",
	}
}
