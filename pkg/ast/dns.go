package ast

// DNSSpec defines DNS resolution settings
type DNSSpec struct {
	RemoteServer string `json:"remoteServer"` // e.g. "https://1.1.1.1/dns-query" or "tcp://8.8.8.8"
	DirectServer string `json:"directServer"` // e.g. "8.8.8.8" or "local"
	Strategy     string `json:"strategy"`     // "prefer_ipv4", "ipv4_only", "prefer_ipv6"
	FakeIP       bool   `json:"fakeIp"`
	FakeIPRange  string `json:"fakeIpRange,omitempty"` // e.g. "198.18.0.0/15"
}

// DefaultDNSSpec returns a sensible default DNS specification
func DefaultDNSSpec() DNSSpec {
	return DNSSpec{
		RemoteServer: "https://1.1.1.1/dns-query",
		DirectServer: "8.8.8.8",
		Strategy:     "ipv4_only",
		FakeIP:       false,
	}
}
