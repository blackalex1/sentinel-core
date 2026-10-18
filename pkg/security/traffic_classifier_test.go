package security

import (
	"testing"
)

func TestTrafficClassifier_IsSafeSystemTraffic(t *testing.T) {
	cases := []struct {
		name     string
		destIP   string
		destHost string
		port     int
		expected bool
	}{
		{"Port 53 DNS", "8.8.8.8", "dns.google", 53, true},
		{"Port 80 HTTP", "93.184.216.34", "example.com", 80, true},
		{"Port 443 HTTPS", "142.250.180.206", "google.com", 443, true},
		{"Port 853 DoT", "1.1.1.1", "cloudflare-dns.com", 853, true},
		{"Loopback IPv4", "127.0.0.1", "", 9000, true},
		{"Loopback IPv6", "::1", "", 9000, true},
		{"Localhost IP string", "localhost", "", 9000, true},
		{"Localhost Host string", "1.2.3.4", "localhost", 9000, true},
		{"Private RFC1918 Class A", "10.0.0.15", "", 8080, true},
		{"Private RFC1918 Class B", "172.16.5.10", "", 8080, true},
		{"Private RFC1918 Class C", "192.168.1.1", "", 8080, true},
		{"Link-local Unicast", "169.254.10.20", "", 8080, true},
		{"Public IP Suspicious Port", "203.0.113.5", "target.com", 445, false},
		{"Invalid IP Suspicious Port", "invalid.ip", "target.com", 9999, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := IsSafeSystemTraffic(tc.destIP, tc.destHost, tc.port)
			if res != tc.expected {
				t.Errorf("IsSafeSystemTraffic(%s, %s, %d) = %v; want %v", tc.destIP, tc.destHost, tc.port, res, tc.expected)
			}
		})
	}
}

func TestTrafficClassifier_IsCloudMetadataEndpoint(t *testing.T) {
	threats := []struct {
		destIP   string
		destHost string
		desc     string
	}{
		{"169.254.169.254", "", "AWS/OpenStack metadata IP"},
		{"100.100.100.200", "", "Alibaba Cloud metadata IP"},
		{"169.254.170.2", "", "AWS ECS / Azure container metadata IP"},
		{"", "metadata.google.internal", "GCP internal metadata hostname"},
		{"", "metadata.goog", "GCP short metadata hostname"},
		{"", "instance-data.ec2.internal", "AWS instance data hostname"},
		{"", "169.254.169.254.nip.io", "DNS rebinding to metadata IP"},
		{"", "sub.169.254.170.2.xip.io", "DNS rebinding to ECS metadata IP"},
		{"", "test.100.100.100.200.nip.io", "DNS rebinding to Alibaba metadata IP"},
	}

	for _, tc := range threats {
		t.Run(tc.desc, func(t *testing.T) {
			if !IsCloudMetadataEndpoint(tc.destIP, tc.destHost) {
				t.Errorf("expected IsCloudMetadataEndpoint(%s, %s) to be true for %s", tc.destIP, tc.destHost, tc.desc)
			}
		})
	}

	safes := []struct {
		destIP   string
		destHost string
	}{
		{"1.1.1.1", "cloudflare.com"},
		{"8.8.8.8", "dns.google"},
		{"93.184.216.34", "example.com"},
		{"127.0.0.1", "localhost"},
	}

	for _, tc := range safes {
		t.Run("Safe: "+tc.destHost, func(t *testing.T) {
			if IsCloudMetadataEndpoint(tc.destIP, tc.destHost) {
				t.Errorf("expected IsCloudMetadataEndpoint(%s, %s) to be false", tc.destIP, tc.destHost)
			}
		})
	}
}
