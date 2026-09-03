package android

import (
	"testing"
)

func TestClassifySource(t *testing.T) {
	tests := []struct {
		srcIP        string
		wantHotspot  bool
		wantSource   string
	}{
		// Loopback
		{"127.0.0.1", false, "loopback"},
		{"127.0.0.2", false, "loopback"},
		{"::1", false, "loopback"},
		{"localhost", false, "loopback"},

		// Local Android TUN interface
		{"10.0.0.2", false, "local_tun"},
		{"10.0.0.1", false, "local_tun"},
		{"fd00::2", false, "local_tun"},
		{"fd00::1", false, "local_tun"},
		{"[fd00::2]", false, "local_tun"},

		// Hotspot / Tethering clients
		{"192.168.43.15", true, "hotspot"},
		{"192.168.1.100", true, "hotspot"},
		{"172.16.0.5", true, "hotspot"},
	}

	for _, tt := range tests {
		gotHotspot, gotSource := ClassifySource(tt.srcIP)
		if gotHotspot != tt.wantHotspot {
			t.Errorf("ClassifySource(%q) isHotspot = %v, want %v", tt.srcIP, gotHotspot, tt.wantHotspot)
		}
		if gotSource != tt.wantSource {
			t.Errorf("ClassifySource(%q) sourceType = %q, want %q", tt.srcIP, gotSource, tt.wantSource)
		}
	}
}
