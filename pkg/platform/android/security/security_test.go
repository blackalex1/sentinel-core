package security

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAndroidThreatEngine_CleanAndThreshold(t *testing.T) {
	engine := NewAndroidThreatEngine(5 * time.Minute)
	defer engine.Close()

	pkg := "com.example.cleanapp"

	// 1. Standard Web traffic should never trigger threat
	v1 := engine.AuditConnection(AuditRequest{
		PackageName:   pkg,
		AppName:       "Clean App",
		DestinationIP: "1.1.1.1",
		Port:          443,
		Protocol:      "TCP",
	})
	if v1.ThreatDetected || v1.ShouldBlock {
		t.Fatalf("expected clean web traffic to pass, got %+v", v1)
	}

	// 2. Non-standard port with dynamic audit ports enabled
	badPkg := "com.example.malware"
	auditPorts := []int{4444, 5555, 6666}

	// First attempt on 4444
	v2 := engine.AuditConnection(AuditRequest{
		PackageName:   badPkg,
		AppName:       "Malware App",
		DestinationIP: "192.168.1.50",
		Port:          4444,
		Protocol:      "TCP",
		AuditPorts:    auditPorts,
		MaxThreshold:  2,
	})
	if v2.ThreatDetected || v2.ShouldBlock {
		t.Fatalf("attempt 1 should be allowed, got %+v", v2)
	}

	// Second attempt on 4444
	v3 := engine.AuditConnection(AuditRequest{
		PackageName:   badPkg,
		AppName:       "Malware App",
		DestinationIP: "192.168.1.50",
		Port:          4444,
		Protocol:      "TCP",
		AuditPorts:    auditPorts,
		MaxThreshold:  2,
	})
	if v3.ThreatDetected || v3.ShouldBlock {
		t.Fatalf("attempt 2 should still be below threshold 2, got %+v", v3)
	}

	// Third attempt on 4444 (Breaches threshold > 2)
	v4 := engine.AuditConnection(AuditRequest{
		PackageName:   badPkg,
		AppName:       "Malware App",
		DestinationIP: "192.168.1.50",
		Port:          4444,
		Protocol:      "TCP",
		AuditPorts:    auditPorts,
		MaxThreshold:  2,
	})
	if !v4.ThreatDetected || !v4.ShouldBlock || v4.Action != ActionBlock {
		t.Fatalf("expected breach on attempt 3, got %+v", v4)
	}
	if !engine.IsAppBlocked(badPkg) {
		t.Fatalf("expected badPkg to be actively blackholed")
	}

	// Subsequent connection should be blocked immediately
	v5 := engine.AuditConnection(AuditRequest{
		PackageName:   badPkg,
		AppName:       "Malware App",
		DestinationIP: "192.168.1.50",
		Port:          4444,
	})
	if !v5.IsBlocked || v5.Action != ActionBlock {
		t.Fatalf("expected blackholed app to be immediately blocked, got %+v", v5)
	}

	// Unblock app
	engine.UnblockApp(badPkg)
	if engine.IsAppBlocked(badPkg) {
		t.Fatalf("expected app to be unblocked")
	}
}

func TestAndroidThreatEngine_SystemPackageProtection(t *testing.T) {
	engine := NewAndroidThreatEngine(5 * time.Minute)
	defer engine.Close()

	sysPkg := "android.system.kernel"

	for i := 0; i < 4; i++ {
		v := engine.AuditConnection(AuditRequest{
			PackageName:   sysPkg,
			AppName:       "System Kernel",
			DestinationIP: "10.0.0.99",
			Port:          9000,
			Protocol:      "TCP",
			MaxThreshold:  2,
		})
		if i < 2 {
			if v.ThreatDetected {
				t.Fatalf("early attempt should not trigger threat")
			}
		} else {
			if !v.ThreatDetected || !v.IsSystemFlagged {
				t.Fatalf("expected system package to be flagged, got %+v", v)
			}
			if v.ShouldBlock || v.Action == ActionBlock {
				t.Fatalf("system package MUST NOT be blocked, got action %s", v.Action)
			}
		}
	}
}

func TestPCAP_GenerationAndDissection(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "sentinel_pcap_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	pcapPath := filepath.Join(tempDir, "test.pcap")

	httpPayload := []byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n")
	pkt := SynthesizeRawIPv4Packet("TCP", "10.0.0.2", 54321, "93.184.216.34", 80, 0x18, 1000, 2000, 64240, httpPayload)

	err = WritePacketToPcap(pcapPath, pkt, time.Now().UnixMilli())
	if err != nil {
		t.Fatalf("failed to write pcap: %v", err)
	}

	// Verify PCAP File on Disk
	data, err := os.ReadFile(pcapPath)
	if err != nil {
		t.Fatalf("failed to read pcap file: %v", err)
	}
	if len(data) < 24+16+len(pkt) {
		t.Fatalf("pcap file too small (%d bytes)", len(data))
	}
	magic := binary.LittleEndian.Uint32(data[0:4])
	if magic != PCAPMagicLittleEndian {
		t.Fatalf("invalid pcap magic: 0x%x", magic)
	}

	// Test Dissection
	dissected, err := DissectPacket(pkt)
	if err != nil {
		t.Fatalf("dissection failed: %v", err)
	}
	if dissected.Protocol != "TCP" || dissected.DestinationPort != 80 {
		t.Fatalf("expected TCP:80, got %s:%d", dissected.Protocol, dissected.DestinationPort)
	}
	if dissected.DetectedProto != "HTTP" {
		t.Fatalf("expected HTTP detected protocol, got %s", dissected.DetectedProto)
	}
	if dissected.ExtraMetadata["host"] != "example.com" {
		t.Fatalf("expected host example.com, got %s", dissected.ExtraMetadata["host"])
	}
}
