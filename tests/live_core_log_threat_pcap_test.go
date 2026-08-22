package tests

import (
	"encoding/binary"
	"os"
	"testing"

	"github.com/blackalex1/sentinel-core/pkg/security"
	"github.com/blackalex1/sentinel-core/pkg/security/detector"
)

func TestLiveCoreLog_DesktopThreatAndPcapCapture(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "sentinel_desktop_pcap_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	engine := security.NewUnifiedSecurityEngine(0)
	defer engine.Stop()

	// Configure automated PCAP capture: 3 prohibited port probes triggers PCAP
	engine.SetPcapConfig(tempDir, 3)

	singboxParser := detector.NewSingboxParser()
	prohibitedPorts := []int{22, 445, 135, 139, 3389, 23, 5353}

	// 1. Prohibited Port Probes Sequence from Desktop process
	logLines := []string{
		"INFO inbound connection to 198.51.100.22:22 from process powershell.exe",
		"INFO inbound connection to 198.51.100.22:445 from process powershell.exe",
		"INFO inbound connection to 198.51.100.22:3389 from process powershell.exe",
	}

	var lastVerdict security.SecurityAuditVerdict
	for i, line := range logLines {
		evt, ok := singboxParser.ParseLogLine(line)
		if !ok {
			t.Fatalf("failed to parse log line %d: %s", i, line)
		}

		lastVerdict = engine.AuditConnection(security.SecurityAuditRequest{
			CallerID:      "powershell.exe",
			DestinationIP: evt.TargetHost,
			Port:          evt.TargetPort,
			Protocol:      "TCP",
			AuditPorts:    prohibitedPorts,
			Platform:      "windows",
		})

		if i < 2 {
			if !lastVerdict.ThreatDetected || lastVerdict.IsBlocked || lastVerdict.Action != "ALERT" {
				t.Fatalf("expected probe %d to ALERT without blocking, got: %+v", i, lastVerdict)
			}
		} else {
			if !lastVerdict.ThreatDetected || !lastVerdict.IsBlocked || lastVerdict.Action != "BLOCK" {
				t.Fatalf("expected probe %d (3rd) to BLOCK, got: %+v", i, lastVerdict)
			}
		}
	}

	// Verify that reaching the threshold (3 probes) automatically recorded PCAP
	if !lastVerdict.PcapCaptured || lastVerdict.PcapFilePath == "" {
		t.Fatalf("expected PCAP capture to be triggered at 3rd probe, got: %+v", lastVerdict)
	}

	pcapData, err := os.ReadFile(lastVerdict.PcapFilePath)
	if err != nil {
		t.Fatalf("failed to read generated PCAP file: %v", err)
	}

	if len(pcapData) < 24+16 {
		t.Fatalf("PCAP file too small: %d bytes", len(pcapData))
	}

	// Validate PCAP magic number (0xa1b2c3d4)
	magic := binary.LittleEndian.Uint32(pcapData[0:4])
	if magic != security.PCAPMagicLittleEndian {
		t.Fatalf("invalid PCAP magic: 0x%x, expected: 0x%x", magic, security.PCAPMagicLittleEndian)
	}

	t.Logf("PASS: Desktop live core log sensitive port detection and automated PCAP capture verified! File: %s (%d bytes)",
		lastVerdict.PcapFilePath, len(pcapData))
}

func TestLiveCoreLog_DesktopPortScan_TriggersImmediatePcap(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "sentinel_portscan_pcap_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	engine := security.NewUnifiedSecurityEngine(0)
	defer engine.Stop()
	engine.SetPcapConfig(tempDir, 3)

	singboxParser := detector.NewSingboxParser()

	// Port scan sequence across 5 non-standard ports
	scanLogs := []string{
		"INFO inbound connection to 198.51.100.50:2101 from process nmap.exe",
		"INFO inbound connection to 198.51.100.50:2102 from process nmap.exe",
		"INFO inbound connection to 198.51.100.50:2103 from process nmap.exe",
		"INFO inbound connection to 198.51.100.50:2104 from process nmap.exe",
		"INFO inbound connection to 198.51.100.50:2105 from process nmap.exe",
	}

	var scanVerdict security.SecurityAuditVerdict
	for _, line := range scanLogs {
		evt, ok := singboxParser.ParseLogLine(line)
		if !ok {
			t.Fatalf("failed to parse scan log line: %s", line)
		}

		scanVerdict = engine.AuditConnection(security.SecurityAuditRequest{
			CallerID:      "nmap.exe",
			DestinationIP: evt.TargetHost,
			Port:          evt.TargetPort,
			Protocol:      "TCP",
			Platform:      "windows",
		})
	}

	if !scanVerdict.ThreatDetected || scanVerdict.ThreatType != security.ThreatPortScan {
		t.Fatalf("expected PORT_SCAN detection, got: %+v", scanVerdict)
	}

	if !scanVerdict.PcapCaptured || scanVerdict.PcapFilePath == "" {
		t.Fatalf("expected PORT_SCAN to trigger automated PCAP capture, got: %+v", scanVerdict)
	}

	stat, err := os.Stat(scanVerdict.PcapFilePath)
	if err != nil || stat.Size() == 0 {
		t.Fatalf("PCAP file does not exist or is empty: %v", err)
	}

	t.Logf("PASS: Desktop live core log PORT_SCAN detection and immediate PCAP capture verified! File: %s", scanVerdict.PcapFilePath)
}

func TestLiveCoreLog_AndroidThreatAndPcapCapture(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "sentinel_android_pcap_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	engine := security.NewUnifiedSecurityEngine(0)
	defer engine.Stop()
	engine.SetPcapConfig(tempDir, 3)

	singboxParser := detector.NewSingboxParser()
	prohibitedPorts := []int{22, 445, 135, 139, 3389, 23, 5353}

	// 1. Android malicious package probing prohibited ports in core logs
	androidLogs := []string{
		"INFO inbound connection to 198.51.100.30:445 from user com.malicious.spyware",
		"INFO inbound connection to 198.51.100.30:135 from user com.malicious.spyware",
		"INFO inbound connection to 198.51.100.30:3389 from user com.malicious.spyware",
	}

	var lastVerdict security.SecurityAuditVerdict
	for i, line := range androidLogs {
		evt, ok := singboxParser.ParseLogLine(line)
		if !ok {
			t.Fatalf("failed to parse android log line %d: %s", i, line)
		}

		lastVerdict = engine.AuditConnection(security.SecurityAuditRequest{
			CallerID:      evt.ClientRawID,
			DestinationIP: evt.TargetHost,
			Port:          evt.TargetPort,
			Protocol:      "TCP",
			AuditPorts:    prohibitedPorts,
			Platform:      "android",
		})

		if i < 2 {
			if !lastVerdict.ThreatDetected || lastVerdict.IsBlocked || lastVerdict.Action != "ALERT" {
				t.Fatalf("expected Android threat %d to ALERT without blocking, got: %+v", i, lastVerdict)
			}
		} else {
			if !lastVerdict.ThreatDetected || !lastVerdict.IsBlocked || lastVerdict.Action != "BLOCK" {
				t.Fatalf("expected Android threat %d (3rd) to BLOCK, got: %+v", i, lastVerdict)
			}
		}
	}

	// 2. Check automated PCAP file generation on threshold
	if !lastVerdict.PcapCaptured || lastVerdict.PcapFilePath == "" {
		t.Fatalf("expected Android threat threshold to capture PCAP, got: %+v", lastVerdict)
	}

	pcapData, err := os.ReadFile(lastVerdict.PcapFilePath)
	if err != nil {
		t.Fatalf("failed to read android PCAP file: %v", err)
	}

	magic := binary.LittleEndian.Uint32(pcapData[0:4])
	if magic != security.PCAPMagicLittleEndian {
		t.Fatalf("invalid PCAP magic in android pcap: 0x%x", magic)
	}

	t.Logf("PASS: Android live core log prohibited port detection and automated PCAP capture verified! File: %s (%d bytes)",
		lastVerdict.PcapFilePath, len(pcapData))
}
