package netfilter

import (
	"testing"
	"time"
)

func testClassifyHelper(event IptablesEvent, policy ClassifierPolicy, lang string) ClassificationResult {
	return ClassifyConnection(event, policy, lang)
}

func TestParseIptablesLine(t *testing.T) {
	// 1. Host outbound to sensitive port
	line1 := "May 30 02:47:54 proxmox kernel: [12345.67] HOST_CONN_OUT: IN= OUT=eth0 SRC=192.168.1.120 DST=192.168.1.1 LEN=60 PROTO=TCP SPT=56088 DPT=22"
	ev1 := ParseIptablesLine(line1, 100)
	if ev1 == nil {
		t.Fatalf("expected ev1 to be parsed")
	}
	if ev1.VMID != 0 || ev1.Direction != "OUT" || ev1.DPT != 22 || ev1.SPT != 56088 || ev1.Src != "192.168.1.120" || ev1.Dst != "192.168.1.1" {
		t.Errorf("unexpected ev1 fields: %+v", ev1)
	}

	// 2. LXC inbound connection
	line2 := "May 30 16:45:10 proxmox kernel: [12345.67] LXC_CONN: IN=veth109i0 OUT= SRC=192.168.1.120 DST=192.168.1.53 LEN=60 PROTO=TCP SPT=48614 DPT=22"
	ev2 := ParseIptablesLine(line2, 100)
	if ev2 == nil {
		t.Fatalf("expected ev2 to be parsed")
	}
	if ev2.VMID != 109 || ev2.Direction != "IN" || ev2.DPT != 22 || ev2.SPT != 48614 {
		t.Errorf("unexpected ev2 fields: %+v", ev2)
	}

	// 3. LXC VPN local outbound
	line3 := "May 30 16:45:10 proxmox kernel: [12345.67] LXC_VPN_LOCAL_OUT: IN= OUT=eth0 SRC=10.0.0.100 DST=1.1.1.1 PROTO=UDP SPT=53000 DPT=53"
	ev3 := ParseIptablesLine(line3, 105)
	if ev3 == nil {
		t.Fatalf("expected ev3 to be parsed")
	}
	if ev3.VMID != 105 || !ev3.IsLocalProcess || ev3.Direction != "OUT" {
		t.Errorf("unexpected ev3 fields: %+v", ev3)
	}

	// 4. Broadcast / Multicast ignore
	line4 := "May 30 16:45:10 proxmox kernel: [12345.67] HOST_CONN_OUT: IN= OUT=eth0 SRC=192.168.1.120 DST=224.0.0.251 PROTO=UDP SPT=5353 DPT=5353"
	ev4 := ParseIptablesLine(line4, 100)
	if ev4 != nil {
		t.Errorf("expected multicast line to be ignored, got %+v", ev4)
	}
}

func TestClassifyConnection(t *testing.T) {
	policy := DefaultClassifierPolicy()
	policy.VPNVMID = 100
	policy.TrustedAdminIPs = []string{"198.51.100.1"}
	policy.ProxmoxHost = "192.168.1.120:8006"
	policy.LXCWhitelistVMIDs = []int{101}

	// 1. Host IN from Internet to SSH -> CRITICAL
	ev1 := IptablesEvent{
		VMID:      0,
		Direction: "IN",
		Proto:     "TCP",
		Src:       "203.0.113.5",
		Dst:       "192.168.1.120",
		DPT:       22,
	}
	res1 := testClassifyHelper(ev1, policy, "ru")
	if res1.RiskLevel != LevelCritical {
		t.Errorf("expected CRITICAL, got %s (%s)", res1.RiskLevel, res1.Label)
	}

	// 2. Host IN from Trusted Admin IP -> INFO
	ev2 := IptablesEvent{
		VMID:      0,
		Direction: "IN",
		Proto:     "TCP",
		Src:       "198.51.100.1",
		Dst:       "192.168.1.120",
		DPT:       8006,
	}
	res2 := testClassifyHelper(ev2, policy, "ru")
	if res2.RiskLevel != LevelInfo {
		t.Errorf("expected INFO, got %s (%s)", res2.RiskLevel, res2.Label)
	}

	// 3. LXC Whitelisted OUT to port 22 -> INFO
	ev3 := IptablesEvent{
		VMID:      101,
		Direction: "OUT",
		Proto:     "TCP",
		Src:       "192.168.1.101",
		Dst:       "198.51.100.42",
		DPT:       22,
	}
	res3 := testClassifyHelper(ev3, policy, "ru")
	if res3.RiskLevel != LevelInfo {
		t.Errorf("expected INFO for whitelisted LXC, got %s (%s)", res3.RiskLevel, res3.Label)
	}

	// 4. Normal LXC OUT to sensitive port 22 -> WARNING
	ev4 := IptablesEvent{
		VMID:      102,
		Direction: "OUT",
		Proto:     "TCP",
		Src:       "192.168.1.102",
		Dst:       "198.51.100.42",
		DPT:       22,
	}
	res4 := testClassifyHelper(ev4, policy, "ru")
	if res4.RiskLevel != LevelWarning {
		t.Errorf("expected WARNING for non-whitelisted LXC SSH, got %s (%s)", res4.RiskLevel, res4.Label)
	}

	// 5. VPN Client OUT to sensitive port -> CRITICAL
	ev5 := IptablesEvent{
		VMID:           100,
		Direction:      "OUT",
		Proto:          "TCP",
		Src:            "10.0.0.100",
		Dst:            "198.51.100.42",
		DPT:            22,
		IsLocalProcess: false,
	}
	res5 := testClassifyHelper(ev5, policy, "ru")
	if res5.RiskLevel != LevelCritical {
		t.Errorf("expected CRITICAL for VPN client attack, got %s (%s)", res5.RiskLevel, res5.Label)
	}
}

func TestFindRealVPNClientIP(t *testing.T) {
	conntrackDump := `
ipv4     2 tcp      6 431999 ESTABLISHED src=192.168.1.55 dst=1.1.1.1 sport=54321 dport=443 src=1.1.1.1 dst=10.0.0.100 sport=443 dport=54321 [ASSURED] mark=0 use=1
ipv4     2 udp     17 29 src=192.168.1.77 dst=8.8.8.8 sport=33333 dport=53 src=8.8.8.8 dst=10.0.0.100 sport=53 dport=33333 mark=0 use=1
`
	// Match TCP flow: container_ip=10.0.0.100, dst_ip=1.1.1.1, sport=54321, dpt=443
	clientIP := FindRealVPNClientIP("tcp", "10.0.0.100", "1.1.1.1", 54321, 443, conntrackDump)
	if clientIP != "192.168.1.55" {
		t.Errorf("expected 192.168.1.55, got %q", clientIP)
	}

	// Match UDP flow: container_ip=10.0.0.100, dst_ip=8.8.8.8, sport=33333, dpt=53
	clientUDP := FindRealVPNClientIP("udp", "10.0.0.100", "8.8.8.8", 33333, 53, conntrackDump)
	if clientUDP != "192.168.1.77" {
		t.Errorf("expected 192.168.1.77, got %q", clientUDP)
	}
}

func TestRouterParsers(t *testing.T) {
	ctLine := "[NEW] tcp      6 120 SYN_SENT src=192.168.1.100 dst=5.255.255.242 sport=33296 dport=443 [UNREPLIED]"
	ctEv := ParseRouterConntrackLine(ctLine)
	if ctEv == nil {
		t.Fatalf("expected router conntrack event")
	}
	if ctEv.SrcIP != "192.168.1.100" || ctEv.DstHost != "5.255.255.242" || ctEv.Proto != "TCP" || ctEv.SrcPort != 33296 || ctEv.DstPort != 443 {
		t.Errorf("unexpected router conntrack event: %+v", ctEv)
	}

	iptLine := "ROUTER-IPS: IN=br-lan OUT= SRC=192.168.1.150 DST=203.0.113.100 PROTO=TCP SPT=54321 DPT=22"
	iptEv := ParseRouterIptablesLine(iptLine)
	if iptEv == nil {
		t.Fatalf("expected router iptables event")
	}
	if iptEv.SrcIP != "192.168.1.150" || iptEv.DstHost != "203.0.113.100" || iptEv.Proto != "TCP" || iptEv.SrcPort != 54321 || iptEv.DstPort != 22 {
		t.Errorf("unexpected router iptables event: %+v", iptEv)
	}
}

func TestRouterThreatDetector_Behavioral(t *testing.T) {
	detector := &RouterThreatDetector{
		history:      make(map[string][]RouterConnectionRecord),
		window:       10 * time.Minute,
		scanLimit:    3,
		burstLimit1m: 10,
		burstLimit3m: 15,
	}

	src := "192.168.1.88"

	// 1. Single access to sensitive port (e.g. port 22) -> Flagged as sensitive_port threat for alert, but not autobanned
	ev1 := &RouterEvent{SrcIP: src, DstHost: "192.0.2.10", DstPort: 22, Proto: "TCP"}
	detector.Evaluate(ev1)
	if !ev1.IsThreat || ev1.ShouldAutoBan || ev1.ThreatType != "sensitive_port" {
		t.Errorf("expected sensitive_port alert without autoban, got threat=%v, ban=%v, type=%s", ev1.IsThreat, ev1.ShouldAutoBan, ev1.ThreatType)
	}

	// 2. Horizontal scan (connecting to 3 distinct IPs on sensitive port) -> Auto-ban
	ev2 := &RouterEvent{SrcIP: src, DstHost: "192.0.2.20", DstPort: 22, Proto: "TCP"}
	detector.Evaluate(ev2)
	ev3 := &RouterEvent{SrcIP: src, DstHost: "192.0.2.30", DstPort: 22, Proto: "TCP"}
	detector.Evaluate(ev3)
	if !ev3.IsThreat || !ev3.ShouldAutoBan || ev3.ThreatType != "horizontal_scan" {
		t.Errorf("expected horizontal_scan autoban, got %+v", ev3)
	}

	// 3. Vertical brute-force on single target (10 connections in burst) -> Auto-ban
	detector.mu.Lock()
	delete(detector.history, src)
	detector.mu.Unlock()

	for i := 0; i < 9; i++ {
		ev := &RouterEvent{SrcIP: src, DstHost: "198.51.100.50", DstPort: 22, Proto: "TCP"}
		detector.Evaluate(ev)
		if ev.ShouldAutoBan {
			t.Errorf("premature ban at attempt %d", i)
		}
	}
	ev10 := &RouterEvent{SrcIP: src, DstHost: "198.51.100.50", DstPort: 22, Proto: "TCP"}
	detector.Evaluate(ev10)
	if !ev10.IsThreat || !ev10.ShouldAutoBan || ev10.ThreatType != "vertical_bruteforce" {
		t.Errorf("expected vertical_bruteforce autoban, got %+v", ev10)
	}

	// 4. Exploit port (Telnet 23) -> Exploit threat
	evTelnet := &RouterEvent{SrcIP: "192.168.1.99", DstHost: "203.0.113.1", DstPort: 23, Proto: "TCP"}
	detector.Evaluate(evTelnet)
	if !evTelnet.IsThreat || evTelnet.ThreatType != "exploit_port" {
		t.Errorf("expected exploit_port threat, got %+v", evTelnet)
	}

	// 5. Normal HTTPS (443) traffic -> Always safe, never flagged as threat even after other events
	evHTTPS := &RouterEvent{SrcIP: src, DstHost: "198.51.100.44", DstPort: 443, Proto: "TCP"}
	detector.Evaluate(evHTTPS)
	if evHTTPS.IsThreat || evHTTPS.ShouldAutoBan {
		t.Errorf("expected normal HTTPS (443) to never be a threat, got isThreat=%v, autoban=%v", evHTTPS.IsThreat, evHTTPS.ShouldAutoBan)
	}
}

func TestRouterThreatDetector_ConfigurableAndPerTargetLimit(t *testing.T) {
	detector := &RouterThreatDetector{
		history:          make(map[string][]RouterConnectionRecord),
		window:           10 * time.Minute,
		scanLimit:        4,
		burstLimit1m:     20,
		burstLimit3m:     30,
		targetBruteLimit: 4, // 4 attempts to same target in window = ban
	}

	src := "192.168.1.150"
	dst := "192.0.2.80"

	// 1. Attempts 1..3 to port 22: Alert only, no autoban
	for i := 1; i <= 3; i++ {
		ev := &RouterEvent{SrcIP: src, DstHost: dst, DstPort: 22, Proto: "TCP"}
		detector.Evaluate(ev)
		if !ev.IsThreat || ev.ShouldAutoBan {
			t.Fatalf("attempt %d should be alert only without autoban, got: %+v", i, ev)
		}
	}

	// 2. Attempt 4 to same target: Reaches targetBruteLimit (4) -> Auto-ban!
	ev4 := &RouterEvent{SrcIP: src, DstHost: dst, DstPort: 22, Proto: "TCP"}
	detector.Evaluate(ev4)
	if !ev4.IsThreat || !ev4.ShouldAutoBan || ev4.ThreatType != "vertical_bruteforce" {
		t.Fatalf("attempt 4 should reach targetBruteLimit and trigger autoban, got: %+v", ev4)
	}

	// 3. Test dynamic Configure & SetSensitivePorts (e.g. adding custom DB port 5432)
	detector.Configure(5, 10, 15, 3, 5*time.Minute, []int{5432})
	if !detector.IsSensitivePort(5432) {
		t.Errorf("expected port 5432 to be classified as sensitive after Configure")
	}

	dbSrc := "192.168.1.151"
	evDB1 := &RouterEvent{SrcIP: dbSrc, DstHost: "192.0.2.99", DstPort: 5432, Proto: "TCP"}
	detector.Evaluate(evDB1)
	if !evDB1.IsThreat || evDB1.ThreatType != "sensitive_port" {
		t.Fatalf("expected custom sensitive port 5432 to be flagged as sensitive_port threat, got: %+v", evDB1)
	}
}


