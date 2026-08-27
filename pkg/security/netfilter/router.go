package netfilter

import (
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	routerConntrackSrcRegex   = regexp.MustCompile(`src=([^\s]+)`)
	routerConntrackDstRegex   = regexp.MustCompile(`dst=([^\s]+)`)
	routerConntrackProtoRegex = regexp.MustCompile(`(?i)\b(tcp|udp)\b`)
	routerConntrackSptRegex   = regexp.MustCompile(`sport=(\d+)`)
	routerConntrackDptRegex   = regexp.MustCompile(`dport=(\d+)`)

	routerIptablesSrcRegex   = regexp.MustCompile(`SRC=([^\s]+)`)
	routerIptablesDstRegex   = regexp.MustCompile(`DST=([^\s]+)`)
	routerIptablesProtoRegex = regexp.MustCompile(`PROTO=([^\s]+)`)
	routerIptablesSptRegex   = regexp.MustCompile(`SPT=(\d+)`)
	routerIptablesDptRegex   = regexp.MustCompile(`DPT=(\d+)`)

	// Sensitive ports monitored by default
	defaultSensitivePorts = map[int]bool{
		22:   true, // SSH
		8006: true, // Proxmox VE Web GUI
		2222: true, // Alt SSH / Direct Admin
		3389: true, // RDP
		8443: true, // Alt HTTPS
	}

	// Known malware / exploit / worm ports
	dangerousExploitPorts = map[int]string{
		23:   "Telnet (Брутфорс IoT/Mirai)",
		2323: "Mirai Telnet",
		445:  "SMB (EternalBlue / WannaCry)",
		135:  "MS RPC Exploit",
		137:  "NetBIOS Name Service",
		138:  "NetBIOS Datagram",
		139:  "NetBIOS Session",
		1433: "MS SQL Brute-Force",
		5555: "ADB Backdoor / Miner",
	}
)

// RouterConnectionRecord stores an individual connection event for behavioral evaluation.
type RouterConnectionRecord struct {
	Timestamp time.Time
	DstHost   string
	DstPort   int
	Proto     string
}

// RouterThreatDetector implements behavioral IDS/IPS analysis in pure Go with zero whitelists.
type RouterThreatDetector struct {
	mu           sync.Mutex
	history      map[string][]RouterConnectionRecord // srcIP -> records
	window       time.Duration                       // default 10 min
	scanLimit    int                                 // default 3 distinct target IPs
	burstLimit1m int                                 // default 10 connections / min to single target
	burstLimit3m int                                 // default 15 connections / 3 min to single target
}

var (
	defaultDetectorOnce sync.Once
	defaultDetector     *RouterThreatDetector
)

// GetDefaultRouterThreatDetector returns the singleton in-memory threat detector instance.
func GetDefaultRouterThreatDetector() *RouterThreatDetector {
	defaultDetectorOnce.Do(func() {
		defaultDetector = &RouterThreatDetector{
			history:      make(map[string][]RouterConnectionRecord),
			window:       10 * time.Minute,
			scanLimit:    3,
			burstLimit1m: 10,
			burstLimit3m: 15,
		}
	})
	return defaultDetector
}

// RouterEvent represents a connection event parsed from router conntrack or iptables logs.
type RouterEvent struct {
	SrcIP         string `json:"src_ip"`
	DstHost       string `json:"dst_host"`
	Proto         string `json:"proto"`
	SrcPort       int    `json:"src_port"`
	DstPort       int    `json:"dst_port"`
	IsThreat      bool   `json:"is_threat"`
	ShouldAutoBan bool   `json:"should_autoban"`
	ThreatType    string `json:"threat_type,omitempty"` // "exploit_port", "horizontal_scan", "vertical_bruteforce", "gateway_attack", ""
	Reason        string `json:"reason,omitempty"`
	DistinctHosts int    `json:"distinct_hosts,omitempty"`
	BurstRate1m   int    `json:"burst_rate_1m,omitempty"`
	RawLine       string `json:"raw_line,omitempty"`
}

// IsPrivateOrLocalIP checks if an IP string is an RFC 1918 private address or loopback.
func IsPrivateOrLocalIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	return ip.IsPrivate()
}

// Evaluate performs behavioral analysis on the connection event without relying on static whitelists.
func (d *RouterThreatDetector) Evaluate(ev *RouterEvent) {
	d.mu.Lock()
	defer d.mu.Unlock()

	now := time.Now()
	// Record event
	d.history[ev.SrcIP] = append(d.history[ev.SrcIP], RouterConnectionRecord{
		Timestamp: now,
		DstHost:   ev.DstHost,
		DstPort:   ev.DstPort,
		Proto:     ev.Proto,
	})

	// Prune old entries outside sliding window
	cutoff := now.Add(-d.window)
	var active []RouterConnectionRecord
	for _, rec := range d.history[ev.SrcIP] {
		if rec.Timestamp.After(cutoff) {
			active = append(active, rec)
		}
	}
	d.history[ev.SrcIP] = active

	// 1. Check dangerous exploit ports (Telnet, SMB, Mirai, ADB)
	if desc, isExploit := dangerousExploitPorts[ev.DstPort]; isExploit {
		exploitCount := 0
		for _, rec := range active {
			if _, ok := dangerousExploitPorts[rec.DstPort]; ok {
				exploitCount++
			}
		}
		ev.IsThreat = true
		ev.ThreatType = "exploit_port"
		if exploitCount >= 3 {
			ev.ShouldAutoBan = true
			ev.Reason = "Эксплойт-активность на опасный порт " + strconv.Itoa(ev.DstPort) + " (" + desc + ")"
		} else {
			ev.ShouldAutoBan = false
			ev.Reason = "Попытка доступа к эксплойт-порту " + strconv.Itoa(ev.DstPort) + " (" + desc + ")"
		}
		return
	}

	// 2. Check if destination is the local router / gateway
	if ev.DstHost == "192.168.1.1" || ev.DstHost == "127.0.0.1" || strings.HasPrefix(ev.DstHost, "192.168.") {
		if defaultSensitivePorts[ev.DstPort] {
			gatewayCount := 0
			for _, rec := range active {
				if (rec.DstHost == "192.168.1.1" || rec.DstHost == "127.0.0.1") && defaultSensitivePorts[rec.DstPort] {
					gatewayCount++
				}
			}
			if gatewayCount >= 3 {
				ev.IsThreat = true
				ev.ShouldAutoBan = true
				ev.ThreatType = "gateway_attack"
				ev.Reason = "Атака на сервисы шлюза (порт " + strconv.Itoa(ev.DstPort) + " " + ev.Proto + ")"
				return
			}
		}
	}

	// Filter sensitive port connections in active window
	var sensitiveConns []RouterConnectionRecord
	distinctMap := make(map[string]bool)
	sameTarget1m := 0
	sameTarget3m := 0
	cutoff1m := now.Add(-1 * time.Minute)
	cutoff3m := now.Add(-3 * time.Minute)

	for _, rec := range active {
		if defaultSensitivePorts[rec.DstPort] {
			sensitiveConns = append(sensitiveConns, rec)
			distinctMap[rec.DstHost] = true
			if rec.DstHost == ev.DstHost && rec.DstPort == ev.DstPort {
				if rec.Timestamp.After(cutoff1m) {
					sameTarget1m++
				}
				if rec.Timestamp.After(cutoff3m) {
					sameTarget3m++
				}
			}
		}
	}

	ev.DistinctHosts = len(distinctMap)
	ev.BurstRate1m = sameTarget1m

	// 3. Horizontal network scan: 3+ distinct destination IPs on sensitive ports in 10 min
	if len(distinctMap) >= d.scanLimit {
		ev.IsThreat = true
		ev.ShouldAutoBan = true
		ev.ThreatType = "horizontal_scan"
		ev.Reason = "Массовое сканирование сети (" + strconv.Itoa(len(distinctMap)) + " целевых IP на порт " + strconv.Itoa(ev.DstPort) + ")"
		return
	}

	// 4. Vertical brute-force on single target: 10+ connections in 60s or 15+ in 180s
	if sameTarget1m >= d.burstLimit1m {
		ev.IsThreat = true
		ev.ShouldAutoBan = true
		ev.ThreatType = "vertical_bruteforce"
		ev.Reason = "Брутфорс SSH/портов (" + strconv.Itoa(sameTarget1m) + " подкл/мин к " + ev.DstHost + ":" + strconv.Itoa(ev.DstPort) + ")"
		return
	}
	if sameTarget3m >= d.burstLimit3m {
		ev.IsThreat = true
		ev.ShouldAutoBan = true
		ev.ThreatType = "vertical_bruteforce"
		ev.Reason = "Брутфорс SSH/портов (" + strconv.Itoa(sameTarget3m) + " подкл/3мин к " + ev.DstHost + ":" + strconv.Itoa(ev.DstPort) + ")"
		return
	}

	// 5. Normal single-host traffic (1-4 connections): Not a threat
	ev.IsThreat = false
	ev.ShouldAutoBan = false
}

// ParseRouterConntrackLine parses a router conntrack event line containing "[NEW]" and performs threat evaluation.
func ParseRouterConntrackLine(line string) *RouterEvent {
	if !strings.Contains(line, "[NEW]") {
		return nil
	}

	srcM := routerConntrackSrcRegex.FindStringSubmatch(line)
	dstM := routerConntrackDstRegex.FindStringSubmatch(line)
	protoM := routerConntrackProtoRegex.FindStringSubmatch(line)
	sptM := routerConntrackSptRegex.FindStringSubmatch(line)
	dptM := routerConntrackDptRegex.FindStringSubmatch(line)

	if len(srcM) < 2 || len(dstM) < 2 || len(protoM) < 2 || len(sptM) < 2 || len(dptM) < 2 {
		return nil
	}

	spt, _ := strconv.Atoi(sptM[1])
	dpt, _ := strconv.Atoi(dptM[1])

	ev := &RouterEvent{
		SrcIP:   srcM[1],
		DstHost: dstM[1],
		Proto:   strings.ToUpper(protoM[1]),
		SrcPort: spt,
		DstPort: dpt,
		RawLine: strings.TrimSpace(line),
	}

	GetDefaultRouterThreatDetector().Evaluate(ev)
	return ev
}

// ParseRouterIptablesLine parses a router iptables/nftables log line containing "ROUTER-IPS:" and performs threat evaluation.
func ParseRouterIptablesLine(line string) *RouterEvent {
	if !strings.Contains(line, "ROUTER-IPS:") {
		return nil
	}

	srcM := routerIptablesSrcRegex.FindStringSubmatch(line)
	dstM := routerIptablesDstRegex.FindStringSubmatch(line)
	protoM := routerIptablesProtoRegex.FindStringSubmatch(line)
	sptM := routerIptablesSptRegex.FindStringSubmatch(line)
	dptM := routerIptablesDptRegex.FindStringSubmatch(line)

	if len(srcM) < 2 || len(dstM) < 2 || len(protoM) < 2 || len(sptM) < 2 || len(dptM) < 2 {
		return nil
	}

	spt, _ := strconv.Atoi(sptM[1])
	dpt, _ := strconv.Atoi(dptM[1])

	ev := &RouterEvent{
		SrcIP:   srcM[1],
		DstHost: dstM[1],
		Proto:   strings.ToUpper(protoM[1]),
		SrcPort: spt,
		DstPort: dpt,
		RawLine: strings.TrimSpace(line),
	}

	GetDefaultRouterThreatDetector().Evaluate(ev)
	return ev
}

