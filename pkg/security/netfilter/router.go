package netfilter

import (
	"regexp"
	"strconv"
	"strings"
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
)

// RouterEvent represents a connection event parsed from router conntrack or iptables logs.
type RouterEvent struct {
	SrcIP   string `json:"src_ip"`
	DstHost string `json:"dst_host"`
	Proto   string `json:"proto"`
	SrcPort int    `json:"src_port"`
	DstPort int    `json:"dst_port"`
	RawLine string `json:"raw_line,omitempty"`
}

// ParseRouterConntrackLine parses a router conntrack event line containing "[NEW]".
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

	return &RouterEvent{
		SrcIP:   srcM[1],
		DstHost: dstM[1],
		Proto:   strings.ToUpper(protoM[1]),
		SrcPort: spt,
		DstPort: dpt,
		RawLine: strings.TrimSpace(line),
	}
}

// ParseRouterIptablesLine parses a router iptables/nftables log line containing "ROUTER-IPS:".
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

	return &RouterEvent{
		SrcIP:   srcM[1],
		DstHost: dstM[1],
		Proto:   strings.ToUpper(protoM[1]),
		SrcPort: spt,
		DstPort: dpt,
		RawLine: strings.TrimSpace(line),
	}
}
