package xray

import (
	"fmt"
	"net"
	"strings"
	"github.com/blackalex1/sentinel-core/pkg/ast"
)

// BuildXrayRouting creates the routing block for Xray-core
func BuildXrayRouting(spec *ast.ConfigSpec) map[string]interface{} {
	rules := make([]map[string]interface{}, 0)

	// Ensure DNS queries (port 53) are routed to Xray's DNS engine
	rules = append(rules, map[string]interface{}{
		"type":        "field",
		"outboundTag": "dns-out",
		"port":        "53",
		"network":     "udp,tcp",
	})

	if srvRule := buildDirectServerRule(spec); srvRule != nil {
		rules = append(rules, srvRule)
	}

	// Drop link-local, multicast, broadcast, and NetBIOS in desktop TUN mode to avoid Windows routing loops
	if spec.ClientInbound != nil && spec.ClientInbound.Mode == ast.InboundModeDesktopTun {
		rules = append(rules,
			map[string]interface{}{
				"type":        "field",
				"outboundTag": "block",
				"ip": []string{
					"169.254.0.0/16",
					"224.0.0.0/4",
					"255.255.255.255/32",
					"fe80::/10",
					"ff00::/8",
					"::1",
				},
			},
			map[string]interface{}{
				"type":        "field",
				"outboundTag": "block",
				"port":        "137,138,1900,5353",
				"network":     "udp",
			},
		)
	}

	if spec.Routing != nil {
		for _, r := range spec.Routing.Rules {
			if !r.IsEnabled() {
				continue
			}
			rules = append(rules, compileXrayRoutingRule(r, spec)...)
		}
	}

	return map[string]interface{}{
		"domainStrategy": "IPIfNonMatch",
		"rules":          rules,
	}
}

func buildDirectServerRule(spec *ast.ConfigSpec) map[string]interface{} {
	var serverAddr string
	if len(spec.ChainNodes) >= 2 && spec.ChainNodes[0] != nil {
		serverAddr = spec.ChainNodes[0].Address
	} else if spec.ServerNode != nil {
		serverAddr = spec.ServerNode.Address
	}
	if serverAddr == "" {
		return nil
	}
	rule := map[string]interface{}{
		"type":        "field",
		"outboundTag": "direct",
	}
	if net.ParseIP(serverAddr) != nil {
		rule["ip"] = []string{serverAddr}
	} else {
		rule["domain"] = []string{serverAddr}
	}
	return rule
}

func resolveXrayOutboundTag(r ast.RoutingRule, spec *ast.ConfigSpec) string {
	if r.OutboundTag != "" {
		return r.OutboundTag
	}
	switch r.Action {
	case ast.ActionProxy:
		if len(spec.ChainNodes) >= 2 {
			last := spec.ChainNodes[len(spec.ChainNodes)-1]
			if last.Name != "" {
				return fmt.Sprintf("chain-%d-%s", len(spec.ChainNodes), last.Name)
			}
			return fmt.Sprintf("chain-hop-%d", len(spec.ChainNodes))
		}
		if spec.ServerNode != nil && spec.ServerNode.Name != "" {
			return spec.ServerNode.Name
		}
		return "proxy"
	case ast.ActionDirect:
		return "direct"
	case ast.ActionBlock:
		return "block"
	default:
		return string(r.Action)
	}
}

func splitXrayProtocols(protocols []string) (networks, allApps, nonBTApps []string, hasBT bool) {
	for _, p := range protocols {
		pLower := strings.ToLower(p)
		if pLower == "tcp" || pLower == "udp" {
			networks = append(networks, pLower)
			continue
		}
		allApps = append(allApps, pLower)
		if pLower == "bittorrent" {
			hasBT = true
		} else {
			nonBTApps = append(nonBTApps, pLower)
		}
	}
	return networks, allApps, nonBTApps, hasBT
}

func compileXrayRoutingRule(r ast.RoutingRule, spec *ast.ConfigSpec) []map[string]interface{} {
	ips := append([]string(nil), r.IPs...)
	if r.IPVersion == 6 {
		hasV6 := false
		for _, ip := range ips {
			if ip == "::/0" {
				hasV6 = true
				break
			}
		}
		if !hasV6 {
			ips = append(ips, "::/0")
		}
	}

	tag := resolveXrayOutboundTag(r, spec)
	networks, allAppProtocols, nonBitTorrentAppProtocols, hasBitTorrent := splitXrayProtocols(r.Protocols)

	createBaseRule := func(appProtos []string) map[string]interface{} {
		ruleMap := map[string]interface{}{
			"type":        "field",
			"outboundTag": tag,
		}
		if len(r.Ports) > 0 {
			ruleMap["port"] = strings.Join(r.Ports, ",")
		}
		if len(networks) > 0 {
			ruleMap["network"] = strings.Join(networks, ",")
		}
		if len(appProtos) > 0 {
			ruleMap["protocol"] = append([]string(nil), appProtos...)
		}
		if len(r.Users) > 0 {
			ruleMap["user"] = r.Users
		} else if len(r.PackageUIDs) > 0 {
			ruleMap["user"] = r.PackageUIDs
		} else if len(r.ProcessNames) > 0 {
			ruleMap["user"] = r.ProcessNames
		}
		if len(r.InboundTags) > 0 {
			ruleMap["inboundTag"] = r.InboundTags
		}
		return ruleMap
	}

	var cleanDomains []string
	for _, d := range r.Domains {
		if d == "geosite:ru" {
			cleanDomains = append(cleanDomains, "geosite:category-ru")
		} else {
			cleanDomains = append(cleanDomains, d)
		}
	}

	hasDomains := len(cleanDomains) > 0
	hasIPs := len(ips) > 0
	splitBitTorrent := hasBitTorrent && (hasDomains || hasIPs)

	var out []map[string]interface{}
	ruleAppProtos := allAppProtocols
	if splitBitTorrent {
		out = append(out, createBaseRule([]string{"bittorrent"}))
		ruleAppProtos = nonBitTorrentAppProtocols
	}
	if hasDomains {
		domainRule := createBaseRule(ruleAppProtos)
		domainRule["domain"] = cleanDomains
		out = append(out, domainRule)
	}
	if hasIPs {
		ipRule := createBaseRule(ruleAppProtos)
		ipRule["ip"] = ips
		out = append(out, ipRule)
	}
	if !hasDomains && !hasIPs && !splitBitTorrent {
		baseRule := createBaseRule(ruleAppProtos)
		if len(baseRule) > 2 {
			out = append(out, baseRule)
		}
	}
	return out
}
