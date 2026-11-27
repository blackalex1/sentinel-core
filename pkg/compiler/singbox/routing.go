package singbox

import (
	"fmt"
	"strconv"
	"strings"
	"github.com/blackalex1/sentinel-core/pkg/ast"
)

func isSingbox114OrNewer(version string) bool {
	if version == "" {
		return true // Default to modern sing-box (1.14+)
	}
	v := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(version)), "v")
	if strings.HasPrefix(v, "1.10") || strings.HasPrefix(v, "1.11") || strings.HasPrefix(v, "1.12") || strings.HasPrefix(v, "1.13") {
		return false
	}
	return true
}

// BuildSingBoxRoute generates the route object and any required top-level http_clients for Sing-box
func BuildSingBoxRoute(spec *ast.ConfigSpec, isV112 bool) (map[string]interface{}, []map[string]interface{}) {
	isV114 := isSingbox114OrNewer(spec.CoreVersion)
	activeMirror, isDirect := GetActiveRuleMirrorWithStatus()
	var httpClients []map[string]interface{}

	route := map[string]interface{}{
		"auto_detect_interface":   true,
		"default_domain_resolver": "dns-direct",
	}
	if spec.ClientInbound != nil && spec.ClientInbound.Mode == ast.InboundModeDesktopTun {
		route["find_process"] = true
	}

	rules := make([]map[string]interface{}, 0)
	ruleSetMap := make(map[string]map[string]interface{})

	if spec.ClientInbound != nil {
		rules = append(rules,
			map[string]interface{}{"action": "hijack-dns", "port": uint16(53)},
			map[string]interface{}{"action": "hijack-dns", "protocol": "dns"},
		)
	}

	if sniffRule := buildSniffRule(spec); sniffRule != nil {
		rules = append(rules, sniffRule)
	}
	rules = append(rules, buildInboundResolveRules(spec)...)

	// Evaluate Clash Direct mode before custom/inbound rules so toggling Direct mode isn't shadowed by inbound catch-alls.
	if spec.ClashAPIAddress != "" {
		rules = append(rules, map[string]interface{}{
			"clash_mode": "Direct",
			"outbound":   "direct",
		})
	}

	downloadDetour, finalTag := resolveDownloadDetourAndFinal(spec, isDirect)
	if finalTag != "" {
		route["final"] = finalTag
	}

	if spec.Routing != nil {
		for _, r := range spec.Routing.Rules {
			if !r.IsEnabled() {
				continue
			}
			rules = append(rules, compileSingBoxRoutingRule(r, spec, activeMirror, downloadDetour, isV114, ruleSetMap)...)
		}
	}

	route["rules"] = rules

	if len(ruleSetMap) > 0 {
		ruleSets := make([]map[string]interface{}, 0, len(ruleSetMap))
		for _, rs := range ruleSetMap {
			ruleSets = append(ruleSets, rs)
		}
		route["rule_set"] = ruleSets

		if isV114 {
			route["default_http_client"] = "rules-client"
			clientObj := map[string]interface{}{"tag": "rules-client"}
			if downloadDetour != "direct" && downloadDetour != "" {
				clientObj["detour"] = downloadDetour
			}
			httpClients = append(httpClients, clientObj)
		}
	}

	return route, httpClients
}

func buildSniffRule(spec *ast.ConfigSpec) map[string]interface{} {
	var sniffingInbounds []string
	if spec.ClientInbound != nil && (spec.ClientInbound.Mode == ast.InboundModeDesktopTun || spec.ClientInbound.Mode == ast.InboundModeMobileVpn) {
		sniffingInbounds = append(sniffingInbounds, "tun-in")
	}
	for _, sb := range spec.ServerInbounds {
		sniffEnabled := true
		if len(sb.Sniffing) > 0 {
			if enabled, ok := sb.Sniffing["enabled"].(bool); ok {
				sniffEnabled = enabled
			}
		}
		if sniffEnabled {
			tag := sb.Tag
			if tag == "" {
				tag = fmt.Sprintf("inbound-%d", sb.Port)
			}
			sniffingInbounds = append(sniffingInbounds, tag)
		}
	}
	if len(sniffingInbounds) == 0 {
		return nil
	}
	rule := map[string]interface{}{"action": "sniff"}
	if len(sniffingInbounds) == 1 {
		rule["inbound"] = sniffingInbounds[0]
	} else {
		rule["inbound"] = sniffingInbounds
	}
	return rule
}

func buildInboundResolveRules(spec *ast.ConfigSpec) []map[string]interface{} {
	var rules []map[string]interface{}
	for _, sb := range spec.ServerInbounds {
		if sb.RawSettings == nil {
			continue
		}
		ds, ok := sb.RawSettings["domain_strategy"].(string)
		if !ok || ds == "" {
			continue
		}
		tag := sb.Tag
		if tag == "" {
			tag = fmt.Sprintf("inbound-%d", sb.Port)
		}
		rules = append(rules, map[string]interface{}{
			"inbound":  tag,
			"action":   "resolve",
			"strategy": ds,
		})
	}
	return rules
}

func resolveDownloadDetourAndFinal(spec *ast.ConfigSpec, isDirect bool) (string, string) {
	if len(spec.ChainNodes) >= 2 {
		lastNode := spec.ChainNodes[len(spec.ChainNodes)-1]
		exitTag := fmt.Sprintf("chain-hop-%d", len(spec.ChainNodes))
		if lastNode.Name != "" {
			exitTag = fmt.Sprintf("chain-%d-%s", len(spec.ChainNodes), lastNode.Name)
		}
		if !isDirect {
			return exitTag, exitTag
		}
		return "direct", exitTag
	}
	if spec.ServerNode != nil {
		if !isDirect {
			if spec.ServerNode.Name != "" {
				return spec.ServerNode.Name, ""
			}
			return "proxy", ""
		}
		return "direct", ""
	}
	if spec.Routing == nil {
		return "direct", ""
	}

	detour := "direct"
	for _, ob := range spec.Routing.Outbounds {
		tag, _ := ob["tag"].(string)
		obType, _ := ob["type"].(string)
		if tag == "" || tag == "direct" || tag == "block" || obType == "direct" || obType == "block" {
			continue
		}
		sMap := parseMapOrJSON(ob["settings"])
		validBackups, _, _, _ := ExtractSingboxFallbackSettings(sMap, tag)
		if obType == "urltest" || obType == "selector" || len(validBackups) > 0 {
			return tag, ""
		}
		if detour == "direct" {
			detour = tag
		}
	}
	if detour == "direct" {
		for _, r := range spec.Routing.Rules {
			if r.IsEnabled() && r.OutboundTag != "" && r.OutboundTag != "direct" && r.OutboundTag != "block" {
				return r.OutboundTag, ""
			}
		}
	}
	return detour, ""
}

func resolveSingBoxRuleOutbound(r ast.RoutingRule, spec *ast.ConfigSpec) string {
	outbound := string(r.Action)
	if r.OutboundTag != "" {
		outbound = r.OutboundTag
	} else if r.Action == ast.ActionProxy {
		if len(spec.ChainNodes) >= 2 {
			lastNode := spec.ChainNodes[len(spec.ChainNodes)-1]
			outbound = fmt.Sprintf("chain-hop-%d", len(spec.ChainNodes))
			if lastNode.Name != "" {
				outbound = fmt.Sprintf("chain-%d-%s", len(spec.ChainNodes), lastNode.Name)
			}
		} else if spec.ServerNode != nil && spec.ServerNode.Name != "" {
			outbound = spec.ServerNode.Name
		} else {
			outbound = "proxy"
		}
	}
	if outbound == "blocked" {
		return "block"
	}
	return outbound
}

func classifySingBoxProtocols(protocols []string) (networks, allApps, nonBTApps []string, hasBT bool) {
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

func applySingBoxPorts(base map[string]interface{}, ports []string) {
	if len(ports) == 0 {
		return
	}
	var intPorts []uint16
	var rangePorts []string
	for _, p := range ports {
		pTrim := strings.TrimSpace(p)
		if num, err := strconv.ParseUint(pTrim, 10, 16); err == nil && num > 0 {
			intPorts = append(intPorts, uint16(num))
		} else if pTrim != "" {
			rangePorts = append(rangePorts, pTrim)
		}
	}
	if len(intPorts) == 1 && len(rangePorts) == 0 {
		base["port"] = intPorts[0]
	} else if len(intPorts) > 0 {
		base["port"] = intPorts
	}
	if len(rangePorts) > 0 {
		base["port_range"] = rangePorts
	}
}

func ensureRemoteRuleSet(ruleSetMap map[string]map[string]interface{}, tag, urlPattern, downloadDetour string, isV114 bool) {
	if _, exists := ruleSetMap[tag]; exists {
		return
	}
	rs := map[string]interface{}{
		"tag":    tag,
		"type":   "remote",
		"format": "binary",
		"url":    fmt.Sprintf(urlPattern, tag),
	}
	if isV114 {
		rs["http_client"] = "rules-client"
		rs["initial_path"] = fmt.Sprintf("rules/%s.srs", tag)
	} else {
		rs["download_detour"] = downloadDetour
	}
	ruleSetMap[tag] = rs
}

func compileSingBoxRoutingRule(
	r ast.RoutingRule,
	spec *ast.ConfigSpec,
	activeMirror RuleMirror,
	downloadDetour string,
	isV114 bool,
	ruleSetMap map[string]map[string]interface{},
) []map[string]interface{} {
	outbound := resolveSingBoxRuleOutbound(r, spec)
	networks, allAppProtocols, nonBitTorrentAppProtocols, hasBitTorrent := classifySingBoxProtocols(r.Protocols)

	createBaseRule := func(appProtos []string) map[string]interface{} {
		base := map[string]interface{}{"outbound": outbound}
		if r.IPVersion != 0 {
			base["ip_version"] = r.IPVersion
		}
		if len(r.InboundTags) > 0 {
			base["inbound"] = r.InboundTags
		}
		applySingBoxPorts(base, r.Ports)
		if len(networks) > 0 {
			base["network"] = networks
		}
		if len(appProtos) > 0 {
			base["protocol"] = append([]string(nil), appProtos...)
		}
		if len(r.Users) > 0 {
			base["auth_user"] = r.Users
		}
		if len(r.PackageUIDs) > 0 {
			base["user_id"] = r.PackageUIDs
		}
		if len(r.ProcessNames) > 0 {
			base["process_name"] = r.ProcessNames
		}
		return base
	}

	var domainRuleSets, regexList, suffixDomains, exactDomains, keywordList []string
	for _, d := range r.Domains {
		switch {
		case strings.HasPrefix(d, "geosite:"):
			tag := "geosite-" + strings.TrimPrefix(d, "geosite:")
			domainRuleSets = append(domainRuleSets, tag)
			ensureRemoteRuleSet(ruleSetMap, tag, activeMirror.GeositePattern, downloadDetour, isV114)
		case strings.HasPrefix(d, "regexp:"):
			regexList = append(regexList, strings.TrimPrefix(d, "regexp:"))
		case strings.HasPrefix(d, "regex:"):
			regexList = append(regexList, strings.TrimPrefix(d, "regex:"))
		case strings.HasPrefix(d, "domain:"):
			exactDomains = append(exactDomains, strings.TrimPrefix(d, "domain:"))
		case strings.HasPrefix(d, "full:"):
			exactDomains = append(exactDomains, strings.TrimPrefix(d, "full:"))
		case strings.HasPrefix(d, "suffix:"):
			suffixDomains = append(suffixDomains, strings.TrimPrefix(d, "suffix:"))
		case strings.HasPrefix(d, "keyword:"):
			keywordList = append(keywordList, strings.TrimPrefix(d, "keyword:"))
		default:
			suffixDomains = append(suffixDomains, d)
		}
	}

	var ipRuleSets, rawIPs []string
	hasIPv6All := r.IPVersion == 6
	for _, ip := range r.IPs {
		if ip == "::/0" {
			hasIPv6All = true
			continue
		}
		if strings.HasPrefix(ip, "geoip:") {
			country := strings.TrimPrefix(ip, "geoip:")
			if country == "private" {
				rawIPs = append(rawIPs, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "fc00::/7", "::1/128")
			} else {
				tag := "geoip-" + country
				ipRuleSets = append(ipRuleSets, tag)
				ensureRemoteRuleSet(ruleSetMap, tag, activeMirror.GeoipPattern, downloadDetour, isV114)
			}
		} else {
			rawIPs = append(rawIPs, strings.TrimPrefix(ip, "ip:"))
		}
	}

	hasDomainMatchers := len(regexList) > 0 || len(suffixDomains) > 0 || len(exactDomains) > 0 || len(keywordList) > 0 || len(domainRuleSets) > 0
	hasIPMatchers := len(rawIPs) > 0 || len(ipRuleSets) > 0 || hasIPv6All
	splitBitTorrent := hasBitTorrent && (hasDomainMatchers || hasIPMatchers)

	var out []map[string]interface{}
	ruleAppProtos := allAppProtocols
	if splitBitTorrent {
		btRule := createBaseRule(nil)
		btRule["protocol"] = []string{"bittorrent"}
		out = append(out, btRule)
		ruleAppProtos = nonBitTorrentAppProtocols
	}
	if hasDomainMatchers {
		dRule := createBaseRule(ruleAppProtos)
		if len(regexList) > 0 {
			dRule["domain_regex"] = regexList
		}
		if len(suffixDomains) > 0 {
			dRule["domain_suffix"] = suffixDomains
		}
		if len(exactDomains) > 0 {
			dRule["domain"] = exactDomains
		}
		if len(keywordList) > 0 {
			dRule["domain_keyword"] = keywordList
		}
		if len(domainRuleSets) > 0 {
			dRule["rule_set"] = domainRuleSets
		}
		out = append(out, dRule)
	}
	if hasIPMatchers {
		iRule := createBaseRule(ruleAppProtos)
		if hasIPv6All {
			iRule["ip_version"] = 6
		}
		if len(rawIPs) > 0 {
			iRule["ip_cidr"] = rawIPs
		}
		if len(ipRuleSets) > 0 {
			iRule["rule_set"] = ipRuleSets
		}
		out = append(out, iRule)
	}
	if !hasDomainMatchers && !hasIPMatchers && !splitBitTorrent {
		baseRule := createBaseRule(ruleAppProtos)
		if len(baseRule) > 1 || r.OutboundTag != "" || r.Action != "" {
			out = append(out, baseRule)
		}
	}
	return out
}
