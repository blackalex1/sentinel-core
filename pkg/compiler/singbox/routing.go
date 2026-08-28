package singbox

import (
	"fmt"
	"strconv"
	"strings"
	"github.com/blackalex1/sentinel-core/pkg/ast"
)

// BuildSingBoxRoute generates the route object for Sing-box
func BuildSingBoxRoute(spec *ast.ConfigSpec, isV112 bool) map[string]interface{} {
	route := map[string]interface{}{
		"auto_detect_interface":   true,
		"default_domain_resolver": "dns-direct",
	}

	if spec.ClientInbound != nil && spec.ClientInbound.Mode == ast.InboundModeDesktopTun {
		route["find_process"] = true
	}

	rules := make([]map[string]interface{}, 0)
	ruleSetMap := make(map[string]map[string]interface{})

	// Add DNS hijacking rule for client TUN mode (match port 53 directly to prevent private IP direct routing loop on 172.19.0.2:53)
	if spec.ClientInbound != nil {
		rules = append(rules, map[string]interface{}{
			"action": "hijack-dns",
			"port":   uint16(53),
		})
		rules = append(rules, map[string]interface{}{
			"action":   "hijack-dns",
			"protocol": "dns",
		})
	}

	// Add sniffing rule action for TUN or inbounds with sniffing enabled (Sing-box 1.11+ migration)
	var sniffingInbounds []string
	if spec.ClientInbound != nil && (spec.ClientInbound.Mode == ast.InboundModeDesktopTun || spec.ClientInbound.Mode == ast.InboundModeMobileVpn) {
		sniffingInbounds = append(sniffingInbounds, "tun-in")
	}
	for _, sb := range spec.ServerInbounds {
		if sb.Sniffing != nil {
			if enabled, ok := sb.Sniffing["enabled"].(bool); ok && enabled {
				tag := sb.Tag
				if tag == "" {
					tag = fmt.Sprintf("inbound-%d", sb.Port)
				}
				sniffingInbounds = append(sniffingInbounds, tag)
			}
		}
	}

	if len(sniffingInbounds) > 0 {
		sniffRule := map[string]interface{}{
			"action": "sniff",
		}
		if len(sniffingInbounds) == 1 {
			sniffRule["inbound"] = sniffingInbounds[0]
		} else {
			sniffRule["inbound"] = sniffingInbounds
		}
		rules = append(rules, sniffRule)
	}

	// Add resolve rule actions for domain_strategy if specified on server inbounds
	for _, sb := range spec.ServerInbounds {
		if sb.RawSettings != nil {
			if ds, ok := sb.RawSettings["domain_strategy"].(string); ok && ds != "" {
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
		}
	}

	downloadDetour := "direct"
	if spec.ServerNode != nil {
		if spec.ServerNode.Name != "" {
			downloadDetour = spec.ServerNode.Name
		} else {
			downloadDetour = "proxy"
		}
	}

	// User defined routing rules
	if spec.Routing != nil {
		for _, r := range spec.Routing.Rules {
			outbound := string(r.Action)
			if r.OutboundTag != "" {
				outbound = r.OutboundTag
			} else if r.Action == ast.ActionProxy {
				if spec.ServerNode != nil && spec.ServerNode.Name != "" {
					outbound = spec.ServerNode.Name
				} else {
					outbound = "proxy"
				}
			}
			if outbound == "blocked" {
				outbound = "block"
			}

			createBaseRule := func() map[string]interface{} {
				base := map[string]interface{}{
					"outbound": outbound,
				}
				if len(r.InboundTags) > 0 {
					base["inbound"] = r.InboundTags
				}
				if len(r.Ports) > 0 {
					var intPorts []uint16
					var rangePorts []string
					for _, p := range r.Ports {
						pTrim := strings.TrimSpace(p)
						if num, err := strconv.Atoi(pTrim); err == nil && num > 0 && num <= 65535 {
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
				if len(r.Protocols) > 0 {
					var networks []string
					var appProtocols []string
					for _, p := range r.Protocols {
						pLower := strings.ToLower(p)
						if pLower == "tcp" || pLower == "udp" {
							networks = append(networks, pLower)
						} else {
							appProtocols = append(appProtocols, pLower)
						}
					}
					if len(networks) > 0 {
						base["network"] = networks
					}
					if len(appProtocols) > 0 {
						base["protocol"] = appProtocols
					}
				}
				if len(r.Users) > 0 {
					base["user"] = r.Users
				}
				if len(r.PackageUIDs) > 0 {
					base["user_id"] = r.PackageUIDs
				}
				if len(r.ProcessNames) > 0 {
					base["process_name"] = r.ProcessNames
				}
				return base
			}

			var domainRuleSets []string
			var ipRuleSets []string

			var regexList []string
			var suffixDomains []string
			var exactDomains []string
			var keywordList []string

			if len(r.Domains) > 0 {
				for _, d := range r.Domains {
					if strings.HasPrefix(d, "geosite:") {
						tag := "geosite-" + strings.TrimPrefix(d, "geosite:")
						domainRuleSets = append(domainRuleSets, tag)
						if _, exists := ruleSetMap[tag]; !exists {
							ruleSetMap[tag] = map[string]interface{}{
								"tag":             tag,
								"type":            "remote",
								"format":          "binary",
								"url":             fmt.Sprintf("https://cdn.jsdelivr.net/gh/SagerNet/sing-geosite@rule-set/%s.srs", tag),
								"download_detour": downloadDetour,
							}
						}
					} else if strings.HasPrefix(d, "regexp:") {
						regexList = append(regexList, strings.TrimPrefix(d, "regexp:"))
					} else if strings.HasPrefix(d, "regex:") {
						regexList = append(regexList, strings.TrimPrefix(d, "regex:"))
					} else if strings.HasPrefix(d, "domain:") {
						exactDomains = append(exactDomains, strings.TrimPrefix(d, "domain:"))
					} else if strings.HasPrefix(d, "full:") {
						exactDomains = append(exactDomains, strings.TrimPrefix(d, "full:"))
					} else if strings.HasPrefix(d, "suffix:") {
						suffixDomains = append(suffixDomains, strings.TrimPrefix(d, "suffix:"))
					} else if strings.HasPrefix(d, "keyword:") {
						keywordList = append(keywordList, strings.TrimPrefix(d, "keyword:"))
					} else {
						suffixDomains = append(suffixDomains, d)
					}
				}
			}

			var rawIPs []string
			if len(r.IPs) > 0 {
				for _, ip := range r.IPs {
					if strings.HasPrefix(ip, "geoip:") {
						country := strings.TrimPrefix(ip, "geoip:")
						if country == "private" {
							rawIPs = append(rawIPs,
								"10.0.0.0/8",
								"172.16.0.0/12",
								"192.168.0.0/16",
								"127.0.0.0/8",
								"fc00::/7",
								"::1/128",
							)
						} else {
							tag := "geoip-" + country
							ipRuleSets = append(ipRuleSets, tag)
							if _, exists := ruleSetMap[tag]; !exists {
								ruleSetMap[tag] = map[string]interface{}{
									"tag":             tag,
									"type":            "remote",
									"format":          "binary",
									"url":             fmt.Sprintf("https://cdn.jsdelivr.net/gh/SagerNet/sing-geoip@rule-set/%s.srs", tag),
									"download_detour": downloadDetour,
								}
							}
						}
					} else if strings.HasPrefix(ip, "ip:") {
						rawIPs = append(rawIPs, strings.TrimPrefix(ip, "ip:"))
					} else {
						rawIPs = append(rawIPs, ip)
					}
				}
			}

			hasDomainMatchers := len(regexList) > 0 || len(suffixDomains) > 0 || len(exactDomains) > 0 || len(keywordList) > 0 || len(domainRuleSets) > 0
			hasIPMatchers := len(rawIPs) > 0 || len(ipRuleSets) > 0

			if hasDomainMatchers && hasIPMatchers {
				// Split into two rules so domains and IPs match independently
				dRule := createBaseRule()
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
				rules = append(rules, dRule)

				iRule := createBaseRule()
				if len(rawIPs) > 0 {
					iRule["ip_cidr"] = rawIPs
				}
				if len(ipRuleSets) > 0 {
					iRule["rule_set"] = ipRuleSets
				}
				rules = append(rules, iRule)
			} else if hasDomainMatchers {
				dRule := createBaseRule()
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
				rules = append(rules, dRule)
			} else if hasIPMatchers {
				iRule := createBaseRule()
				if len(rawIPs) > 0 {
					iRule["ip_cidr"] = rawIPs
				}
				if len(ipRuleSets) > 0 {
					iRule["rule_set"] = ipRuleSets
				}
				rules = append(rules, iRule)
			} else {
				baseRule := createBaseRule()
				if len(baseRule) > 1 || r.OutboundTag != "" || r.Action != "" {
					rules = append(rules, baseRule)
				}
			}
		}
	}

	if spec.ClashAPIAddress != "" {
		rules = append(rules, map[string]interface{}{
			"clash_mode": "Direct",
			"outbound":   "direct",
		})
	}

	route["rules"] = rules

	if len(ruleSetMap) > 0 {
		ruleSets := make([]map[string]interface{}, 0, len(ruleSetMap))
		for _, rs := range ruleSetMap {
			ruleSets = append(ruleSets, rs)
		}
		route["rule_set"] = ruleSets
	}

	return route
}
