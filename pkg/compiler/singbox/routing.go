package singbox

import (
	"fmt"
	"strings"
	"github.com/blackalex1/sentinel-core/pkg/ast"
)

// BuildSingBoxRoute generates the route object for Sing-box
func BuildSingBoxRoute(spec *ast.ConfigSpec, isV112 bool) map[string]interface{} {
	route := map[string]interface{}{
		"auto_detect_interface":   true,
		"default_domain_resolver": "dns-direct",
	}

	rules := make([]map[string]interface{}, 0)
	ruleSetMap := make(map[string]map[string]interface{})

	// Add DNS hijacking rule for client TUN mode
	if spec.ClientInbound != nil {
		rules = append(rules, map[string]interface{}{
			"protocol": "dns",
			"action":   "hijack-dns",
		})
	}

	// User defined routing rules
	if spec.Routing != nil {
		for _, r := range spec.Routing.Rules {
			outbound := string(r.Action)
			if r.OutboundTag != "" {
				outbound = r.OutboundTag
			} else if r.Action == ast.ActionProxy {
				outbound = "proxy"
			}
			if outbound == "blocked" {
				outbound = "block"
			}

			ruleMap := map[string]interface{}{
				"outbound": outbound,
			}

			var activeRuleSets []string

			if len(r.Domains) > 0 {
				var regexList []string
				var suffixDomains []string
				var exactDomains []string
				var keywordList []string

				for _, d := range r.Domains {
					if strings.HasPrefix(d, "geosite:") {
						tag := "geosite-" + strings.TrimPrefix(d, "geosite:")
						activeRuleSets = append(activeRuleSets, tag)
						if _, exists := ruleSetMap[tag]; !exists {
							ruleSetMap[tag] = map[string]interface{}{
								"tag":             tag,
								"type":            "remote",
								"format":          "binary",
								"url":             fmt.Sprintf("https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/%s.srs", tag),
								"download_detour": "direct",
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

				if len(regexList) > 0 {
					ruleMap["domain_regex"] = regexList
				}
				if len(suffixDomains) > 0 {
					ruleMap["domain_suffix"] = suffixDomains
				}
				if len(exactDomains) > 0 {
					ruleMap["domain"] = exactDomains
				}
				if len(keywordList) > 0 {
					ruleMap["domain_keyword"] = keywordList
				}
			}

			if len(r.IPs) > 0 {
				var rawIPs []string
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
							activeRuleSets = append(activeRuleSets, tag)
							if _, exists := ruleSetMap[tag]; !exists {
								ruleSetMap[tag] = map[string]interface{}{
									"tag":             tag,
									"type":            "remote",
									"format":          "binary",
									"url":             fmt.Sprintf("https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/%s.srs", tag),
									"download_detour": "direct",
								}
							}
						}
					} else if strings.HasPrefix(ip, "ip:") {
						rawIPs = append(rawIPs, strings.TrimPrefix(ip, "ip:"))
					} else {
						rawIPs = append(rawIPs, ip)
					}
				}
				if len(rawIPs) > 0 {
					ruleMap["ip_cidr"] = rawIPs
				}
			}

			if len(activeRuleSets) > 0 {
				ruleMap["rule_set"] = activeRuleSets
			}

			if len(r.InboundTags) > 0 {
				ruleMap["inbound"] = r.InboundTags
			}

			if len(r.Ports) > 0 {
				ruleMap["port"] = r.Ports
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
					ruleMap["network"] = networks
				}
				if len(appProtocols) > 0 {
					ruleMap["protocol"] = appProtocols
				}
			}

			if len(r.Users) > 0 {
				ruleMap["user"] = r.Users
			}
			if len(r.PackageUIDs) > 0 {
				ruleMap["user_id"] = r.PackageUIDs
			}
			if len(r.ProcessNames) > 0 {
				ruleMap["process_name"] = r.ProcessNames
			}

			rules = append(rules, ruleMap)
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
