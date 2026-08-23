package xray

import (
	"net"
	"strings"
	"github.com/blackalex1/sentinel-core/pkg/ast"
)

// BuildXrayRouting creates the routing block for Xray-core
func BuildXrayRouting(spec *ast.ConfigSpec) map[string]interface{} {
	rules := make([]map[string]interface{}, 0)

	// 0. Ensure DNS queries (port 53) are routed to Xray's DNS engine
	dnsRule := map[string]interface{}{
		"type":        "field",
		"outboundTag": "dns-out",
		"port":        "53",
		"network":     "udp,tcp",
	}
	rules = append(rules, dnsRule)

	// 0.1 Ensure direct connection to server IP/host to prevent routing loopbacks
	if spec.ServerNode != nil && spec.ServerNode.Address != "" {
		srvRule := map[string]interface{}{
			"type":        "field",
			"outboundTag": "direct",
		}
		if net.ParseIP(spec.ServerNode.Address) != nil {
			srvRule["ip"] = []string{spec.ServerNode.Address}
		} else {
			srvRule["domain"] = []string{spec.ServerNode.Address}
		}
		rules = append(rules, srvRule)
	}

	// 0.1 Drop link-local, multicast, broadcast, and NetBIOS in desktop TUN mode to avoid Windows routing loops
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
			tag := string(r.Action)
			if r.OutboundTag != "" {
				tag = r.OutboundTag
			} else if r.Action == ast.ActionProxy {
				if spec.ServerNode != nil && spec.ServerNode.Name != "" {
					tag = spec.ServerNode.Name
				} else {
					tag = "proxy"
				}
			} else if r.Action == ast.ActionDirect {
				tag = "direct"
			} else if r.Action == ast.ActionBlock {
				tag = "block"
			}

			createBaseRule := func() map[string]interface{} {
				ruleMap := map[string]interface{}{
					"type":        "field",
					"outboundTag": tag,
				}
				if len(r.Ports) > 0 {
					ruleMap["port"] = strings.Join(r.Ports, ",")
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
						ruleMap["network"] = strings.Join(networks, ",")
					}
					if len(appProtocols) > 0 {
						ruleMap["protocol"] = appProtocols
					}
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
			if len(r.Domains) > 0 {
				for _, d := range r.Domains {
					if d == "geosite:ru" {
						cleanDomains = append(cleanDomains, "geosite:category-ru")
					} else {
						cleanDomains = append(cleanDomains, d)
					}
				}
			}

			hasDomains := len(cleanDomains) > 0
			hasIPs := len(r.IPs) > 0

			if hasDomains && hasIPs {
				domainRule := createBaseRule()
				domainRule["domain"] = cleanDomains
				rules = append(rules, domainRule)

				ipRule := createBaseRule()
				ipRule["ip"] = r.IPs
				rules = append(rules, ipRule)
			} else if hasDomains {
				domainRule := createBaseRule()
				domainRule["domain"] = cleanDomains
				rules = append(rules, domainRule)
			} else if hasIPs {
				ipRule := createBaseRule()
				ipRule["ip"] = r.IPs
				rules = append(rules, ipRule)
			} else {
				baseRule := createBaseRule()
				if len(baseRule) > 2 {
					rules = append(rules, baseRule)
				}
			}
		}
	}

	return map[string]interface{}{
		"domainStrategy": "IPIfNonMatch",
		"rules":          rules,
	}
}
