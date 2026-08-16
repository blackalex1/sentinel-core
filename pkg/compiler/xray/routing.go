package xray

import (
	"strings"
	"github.com/blackalex1/sentinel-core/pkg/ast"
)

// BuildXrayRouting creates the routing block for Xray-core
func BuildXrayRouting(spec *ast.ConfigSpec) map[string]interface{} {
	rules := make([]map[string]interface{}, 0)

	if spec.Routing != nil {
		for _, r := range spec.Routing.Rules {
			tag := string(r.Action)
			if r.OutboundTag != "" {
				tag = r.OutboundTag
			} else if r.Action == ast.ActionProxy {
				tag = "proxy"
			} else if r.Action == ast.ActionDirect {
				tag = "direct"
			} else if r.Action == ast.ActionBlock {
				tag = "block"
			}

			ruleMap := map[string]interface{}{
				"type":        "field",
				"outboundTag": tag,
			}

			hasField := false
			if len(r.Domains) > 0 {
				var cleanDomains []string
				for _, d := range r.Domains {
					if d == "geosite:ru" {
						cleanDomains = append(cleanDomains, "geosite:category-ru")
					} else {
						cleanDomains = append(cleanDomains, d)
					}
				}
				ruleMap["domain"] = cleanDomains
				hasField = true
			}
			if len(r.IPs) > 0 {
				ruleMap["ip"] = r.IPs
				hasField = true
			}
			if len(r.Ports) > 0 {
				ruleMap["port"] = strings.Join(r.Ports, ",")
				hasField = true
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
					hasField = true
				}
				if len(appProtocols) > 0 {
					ruleMap["protocol"] = appProtocols
					hasField = true
				}
			}
			if len(r.Users) > 0 {
				ruleMap["user"] = r.Users
				hasField = true
			} else if len(r.PackageUIDs) > 0 {
				ruleMap["user"] = r.PackageUIDs
				hasField = true
			}
			if len(r.InboundTags) > 0 {
				ruleMap["inboundTag"] = r.InboundTags
				hasField = true
			}

			if hasField || r.OutboundTag != "" || r.Action != "" {
				rules = append(rules, ruleMap)
			}
		}
	}

	return map[string]interface{}{
		"domainStrategy": "IPIfNonMatch",
		"rules":          rules,
	}
}
