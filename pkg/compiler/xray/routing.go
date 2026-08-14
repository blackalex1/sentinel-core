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

			if len(r.Domains) > 0 {
				ruleMap["domain"] = r.Domains
			}
			if len(r.IPs) > 0 {
				ruleMap["ip"] = r.IPs
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
			if len(r.PackageUIDs) > 0 {
				ruleMap["user"] = r.PackageUIDs
			}
			if len(r.InboundTags) > 0 {
				ruleMap["inboundTag"] = r.InboundTags
			}

			rules = append(rules, ruleMap)
		}
	}

	return map[string]interface{}{
		"domainStrategy": "IPIfNonMatch",
		"rules":          rules,
	}
}
