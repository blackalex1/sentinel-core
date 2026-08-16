package security

import (
	"strconv"

	"github.com/blackalex1/sentinel-core/pkg/ast"
	"github.com/blackalex1/sentinel-core/pkg/security/filter"
)

// InjectSecurityRules injects high-priority blocking rules into the AST RoutingSpec based on SecurityConfig.
func InjectSecurityRules(baseRouting *ast.RoutingSpec, cfg SecurityConfig, quarantinedUsers []string) *ast.RoutingSpec {
	if baseRouting == nil {
		baseRouting = &ast.RoutingSpec{
			DefaultAction: ast.ActionProxy,
			Rules:         make([]ast.RoutingRule, 0),
		}
	}

	securityRules := make([]ast.RoutingRule, 0)

	// 1. Quarantined / Compromised Users block rule (Highest priority)
	if len(quarantinedUsers) > 0 {
		securityRules = append(securityRules, ast.RoutingRule{
			Action:      ast.ActionBlock,
			OutboundTag: "block",
			Users:       quarantinedUsers,
		})
	}

	// 2. Cloud Metadata / SSRF Protection rule
	if cfg.Integrity.BlockCloudMetadata {
		securityRules = append(securityRules, ast.RoutingRule{
			Action:      ast.ActionBlock,
			OutboundTag: "block",
			IPs: []string{
				"169.254.169.254", // AWS/GCP/Azure metadata IP
				"100.100.100.200", // Alibaba Cloud metadata IP
				"169.254.170.2",   // AWS ECS Task metadata
			},
			Domains: []string{
				"domain:metadata.google.internal",
				"domain:metadata.goog",
				"domain:instance-data",
			},
		})
	}

	// 3. Sensitive Ports IPS Protection rule
	if cfg.PortGuard.Enabled && len(cfg.PortGuard.SensitivePorts) > 0 {
		var portStrs []string
		for _, p := range cfg.PortGuard.SensitivePorts {
			portStrs = append(portStrs, strconv.Itoa(p))
		}
		securityRules = append(securityRules, ast.RoutingRule{
			Action:      ast.ActionBlock,
			OutboundTag: "block",
			Ports:       portStrs,
		})
	}

	// 4. Threat Intelligence Feeds (Malware, Phishing, Miners, Ads)
	if cfg.Filter.Enabled {
		var blockedDomains []string
		if cfg.Filter.BlockMalware {
			for _, d := range filter.DefaultMalwareDomains {
				blockedDomains = append(blockedDomains, "domain:"+d)
			}
		}
		if cfg.Filter.BlockPhishing {
			for _, d := range filter.DefaultPhishingDomains {
				blockedDomains = append(blockedDomains, "domain:"+d)
			}
		}
		if cfg.Filter.BlockMiners {
			for _, d := range filter.DefaultMinerDomains {
				blockedDomains = append(blockedDomains, "domain:"+d)
			}
		}
		if cfg.Filter.BlockAds {
			blockedDomains = append(blockedDomains, "geosite:category-ads-all")
		}
		for _, customDom := range cfg.Filter.CustomBlockedDomains {
			blockedDomains = append(blockedDomains, "domain:"+customDom)
		}

		if len(blockedDomains) > 0 || len(cfg.Filter.CustomBlockedIPs) > 0 {
			securityRules = append(securityRules, ast.RoutingRule{
				Action:      ast.ActionBlock,
				OutboundTag: "block",
				Domains:     blockedDomains,
				IPs:         cfg.Filter.CustomBlockedIPs,
			})
		}
	}

	// Prepend security rules at the very beginning of the routing table (highest priority)
	newRules := append(securityRules, baseRouting.Rules...)

	return &ast.RoutingSpec{
		DefaultAction:       baseRouting.DefaultAction,
		Rules:               newRules,
		Outbounds:           baseRouting.Outbounds,
		AutoDetectInterface: baseRouting.AutoDetectInterface,
		OverrideDNS:         baseRouting.OverrideDNS,
		RuleSets:            baseRouting.RuleSets,
	}
}
