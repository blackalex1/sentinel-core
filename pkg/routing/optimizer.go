package routing

import (
	"bytes"
	"net"
	"sort"
	"strings"
)

// OptimizeRules cleans, deduplicates, and compresses routing rules for maximum matching speed and minimal config size
func OptimizeRules(rules []RoutingRuleRow) []RoutingRuleRow {
	if len(rules) == 0 {
		return []RoutingRuleRow{}
	}

	result := make([]RoutingRuleRow, 0, len(rules))
	for _, r := range rules {
		if !r.Enabled {
			continue
		}

		row := r
		if len(row.IPs) > 0 {
			row.IPs = OptimizeCIDRs(row.IPs)
		}
		if len(row.Domains) > 0 {
			row.Domains = OptimizeDomains(row.Domains)
		}

		// Keep rule if it has any matchers or attributes
		if len(row.Domains) > 0 || len(row.IPs) > 0 || len(row.Ports) > 0 ||
			len(row.Protocols) > 0 || len(row.PackageUIDs) > 0 ||
			len(row.ProcessNames) > 0 || row.Target != "" {
			result = append(result, row)
		}
	}

	return result
}

// OptimizeCIDRs deduplicates and merges overlapping IPv4/IPv6 CIDR ranges while preserving geoip: tags
func OptimizeCIDRs(ips []string) []string {
	if len(ips) <= 1 {
		return ips
	}

	var geoTags []string
	var nets []*net.IPNet
	seenGeo := make(map[string]bool)

	for _, raw := range ips {
		tr := strings.TrimSpace(raw)
		if tr == "" {
			continue
		}

		if strings.HasPrefix(tr, "geoip:") {
			if !seenGeo[tr] {
				seenGeo[tr] = true
				geoTags = append(geoTags, tr)
			}
			continue
		}

		cleaned := strings.TrimPrefix(tr, "ip:")
		if !strings.Contains(cleaned, "/") {
			ip := net.ParseIP(cleaned)
			if ip != nil {
				if ip.To4() != nil {
					cleaned = cleaned + "/32"
				} else {
					cleaned = cleaned + "/128"
				}
			}
		}

		_, ipNet, err := net.ParseCIDR(cleaned)
		if err == nil && ipNet != nil {
			nets = append(nets, ipNet)
		} else {
			// Fallback: keep raw entry if not a valid CIDR
			if !seenGeo[tr] {
				seenGeo[tr] = true
				geoTags = append(geoTags, tr)
			}
		}
	}

	if len(nets) == 0 {
		return geoTags
	}

	// Sort networks by mask length (broadest networks first)
	sort.Slice(nets, func(i, j int) bool {
		onesI, _ := nets[i].Mask.Size()
		onesJ, _ := nets[j].Mask.Size()
		if onesI != onesJ {
			return onesI < onesJ // /8 before /16 before /24 before /32
		}
		return bytes.Compare(nets[i].IP, nets[j].IP) < 0
	})

	var mergedNets []*net.IPNet
	for _, n := range nets {
		contained := false
		for _, parent := range mergedNets {
			if isSubnet(parent, n) {
				contained = true
				break
			}
		}
		if !contained {
			mergedNets = append(mergedNets, n)
		}
	}

	result := make([]string, 0, len(geoTags)+len(mergedNets))
	result = append(result, geoTags...)
	for _, n := range mergedNets {
		result = append(result, n.String())
	}

	return result
}

func isSubnet(parent, child *net.IPNet) bool {
	// Child must be of same IP version
	if (parent.IP.To4() == nil) != (child.IP.To4() == nil) {
		return false
	}
	parentOnes, _ := parent.Mask.Size()
	childOnes, _ := child.Mask.Size()
	if childOnes < parentOnes {
		return false
	}
	return parent.Contains(child.IP)
}

// OptimizeDomains deduplicates domains, groups by suffix, and removes redundant subdomains
func OptimizeDomains(domains []string) []string {
	if len(domains) <= 1 {
		return domains
	}

	var specialTags []string // geosite:, regexp:, keyword:, full:
	var suffixDomains []string
	prefixMap := make(map[string]string)
	seenSpecial := make(map[string]bool)

	for _, d := range domains {
		tr := strings.TrimSpace(d)
		if tr == "" {
			continue
		}

		if strings.HasPrefix(tr, "geosite:") || strings.HasPrefix(tr, "regexp:") ||
			strings.HasPrefix(tr, "regex:") || strings.HasPrefix(tr, "keyword:") ||
			strings.HasPrefix(tr, "full:") {
			if !seenSpecial[tr] {
				seenSpecial[tr] = true
				specialTags = append(specialTags, tr)
			}
		} else {
			prefix := ""
			cleanDomain := tr
			if strings.HasPrefix(tr, "domain:") {
				prefix = "domain:"
				cleanDomain = strings.TrimPrefix(tr, "domain:")
			} else if strings.HasPrefix(tr, "suffix:") {
				prefix = "suffix:"
				cleanDomain = strings.TrimPrefix(tr, "suffix:")
			}
			cleanDomain = strings.ToLower(cleanDomain)
			if cleanDomain != "" {
				suffixDomains = append(suffixDomains, cleanDomain)
				if _, exists := prefixMap[cleanDomain]; !exists {
					prefixMap[cleanDomain] = prefix
				}
			}
		}
	}

	if len(suffixDomains) == 0 {
		sort.Strings(specialTags)
		return specialTags
	}

	// Sort suffix domains by parts length (shorter / root domains first)
	sort.Slice(suffixDomains, func(i, j int) bool {
		partsI := strings.Count(suffixDomains[i], ".")
		partsJ := strings.Count(suffixDomains[j], ".")
		if partsI != partsJ {
			return partsI < partsJ // example.com before sub.example.com
		}
		return suffixDomains[i] < suffixDomains[j]
	})

	var retainedDomains []string
	seenRoot := make(map[string]bool)

	for _, d := range suffixDomains {
		if seenRoot[d] {
			continue
		}

		isSub := false
		for _, parent := range retainedDomains {
			if strings.HasSuffix(d, "."+parent) || d == parent {
				isSub = true
				break
			}
		}

		if !isSub {
			retainedDomains = append(retainedDomains, d)
			seenRoot[d] = true
		}
	}

	sort.Strings(specialTags)
	sort.Strings(retainedDomains)

	result := make([]string, 0, len(specialTags)+len(retainedDomains))
	result = append(result, specialTags...)
	for _, d := range retainedDomains {
		result = append(result, prefixMap[d]+d)
	}

	return result
}
