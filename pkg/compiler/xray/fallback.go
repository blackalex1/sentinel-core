package xray

import (
	"fmt"
	"strings"
)

// ExtractXrayFallbackSettings extracts backup nodes, probe URL, interval, and strategy.
func ExtractXrayFallbackSettings(settingsMap map[string]interface{}, tag string) ([]string, string, string, string) {
	var backups []string
	probeURL := "https://www.gstatic.com/generate_204"
	probeInterval := "15s"
	strategy := "priority"

	if settingsMap == nil {
		return backups, probeURL, probeInterval, strategy
	}

	if backupsRaw, ok := settingsMap["backup_outbounds"]; ok {
		if bList, ok := backupsRaw.([]interface{}); ok {
			for _, b := range bList {
				if bStr, ok := b.(string); ok && bStr != "" && bStr != tag {
					backups = append(backups, bStr)
				}
			}
		} else if bList, ok := backupsRaw.([]string); ok {
			for _, b := range bList {
				if b != "" && b != tag {
					backups = append(backups, b)
				}
			}
		}
	}

	if fbStr, ok := settingsMap["fallback_outbound"].(string); ok && fbStr != "" && fbStr != tag {
		found := false
		for _, b := range backups {
			if b == fbStr {
				found = true
				break
			}
		}
		if !found {
			backups = append(backups, fbStr)
		}
	}

	if pURL, ok := settingsMap["health_check_url"].(string); ok && pURL != "" {
		probeURL = pURL
	}
	if pInt, ok := settingsMap["health_check_interval"].(float64); ok && pInt > 0 {
		probeInterval = fmt.Sprintf("%ds", int(pInt))
	} else if pInt, ok := settingsMap["health_check_interval"].(int); ok && pInt > 0 {
		probeInterval = fmt.Sprintf("%ds", pInt)
	}

	if s, ok := settingsMap["fallback_strategy"].(string); ok && s != "" {
		strategy = s
	}

	return backups, probeURL, probeInterval, strategy
}

// BuildXrayBalancer creates an Xray balancer object based on strategy.
func BuildXrayBalancer(tag string, balancerTag string, backups []string, strategy string) map[string]interface{} {
	strat := strings.ToLower(strings.TrimSpace(strategy))

	if strat == "least_ping" {
		return map[string]interface{}{
			"tag":      balancerTag,
			"selector": append([]string{tag}, backups...),
			"strategy": map[string]interface{}{
				"type": "leastPing",
			},
		}
	}

	if strat == "round_robin" || strat == "random" || strat == "load_balance" {
		return map[string]interface{}{
			"tag":      balancerTag,
			"selector": append([]string{tag}, backups...),
			"strategy": map[string]interface{}{
				"type": "random",
			},
		}
	}

	// Default: Strict Priority (Primary / Fallback)
	fallbackTag := backups[0]
	return map[string]interface{}{
		"tag":         balancerTag,
		"selector":    []string{tag},
		"fallbackTag": fallbackTag,
		"strategy": map[string]interface{}{
			"type": "leastPing",
		},
	}
}

// BuildXrayObservatory creates a deduplicated observatory config.
func BuildXrayObservatory(subjects []string, probeURL string, probeInterval string) map[string]interface{} {
	seen := make(map[string]bool)
	var uniqueSubjects []string
	for _, s := range subjects {
		if !seen[s] && s != "" {
			seen[s] = true
			uniqueSubjects = append(uniqueSubjects, s)
		}
	}

	if len(uniqueSubjects) == 0 {
		return nil
	}

	return map[string]interface{}{
		"subjectSelector":   uniqueSubjects,
		"probeUrl":          probeURL,
		"probeInterval":     probeInterval,
		"enableConcurrency": true,
	}
}
