package singbox

import (
	"fmt"
	"strings"

	"github.com/blackalex1/sentinel-core/pkg/ast"
)

// ExtractSingboxFallbackSettings parses and extracts fallback parameters from settings map.
func ExtractSingboxFallbackSettings(sMap map[string]interface{}, tag string) ([]string, string, int, string) {
	var validBackups []string
	probeURL := "https://www.gstatic.com/generate_204"
	probeInt := 15
	fallbackStrat := "priority"

	if sMap == nil {
		return validBackups, probeURL, probeInt, fallbackStrat
	}

	if bkRaw, ok := sMap["backup_outbounds"].([]interface{}); ok {
		for _, b := range bkRaw {
			if bStr, ok := b.(string); ok && bStr != "" && bStr != tag {
				validBackups = append(validBackups, bStr)
			}
		}
	} else if bkRaw, ok := sMap["backup_outbounds"].([]string); ok {
		for _, bStr := range bkRaw {
			if bStr != "" && bStr != tag {
				validBackups = append(validBackups, bStr)
			}
		}
	}

	if bkStr, ok := sMap["fallback_outbound"].(string); ok && bkStr != "" && bkStr != tag {
		found := false
		for _, vb := range validBackups {
			if vb == bkStr {
				found = true
				break
			}
		}
		if !found {
			validBackups = append(validBackups, bkStr)
		}
	}

	if u, ok := sMap["health_check_url"].(string); ok && u != "" {
		probeURL = u
	}

	if i, ok := sMap["health_check_interval"].(float64); ok && i > 0 {
		probeInt = int(i)
	} else if i, ok := sMap["health_check_interval"].(int); ok && i > 0 {
		probeInt = i
	}

	if s, ok := sMap["fallback_strategy"].(string); ok && s != "" {
		fallbackStrat = s
	}

	return validBackups, probeURL, probeInt, fallbackStrat
}

// CalculateSingboxTolerance determines tolerance in ms according to strategy.
func CalculateSingboxTolerance(strategy string) int {
	strategy = strings.ToLower(strings.TrimSpace(strategy))
	if strategy == "load_balance" || strategy == "round_robin" || strategy == "random" {
		return 50
	}
	return 0
}

// BuildSingboxFallbackGroup constructs an urltest outbound group and renamed primary node.
func BuildSingboxFallbackGroup(tag string, primaryCompiled map[string]interface{}, backups []string, probeURL string, probeInterval int, strategy string) map[string]interface{} {
	primaryTag := tag + "-primary"
	toleranceVal := CalculateSingboxTolerance(strategy)

	return map[string]interface{}{
		"type":      "urltest",
		"tag":       tag,
		"outbounds": append([]string{primaryTag}, backups...),
		"url":       probeURL,
		"interval":  fmt.Sprintf("%ds", probeInterval),
		"tolerance": toleranceVal,
	}
}

// BuildSingboxNodeFallback handles ast.ServerProfile fallback generation.
func BuildSingboxNodeFallback(adaptedNode *ast.ServerProfile) (map[string]interface{}, map[string]interface{}, error) {
	primaryTag := adaptedNode.Name
	if primaryTag == "" {
		primaryTag = "proxy"
	}
	nodeCopy := *adaptedNode
	nodeCopy.Name = primaryTag + "-primary"
	primaryNodeObj, err := BuildSingBoxOutbound(&nodeCopy)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to build sing-box primary outbound: %w", err)
	}

	probeURL := adaptedNode.HealthCheckURL
	if probeURL == "" {
		probeURL = "https://www.gstatic.com/generate_204"
	}
	probeInt := adaptedNode.HealthCheckInterval
	if probeInt <= 0 {
		probeInt = 15
	}

	urltestOb := BuildSingboxFallbackGroup(primaryTag, primaryNodeObj, adaptedNode.BackupOutbounds, probeURL, probeInt, adaptedNode.FallbackStrategy)
	return urltestOb, primaryNodeObj, nil
}

// BuildSingboxRawFallback handles raw dictionary outbound fallback generation.
func BuildSingboxRawFallback(ob map[string]interface{}) (map[string]interface{}, map[string]interface{}, bool) {
	tag, _ := ob["tag"].(string)
	if tag == "" {
		return nil, nil, false
	}

	sMap := parseMapOrJSON(ob["settings"])
	validBackups, probeURL, probeInt, fallbackStrat := ExtractSingboxFallbackSettings(sMap, tag)

	if len(validBackups) == 0 {
		return nil, nil, false
	}

	primaryTag := tag + "-primary"
	primaryObDict := make(map[string]interface{})
	for k, v := range ob {
		primaryObDict[k] = v
	}
	primaryObDict["tag"] = primaryTag
	primaryCompiled := CompileRawOutboundToSingbox(primaryObDict)

	urltestOb := BuildSingboxFallbackGroup(tag, primaryCompiled, validBackups, probeURL, probeInt, fallbackStrat)
	return urltestOb, primaryCompiled, true
}
