package singbox

import (
	"fmt"
	"strings"

	"github.com/blackalex1/sentinel-core/pkg/ast"
	"github.com/blackalex1/sentinel-core/pkg/matrix"
)

const (
	defaultSingboxProbeURL      = "https://www.gstatic.com/generate_204"
	defaultSingboxProbeInterval = 30
	defaultSingboxToleranceMs   = 50
)

// IsStrictPriorityStrategy reports whether strategy requests strict primary-first failover.
func IsStrictPriorityStrategy(strategy string) bool {
	s := strings.ToLower(strings.TrimSpace(strategy))
	return s == "" || s == "priority" || s == "primary" || s == "fallback"
}

// IsRoundRobinStrategy reports whether strategy requests round-robin or random balancing.
func IsRoundRobinStrategy(strategy string) bool {
	s := strings.ToLower(strings.TrimSpace(strategy))
	return s == "load_balance" || s == "round_robin" || s == "random"
}

// NormalizeSingboxProbeInterval clamps interval into [5, 3600] seconds, defaulting to 30s.
func NormalizeSingboxProbeInterval(probeInterval int) int {
	if probeInterval <= 0 {
		return defaultSingboxProbeInterval
	}
	if probeInterval < 5 {
		return 5
	}
	if probeInterval > 3600 {
		return 3600
	}
	return probeInterval
}

// CollectFallbackStrategyWarnings returns compatibility warnings when Sing-box adapts a failover strategy.
func CollectFallbackStrategyWarnings(strategy string, clashManaged bool) []matrix.NegotiationWarning {
	var warnings []matrix.NegotiationWarning
	if IsRoundRobinStrategy(strategy) {
		warnings = append(warnings, matrix.NegotiationWarning{
			Feature: matrix.Feature("fallback_strategy:" + strings.TrimSpace(strategy)),
			Message: "sing-box does not natively support round-robin/random outbound groups; using least-latency urltest with 50ms tolerance",
			Action:  "downgrade_to_urltest_least_ping",
		})
	} else if IsStrictPriorityStrategy(strategy) && !clashManaged {
		warnings = append(warnings, matrix.NegotiationWarning{
			Feature: matrix.Feature("fallback_strategy:priority"),
			Message: "strict priority without Clash API controller falls back to urltest with 50ms tolerance",
			Action:  "downgrade_to_urltest",
		})
	}
	return warnings
}

// ExtractSingboxFallbackSettings parses and extracts fallback parameters from settings map.
func ExtractSingboxFallbackSettings(sMap map[string]interface{}, tag string) ([]string, string, int, string) {
	var validBackups []string
	probeURL := defaultSingboxProbeURL
	probeInt := defaultSingboxProbeInterval
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

// CalculateSingboxTolerance determines urltest tolerance in ms according to strategy.
// A 50ms hysteresis threshold avoids both 1ms jitter flapping (0ms) and backup lock-in (5000ms).
func CalculateSingboxTolerance(strategy string) int {
	return defaultSingboxToleranceMs
}

func buildFallbackOutboundGroup(tag string, outbounds []string, probeURL string, probeInterval int, strategy string, clashManaged bool) map[string]interface{} {
	if strings.TrimSpace(probeURL) == "" {
		probeURL = defaultSingboxProbeURL
	}
	if clashManaged && IsStrictPriorityStrategy(strategy) && len(outbounds) > 0 {
		return map[string]interface{}{
			"type":                        "selector",
			"tag":                         tag,
			"outbounds":                   outbounds,
			"default":                     outbounds[0],
			"interrupt_exist_connections": false,
		}
	}

	interval := NormalizeSingboxProbeInterval(probeInterval)
	idleTimeoutSec := 1800
	if interval >= idleTimeoutSec {
		idleTimeoutSec = interval * 2
	}

	return map[string]interface{}{
		"type":                        "urltest",
		"tag":                         tag,
		"outbounds":                   outbounds,
		"url":                         probeURL,
		"interval":                    fmt.Sprintf("%ds", interval),
		"tolerance":                   CalculateSingboxTolerance(strategy),
		"idle_timeout":                fmt.Sprintf("%ds", idleTimeoutSec),
		"interrupt_exist_connections": false,
	}
}

// BuildSingboxFallbackGroup constructs a standalone urltest outbound group using default Clash-unmanaged mode.
func BuildSingboxFallbackGroup(tag string, primaryCompiled map[string]interface{}, backups []string, probeURL string, probeInterval int, strategy string) map[string]interface{} {
	return BuildSingboxFallbackGroupWithMode(tag, primaryCompiled, backups, probeURL, probeInterval, strategy, false)
}

// BuildSingboxFallbackGroupWithMode constructs a selector (for Clash-managed priority) or urltest outbound group.
func BuildSingboxFallbackGroupWithMode(tag string, primaryCompiled map[string]interface{}, backups []string, probeURL string, probeInterval int, strategy string, clashManaged bool) map[string]interface{} {
	primaryTag := tag + "-primary"
	outbounds := append([]string{primaryTag}, backups...)
	return buildFallbackOutboundGroup(tag, outbounds, probeURL, probeInterval, strategy, clashManaged)
}

// BuildSingboxNodeFallback handles ast.ServerProfile fallback generation in standalone mode.
func BuildSingboxNodeFallback(adaptedNode *ast.ServerProfile) (map[string]interface{}, map[string]interface{}, error) {
	return BuildSingboxNodeFallbackWithMode(adaptedNode, false)
}

// BuildSingboxNodeFallbackWithMode handles ast.ServerProfile fallback generation, emitting a selector for Clash-managed priority.
func BuildSingboxNodeFallbackWithMode(adaptedNode *ast.ServerProfile, clashManaged bool) (map[string]interface{}, map[string]interface{}, error) {
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
		probeURL = defaultSingboxProbeURL
	}
	probeInt := NormalizeSingboxProbeInterval(adaptedNode.HealthCheckInterval)

	groupOb := BuildSingboxFallbackGroupWithMode(primaryTag, primaryNodeObj, adaptedNode.BackupOutbounds, probeURL, probeInt, adaptedNode.FallbackStrategy, clashManaged)
	return groupOb, primaryNodeObj, nil
}

// BuildSingboxRawFallback handles raw dictionary outbound fallback generation in standalone mode.
func BuildSingboxRawFallback(ob map[string]interface{}) (map[string]interface{}, map[string]interface{}, bool) {
	groupOb, primaryCompiled, _, ok := BuildSingboxRawFallbackWithMode(ob, false)
	return groupOb, primaryCompiled, ok
}

// BuildSingboxRawFallbackWithMode handles raw dictionary outbound fallback generation and returns the resolved strategy.
func BuildSingboxRawFallbackWithMode(ob map[string]interface{}, clashManaged bool) (map[string]interface{}, map[string]interface{}, string, bool) {
	tag, _ := ob["tag"].(string)
	if tag == "" {
		return nil, nil, "", false
	}

	sMap := parseMapOrJSON(ob["settings"])
	validBackups, probeURL, probeInt, fallbackStrat := ExtractSingboxFallbackSettings(sMap, tag)

	if len(validBackups) == 0 {
		return nil, nil, "", false
	}

	primaryTag := tag + "-primary"
	primaryObDict := make(map[string]interface{})
	for k, v := range ob {
		primaryObDict[k] = v
	}
	primaryObDict["tag"] = primaryTag
	primaryCompiled := CompileRawOutboundToSingbox(primaryObDict)

	groupOb := BuildSingboxFallbackGroupWithMode(tag, primaryCompiled, validBackups, probeURL, probeInt, fallbackStrat, clashManaged)
	return groupOb, primaryCompiled, fallbackStrat, true
}

// BuildSingboxMultiNodeFallback constructs a multi-node fallback group in standalone mode.
func BuildSingboxMultiNodeFallback(adaptedNode *ast.ServerProfile, backupProfiles []*ast.ServerProfile) (map[string]interface{}, []map[string]interface{}, error) {
	return BuildSingboxMultiNodeFallbackWithMode(adaptedNode, backupProfiles, false)
}

// BuildSingboxMultiNodeFallbackWithMode constructs a multi-node selector/urltest outbound group and compiles all profiles.
func BuildSingboxMultiNodeFallbackWithMode(adaptedNode *ast.ServerProfile, backupProfiles []*ast.ServerProfile, clashManaged bool) (map[string]interface{}, []map[string]interface{}, error) {
	groupTag := adaptedNode.Name
	if groupTag == "" {
		groupTag = "proxy"
	}

	primaryTag := fmt.Sprintf("%s-node-1", groupTag)
	primaryCopy := *adaptedNode
	primaryCopy.Name = primaryTag
	primaryOutbound, err := BuildSingBoxOutbound(&primaryCopy)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to build primary outbound: %w", err)
	}

	compiledNodes := []map[string]interface{}{primaryOutbound}
	outboundTags := []string{primaryTag}

	for i, bp := range backupProfiles {
		if bp == nil {
			continue
		}
		nodeTag := fmt.Sprintf("%s-node-%d", groupTag, i+2)
		bpCopy := *bp
		bpCopy.Name = nodeTag
		ob, err := BuildSingBoxOutbound(&bpCopy)
		if err != nil {
			continue
		}
		compiledNodes = append(compiledNodes, ob)
		outboundTags = append(outboundTags, nodeTag)
	}

	for _, bTag := range adaptedNode.BackupOutbounds {
		if bTag != "" && bTag != groupTag {
			outboundTags = append(outboundTags, bTag)
		}
	}

	probeURL := adaptedNode.HealthCheckURL
	if probeURL == "" {
		probeURL = "https://api.telegram.org"
	}
	probeInt := NormalizeSingboxProbeInterval(adaptedNode.HealthCheckInterval)
	strategy := adaptedNode.FallbackStrategy
	if strategy == "" {
		strategy = "priority"
	}

	groupOb := buildFallbackOutboundGroup(groupTag, outboundTags, probeURL, probeInt, strategy, clashManaged)
	return groupOb, compiledNodes, nil
}



