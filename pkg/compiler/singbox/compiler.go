package singbox

import (
	"encoding/json"
	"fmt"
	"strings"
	"github.com/blackalex1/sentinel-core/pkg/ast"
	"github.com/blackalex1/sentinel-core/pkg/matrix"
)

// Compiler compiles an ast.ConfigSpec into a complete Sing-box JSON configuration.
type Compiler struct {
	negotiator *matrix.Negotiator
}

// NewCompiler creates a new Sing-box compiler.
func NewCompiler() *Compiler {
	return &Compiler{
		negotiator: matrix.NewNegotiator(),
	}
}

// Compile compiles the given specification into a formatted JSON string.
func (c *Compiler) Compile(spec *ast.ConfigSpec) (string, []matrix.NegotiationWarning, error) {
	if spec == nil {
		return "", nil, fmt.Errorf("config spec cannot be nil")
	}

	var allWarnings []matrix.NegotiationWarning

	// 1. Negotiate active server node features
	var primaryOutbounds []map[string]interface{}
	if spec.ServerNode != nil {
		adaptedNode, warnings, err := c.negotiator.Negotiate(
			spec.ServerNode,
			ast.CoreSingBox,
			spec.CoreVersion,
			spec.StrictMode,
		)
		if err != nil {
			return "", nil, fmt.Errorf("feature negotiation failed for sing-box: %w", err)
		}
		allWarnings = append(allWarnings, warnings...)

		if len(adaptedNode.BackupOutbounds) > 0 {
			primaryTag := adaptedNode.Name
			if primaryTag == "" {
				primaryTag = "proxy"
			}
			nodeCopy := *adaptedNode
			nodeCopy.Name = primaryTag + "-primary"
			primaryNodeObj, err := BuildSingBoxOutbound(&nodeCopy)
			if err != nil {
				return "", nil, fmt.Errorf("failed to build sing-box primary outbound: %w", err)
			}

			probeURL := adaptedNode.HealthCheckURL
			if probeURL == "" {
				probeURL = "https://www.gstatic.com/generate_204"
			}
			probeInt := adaptedNode.HealthCheckInterval
			if probeInt <= 0 {
				probeInt = 15
			}
			toleranceVal := 0
			if adaptedNode.FallbackStrategy == "load_balance" {
				toleranceVal = 50
			}

			urltestOb := map[string]interface{}{
				"type":      "urltest",
				"tag":       primaryTag,
				"outbounds": append([]string{primaryTag + "-primary"}, adaptedNode.BackupOutbounds...),
				"url":       probeURL,
				"interval":  fmt.Sprintf("%ds", probeInt),
				"tolerance": toleranceVal,
			}
			primaryOutbounds = append(primaryOutbounds, urltestOb, primaryNodeObj)
		} else {
			outboundObj, err := BuildSingBoxOutbound(adaptedNode)
			if err != nil {
				return "", nil, fmt.Errorf("failed to build sing-box primary outbound: %w", err)
			}
			primaryOutbounds = append(primaryOutbounds, outboundObj)
		}
	}

	// 2. Build Inbounds
	inbounds := BuildSingBoxInbounds(spec)

	// 3. Build Outbounds (Direct, Block + Server nodes)
	outbounds := make([]map[string]interface{}, 0)
	if len(primaryOutbounds) > 0 {
		outbounds = append(outbounds, primaryOutbounds...)
	}
	outbounds = append(outbounds,
		map[string]interface{}{"type": "direct", "tag": "direct"},
		map[string]interface{}{"type": "block", "tag": "block"},
	)

	if spec.Routing != nil && len(spec.Routing.Outbounds) > 0 {
		for _, ob := range spec.Routing.Outbounds {
			tag, _ := ob["tag"].(string)
			if tag == "" || tag == "direct" || tag == "block" {
				continue
			}
			if obType, ok := ob["type"].(string); ok && obType != "" {
				outbounds = append(outbounds, ob)
				continue
			}

			sMap := parseMapOrJSON(ob["settings"])
			var validBackups []string
			probeURL := "https://www.gstatic.com/generate_204"
			probeInt := 15
			fallbackStrat := "priority"

			if sMap != nil {
				if bkRaw, ok := sMap["backup_outbounds"].([]interface{}); ok {
					for _, b := range bkRaw {
						if bStr, ok := b.(string); ok && bStr != "" && bStr != tag {
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
			}

			if len(validBackups) > 0 {
				primaryTag := tag + "-primary"
				primaryObDict := make(map[string]interface{})
				for k, v := range ob {
					primaryObDict[k] = v
				}
				primaryObDict["tag"] = primaryTag
				primaryCompiled := CompileRawOutboundToSingbox(primaryObDict)

				toleranceVal := 0
				if fallbackStrat == "load_balance" {
					toleranceVal = 50
				}

				urltestOb := map[string]interface{}{
					"type":      "urltest",
					"tag":       tag,
					"outbounds": append([]string{primaryTag}, validBackups...),
					"url":       probeURL,
					"interval":  fmt.Sprintf("%ds", probeInt),
					"tolerance": toleranceVal,
				}
				outbounds = append(outbounds, urltestOb)
				if primaryCompiled != nil {
					outbounds = append(outbounds, primaryCompiled)
				}
			} else {
				outboundObj := CompileRawOutboundToSingbox(ob)
				if outboundObj != nil {
					outbounds = append(outbounds, outboundObj)
				}
			}
		}
	}

	// 4. Build DNS (modern format for Sing-box 1.12+)
	dnsConfig := buildSingBoxDNS(spec)

	// 5. Build Routing
	isV112 := strings.HasPrefix(spec.CoreVersion, "1.12") || strings.HasPrefix(spec.CoreVersion, "v1.12") || strings.HasPrefix(spec.CoreVersion, "1.13")
	routeConfig := BuildSingBoxRoute(spec, isV112)

	// 6. Log Level
	logLevel := strings.ToLower(strings.TrimSpace(spec.LogLevel))
	if logLevel != "trace" && logLevel != "debug" && logLevel != "info" && logLevel != "warn" && logLevel != "error" && logLevel != "fatal" && logLevel != "panic" {
		logLevel = "info"
	}

	logMap := map[string]interface{}{
		"disabled":  false,
		"level":     logLevel,
		"timestamp": true,
	}
	if spec.LogPath != "" {
		logMap["output"] = spec.LogPath
	}

	configObj := map[string]interface{}{
		"log":       logMap,
		"dns":       dnsConfig,
		"inbounds":  inbounds,
		"outbounds": outbounds,
		"route":     routeConfig,
	}

	// 7. Clash API / External Controller
	if spec.ClashAPIAddress != "" {
		configObj["experimental"] = map[string]interface{}{
			"clash_api": map[string]interface{}{
				"external_controller": spec.ClashAPIAddress,
			},
		}
	}

	jsonBytes, err := json.MarshalIndent(configObj, "", "  ")
	if err != nil {
		return "", nil, fmt.Errorf("failed to marshal sing-box config to JSON: %w", err)
	}

	return string(jsonBytes), allWarnings, nil
}

func buildSingBoxDNS(spec *ast.ConfigSpec) map[string]interface{} {
	remoteDNS := "1.1.1.1"
	directDNS := "8.8.8.8"
	strategy := "ipv4_only"

	if spec.DNS != nil {
		if spec.DNS.RemoteServer != "" {
			cleaned := strings.TrimPrefix(spec.DNS.RemoteServer, "https://")
			cleaned = strings.TrimSuffix(cleaned, "/dns-query")
			if cleaned != "" {
				remoteDNS = cleaned
			}
		}
		if spec.DNS.DirectServer != "" {
			directDNS = spec.DNS.DirectServer
		}
		if spec.DNS.Strategy != "" {
			strategy = spec.DNS.Strategy
		}
	}

	servers := []map[string]interface{}{
		{
			"tag":         "dns-direct",
			"type":        "udp",
			"server":      directDNS,
			"server_port": 53,
		},
	}

	if spec.ServerNode != nil {
		servers = append(servers, map[string]interface{}{
			"tag":         "dns-remote",
			"type":        "https",
			"server":      remoteDNS,
			"server_port": 443,
			"detour":      "proxy",
		})
	}

	return map[string]interface{}{
		"servers":  servers,
		"strategy": strategy,
	}
}
