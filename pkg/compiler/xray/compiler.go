package xray

import (
	"encoding/json"
	"fmt"
	"strings"
	"github.com/blackalex1/sentinel-core/pkg/ast"
	"github.com/blackalex1/sentinel-core/pkg/matrix"
)

// Compiler compiles an ast.ConfigSpec into a complete Xray-core JSON configuration.
type Compiler struct {
	negotiator *matrix.Negotiator
}

// NewCompiler creates a new Xray compiler instance.
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
	var primaryOutbound map[string]interface{}
	if spec.ServerNode != nil {
		adaptedNode, warnings, err := c.negotiator.Negotiate(
			spec.ServerNode,
			ast.CoreXray,
			spec.CoreVersion,
			spec.StrictMode,
		)
		if err != nil {
			return "", nil, fmt.Errorf("feature negotiation failed for xray: %w", err)
		}
		allWarnings = append(allWarnings, warnings...)

		outboundObj, err := BuildXrayOutbound(adaptedNode)
		if err != nil {
			return "", nil, fmt.Errorf("failed to build xray primary outbound: %w", err)
		}
		primaryOutbound = outboundObj
	}

	// 2. Build Inbounds
	inbounds := BuildXrayInbounds(spec)

	// 3. Build Outbounds
	outbounds := make([]map[string]interface{}, 0)
	if primaryOutbound != nil {
		outbounds = append(outbounds, primaryOutbound)
	}

	var observatory map[string]interface{}
	var balancers []map[string]interface{}
	backupOutboundMap := make(map[string]string)

	if spec.Routing != nil && len(spec.Routing.Outbounds) > 0 {
		var observatorySubjects []string
		probeURL := "https://www.gstatic.com/generate_204"
		probeInterval := "10s"

		for _, ob := range spec.Routing.Outbounds {
			tag, _ := ob["tag"].(string)
			if tag == "" {
				continue
			}
			proto, _ := ob["protocol"].(string)
			if proto == "" {
				proto = "freedom"
			}

			var settingsMap map[string]interface{}
			if s, ok := ob["settings"].(map[string]interface{}); ok {
				settingsMap = s
			} else if sStr, ok := ob["settings"].(string); ok && sStr != "" {
				_ = json.Unmarshal([]byte(sStr), &settingsMap)
			}

			if settingsMap == nil {
				settingsMap = make(map[string]interface{})
			}

			if proto == "hysteria2" || proto == "hysteria" {
				proto = "socks"
				socksPort := 10808
				if p, ok := settingsMap["port"].(float64); ok && p > 0 {
					socksPort = int(p)
				} else if p, ok := settingsMap["port"].(int); ok && p > 0 {
					socksPort = p
				}
				settingsMap = map[string]interface{}{
					"servers": []map[string]interface{}{
						{
							"address": "127.0.0.1",
							"port":    socksPort,
						},
					},
				}
			} else if proto == "socks" {
				if _, ok := settingsMap["servers"]; !ok {
					addr, _ := settingsMap["address"].(string)
					if addr == "" {
						addr = "127.0.0.1"
					}
					port := 10808
					if p, ok := settingsMap["port"].(float64); ok && p > 0 {
						port = int(p)
					} else if p, ok := settingsMap["port"].(int); ok && p > 0 {
						port = p
					}
					settingsMap = map[string]interface{}{
						"servers": []map[string]interface{}{
							{
								"address": addr,
								"port":    port,
							},
						},
					}
				}
			} else if proto == "vless" || proto == "vmess" {
				if vnextList, ok := settingsMap["vnext"].([]interface{}); ok {
					for _, vn := range vnextList {
						if vnMap, ok := vn.(map[string]interface{}); ok {
							if users, ok := vnMap["users"].([]interface{}); !ok || len(users) == 0 {
								vnMap["users"] = []map[string]interface{}{
									{
										"id":         "00000000-0000-0000-0000-000000000000",
										"encryption": "none",
									},
								}
							}
						}
					}
				}
			}

			var streamSettingsMap map[string]interface{}
			if ss, ok := ob["streamSettings"].(map[string]interface{}); ok {
				streamSettingsMap = ss
			} else if ssStr, ok := ob["stream_settings"].(string); ok && ssStr != "" {
				_ = json.Unmarshal([]byte(ssStr), &streamSettingsMap)
			}

			xrayOb := map[string]interface{}{
				"protocol": proto,
				"tag":      tag,
			}
			if len(settingsMap) > 0 {
				xrayOb["settings"] = settingsMap
			}
			if streamSettingsMap != nil {
				xrayOb["streamSettings"] = streamSettingsMap
			}
			outbounds = append(outbounds, xrayOb)

			if settingsMap != nil {
				var backups []string
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

				if len(backups) > 0 {
					balancerTag := fmt.Sprintf("balancer-%s", tag)
					backupOutboundMap[tag] = balancerTag

					if pURL, ok := settingsMap["health_check_url"].(string); ok && pURL != "" {
						probeURL = pURL
					}
					if pInt, ok := settingsMap["health_check_interval"].(float64); ok && pInt > 0 {
						probeInterval = fmt.Sprintf("%ds", int(pInt))
					} else if pInt, ok := settingsMap["health_check_interval"].(int); ok && pInt > 0 {
						probeInterval = fmt.Sprintf("%ds", pInt)
					}

					observatorySubjects = append(observatorySubjects, tag)
					observatorySubjects = append(observatorySubjects, backups...)

					fallbackTag := backups[0]
					balancers = append(balancers, map[string]interface{}{
						"tag":         balancerTag,
						"selector":    []string{tag},
						"fallbackTag": fallbackTag,
						"strategy": map[string]interface{}{
							"type": "leastPing",
						},
					})
				}
			}
		}

		if len(observatorySubjects) > 0 {
			seen := make(map[string]bool)
			var uniqueSubjects []string
			for _, s := range observatorySubjects {
				if !seen[s] {
					seen[s] = true
					uniqueSubjects = append(uniqueSubjects, s)
				}
			}
			observatory = map[string]interface{}{
				"subjectSelector":   uniqueSubjects,
				"probeUrl":          probeURL,
				"probeInterval":     probeInterval,
				"enableConcurrency": true,
			}
		}
	}

	// For Server mode, configure stats gRPC API (127.0.0.1:10085)
	if len(spec.ServerInbounds) > 0 {
		inbounds = append(inbounds, map[string]interface{}{
			"tag":      "api",
			"port":     10085,
			"listen":   "127.0.0.1",
			"protocol": "dokodemo-door",
			"settings": map[string]interface{}{
				"address": "127.0.0.1",
			},
		})
	}

	hasDirect := false
	hasBlock := false
	hasBlocked := false
	hasAPI := false
	for _, ob := range outbounds {
		if t, _ := ob["tag"].(string); t == "direct" {
			hasDirect = true
		} else if t == "block" {
			hasBlock = true
		} else if t == "blocked" {
			hasBlocked = true
		} else if t == "api" {
			hasAPI = true
		}
	}
	if !hasDirect {
		outbounds = append(outbounds, map[string]interface{}{"protocol": "freedom", "tag": "direct"})
	}
	if !hasBlock {
		outbounds = append(outbounds, map[string]interface{}{"protocol": "blackhole", "tag": "block"})
	}
	if !hasBlocked {
		outbounds = append(outbounds, map[string]interface{}{"protocol": "blackhole", "tag": "blocked"})
	}
	if len(spec.ServerInbounds) > 0 && !hasAPI {
		outbounds = append(outbounds, map[string]interface{}{"protocol": "blackhole", "tag": "api"})
	}

	// 4. Build Routing
	routing := BuildXrayRouting(spec)
	if len(spec.ServerInbounds) > 0 {
		apiRule := map[string]interface{}{
			"type":        "field",
			"inboundTag": []string{"api"},
			"outboundTag": "api",
		}
		if existingRules, ok := routing["rules"].([]map[string]interface{}); ok {
			routing["rules"] = append([]map[string]interface{}{apiRule}, existingRules...)
		} else {
			routing["rules"] = []map[string]interface{}{apiRule}
		}
	}

	if len(balancers) > 0 {
		routing["balancers"] = balancers
		if rules, ok := routing["rules"].([]map[string]interface{}); ok {
			for _, r := range rules {
				if obTag, ok := r["outboundTag"].(string); ok {
					if balTag, found := backupOutboundMap[obTag]; found {
						delete(r, "outboundTag")
						r["balancerTag"] = balTag
					}
				}
			}
		}
	}

	// 5. Build DNS
	dnsConfig := map[string]interface{}{
		"servers": []string{"https://1.1.1.1/dns-query", "8.8.8.8", "localhost"},
	}

	// 6. Log
	logLevel := strings.ToLower(strings.TrimSpace(spec.LogLevel))
	if logLevel == "warn" {
		logLevel = "warning"
	}
	if logLevel != "debug" && logLevel != "info" && logLevel != "warning" && logLevel != "error" && logLevel != "none" {
		logLevel = "warning"
	}

	logMap := map[string]interface{}{
		"loglevel": logLevel,
	}
	if spec.LogPath != "" {
		logMap["access"] = spec.LogPath
		logMap["error"] = spec.LogPath
	}

	configObj := map[string]interface{}{
		"log":       logMap,
		"dns":       dnsConfig,
		"inbounds":  inbounds,
		"outbounds": outbounds,
		"routing":   routing,
	}

	if len(spec.ServerInbounds) > 0 {
		configObj["api"] = map[string]interface{}{
			"tag":      "api",
			"services": []string{"HandlerService", "LoggerService", "StatsService"},
		}
		configObj["stats"] = map[string]interface{}{}
		configObj["policy"] = map[string]interface{}{
			"system": map[string]interface{}{
				"statsInboundUplink":    true,
				"statsInboundDownlink":  true,
				"statsOutboundUplink":   true,
				"statsOutboundDownlink": true,
			},
			"levels": map[string]interface{}{
				"0": map[string]interface{}{
					"statsUserUplink":   true,
					"statsUserDownlink": true,
				},
			},
		}
	}
	if observatory != nil {
		configObj["observatory"] = observatory
	}

	jsonBytes, err := json.MarshalIndent(configObj, "", "  ")
	if err != nil {
		return "", nil, fmt.Errorf("failed to marshal xray config to JSON: %w", err)
	}

	return string(jsonBytes), allWarnings, nil
}
