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

	// 0. If RawJSONConfig is provided (e.g. native subscription config with full outbounds, routing rules, and balancers)
	rawJSON := spec.RawJSONConfig
	if rawJSON == "" && spec.ServerNode != nil {
		rawJSON = spec.ServerNode.RawJSONConfig
	}

	if rawJSON != "" {
		var rawConfig map[string]interface{}
		if err := json.Unmarshal([]byte(rawJSON), &rawConfig); err == nil && len(rawConfig) > 0 {
			// Inject our built inbounds (mobile VPN tun-in and local socks-in)
			builtInbounds := BuildXrayInbounds(spec)
			var finalInbounds []interface{}
			for _, bi := range builtInbounds {
				finalInbounds = append(finalInbounds, bi)
			}
			// Preserve any existing non-tun / non-socks inbounds from rawConfig (e.g. loopback inbounds for balancers)
			if existingInbounds, ok := rawConfig["inbounds"].([]interface{}); ok {
				for _, ei := range existingInbounds {
					if eiMap, ok := ei.(map[string]interface{}); ok {
						tag, _ := eiMap["tag"].(string)
						if tag != "tun-in" && tag != "socks-in" {
							finalInbounds = append(finalInbounds, ei)
						}
					}
				}
			}
			rawConfig["inbounds"] = finalInbounds

			// Ensure balancers in subscription raw configs have fallbackTag to prevent fatal empty tag drops
			if routing, ok := rawConfig["routing"].(map[string]interface{}); ok {
				if balancers, ok := routing["balancers"].([]interface{}); ok {
					for _, b := range balancers {
						if bMap, ok := b.(map[string]interface{}); ok {
							fallback, _ := bMap["fallbackTag"].(string)
							if fallback == "" {
								var candidateTag string
								if selList, ok := bMap["selector"].([]interface{}); ok && len(selList) > 0 {
									if s, ok := selList[0].(string); ok && s != "" {
										candidateTag = s
									}
								} else if selList, ok := bMap["selectors"].([]interface{}); ok && len(selList) > 0 {
									if s, ok := selList[0].(string); ok && s != "" {
										candidateTag = s
									}
								}
								if candidateTag != "" {
									bMap["fallbackTag"] = candidateTag
								}
							}
						}
					}
				}
			}

			// Ensure log config if specified
			if spec.LogLevel != "" {
				rawConfig["log"] = map[string]interface{}{
					"loglevel": spec.LogLevel,
				}
			}

			formatted, err := json.MarshalIndent(rawConfig, "", "  ")
			if err != nil {
				return "", nil, fmt.Errorf("failed to format raw xray json config: %w", err)
			}
			return string(formatted), allWarnings, nil
		}
	}

	// 1. Negotiate active server node features
	var primaryOutbound map[string]interface{}
	var chainOutbounds []map[string]interface{}

	if len(spec.ChainNodes) >= 2 {
		for i, node := range spec.ChainNodes {
			adaptedNode, warnings, err := c.negotiator.Negotiate(
				node,
				ast.CoreXray,
				spec.CoreVersion,
				spec.StrictMode,
			)
			if err != nil {
				return "", nil, fmt.Errorf("feature negotiation failed for chain hop %d: %w", i+1, err)
			}
			allWarnings = append(allWarnings, warnings...)

			tag := fmt.Sprintf("chain-hop-%d", i+1)
			if node.Name != "" {
				tag = fmt.Sprintf("chain-%d-%s", i+1, node.Name)
			}

			// If previous hop in the chain already uses xtls-rprx-vision, nested vision over another vision transport is invalid.
			// However, if previous hop is a standard stream (e.g. SOCKS5 loopback entry gateway), flow: xtls-rprx-vision is preserved.
			if i > 0 && spec.ChainNodes[i-1].Flow == "xtls-rprx-vision" && adaptedNode.Flow == "xtls-rprx-vision" {
				adaptedNode.Flow = ""
			}

			outboundObj, err := BuildXrayOutboundWithTag(tag, adaptedNode)
			if err != nil {
				return "", nil, fmt.Errorf("failed to build chain hop %d outbound: %w", i+1, err)
			}

			if i > 0 {
				prevTag := fmt.Sprintf("chain-hop-%d", i)
				if spec.ChainNodes[i-1].Name != "" {
					prevTag = fmt.Sprintf("chain-%d-%s", i, spec.ChainNodes[i-1].Name)
				}
				streamSettings, ok := outboundObj["streamSettings"].(map[string]interface{})
				if !ok || streamSettings == nil {
					streamSettings = make(map[string]interface{})
					outboundObj["streamSettings"] = streamSettings
				}
				sockopt, ok := streamSettings["sockopt"].(map[string]interface{})
				if !ok || sockopt == nil {
					sockopt = make(map[string]interface{})
					streamSettings["sockopt"] = sockopt
				}
				sockopt["dialerProxy"] = prevTag
			}

			chainOutbounds = append(chainOutbounds, outboundObj)
		}
	} else if spec.ServerNode != nil {
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
	if len(chainOutbounds) > 0 {
		// Put exit node (last hop) first so it becomes the default outbound for unmatched traffic
		exitNodeObj := chainOutbounds[len(chainOutbounds)-1]
		outbounds = append(outbounds, exitNodeObj)
		for i := 0; i < len(chainOutbounds)-1; i++ {
			outbounds = append(outbounds, chainOutbounds[i])
		}
	} else if primaryOutbound != nil {
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

			if proto == "hysteria2" {
				proto = "hysteria"
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
			}

			var streamSettingsMap map[string]interface{}
			if ss, ok := ob["streamSettings"].(map[string]interface{}); ok {
				streamSettingsMap = ss
			} else if ssStr, ok := ob["stream_settings"].(string); ok && ssStr != "" {
				_ = json.Unmarshal([]byte(ssStr), &streamSettingsMap)
			}

			if proto == "vless" {
				secVal := ""
				if streamSettingsMap != nil {
					if s, ok := streamSettingsMap["security"].(string); ok {
						secVal = s
					}
				}
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
							} else {
								for _, u := range users {
									if uMap, ok := u.(map[string]interface{}); ok {
										if enc, ok := uMap["encryption"].(string); !ok || enc == "" {
											uMap["encryption"] = "none"
										}
										// Flow xtls-rprx-vision requires TLS or Reality transport
										if secVal != "tls" && secVal != "reality" {
											delete(uMap, "flow")
										}
									}
								}
							}
						}
					}
				}
			} else if proto == "vmess" {
				if vnextList, ok := settingsMap["vnext"].([]interface{}); ok {
					for _, vn := range vnextList {
						if vnMap, ok := vn.(map[string]interface{}); ok {
							if users, ok := vnMap["users"].([]interface{}); !ok || len(users) == 0 {
								vnMap["users"] = []map[string]interface{}{
									{
										"id":       "00000000-0000-0000-0000-000000000000",
										"security": "auto",
									},
								}
							} else {
								for _, u := range users {
									if uMap, ok := u.(map[string]interface{}); ok {
										if sec, ok := uMap["security"].(string); !ok || sec == "" {
											uMap["security"] = "auto"
										}
									}
								}
							}
						}
					}
				}
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
				backups, pURL, pInt, strat := ExtractXrayFallbackSettings(settingsMap, tag)
				if len(backups) > 0 {
					balancerTag := fmt.Sprintf("balancer-%s", tag)
					backupOutboundMap[tag] = balancerTag

					probeURL = pURL
					probeInterval = pInt

					observatorySubjects = append(observatorySubjects, tag)
					observatorySubjects = append(observatorySubjects, backups...)

					balancerObj := BuildXrayBalancer(tag, balancerTag, backups, strat)
					balancers = append(balancers, balancerObj)
				}
			}
		}

		if len(observatorySubjects) > 0 {
			observatory = BuildXrayObservatory(observatorySubjects, probeURL, probeInterval)
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
	hasDNS := false
	for _, ob := range outbounds {
		if t, _ := ob["tag"].(string); t == "direct" {
			hasDirect = true
		} else if t == "block" {
			hasBlock = true
		} else if t == "blocked" {
			hasBlocked = true
		} else if t == "api" {
			hasAPI = true
		} else if t == "dns-out" {
			hasDNS = true
		}
	}
	if !hasDNS {
		outbounds = append(outbounds, map[string]interface{}{"protocol": "dns", "tag": "dns-out"})
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

	// 5. Build DNS (Split-DNS with encrypted DoH)
	var dnsServers []interface{}
	directDNS := "https://8.8.8.8/dns-query"
	if spec.DNS != nil && spec.DNS.DirectServer != "" {
		directDNS = spec.DNS.DirectServer
	}
	remoteDNS := "https://1.1.1.1/dns-query"
	if spec.DNS != nil && spec.DNS.RemoteServer != "" {
		remoteDNS = spec.DNS.RemoteServer
	} else if spec.DNS != nil && len(spec.DNS.Servers) > 0 {
		remoteDNS = spec.DNS.Servers[0]
	}

	dnsServers = append(dnsServers, map[string]interface{}{
		"address": directDNS,
		"domains": []string{"domain:ru", "domain:su", "domain:xn--p1ai"},
	})
	if remoteDNS != directDNS {
		dnsServers = append(dnsServers, remoteDNS)
	}
	if spec.DNS != nil {
		for _, s := range spec.DNS.Servers {
			if s != "" && s != directDNS && s != remoteDNS {
				dnsServers = append(dnsServers, s)
			}
		}
	}
	dnsServers = append(dnsServers, "localhost")

	qStrategy := "UseIPv4"
	if spec.DNS != nil && spec.DNS.Strategy != "" {
		switch spec.DNS.Strategy {
		case "ipv6_only", "prefer_ipv6":
			qStrategy = "UseIPv6"
		default:
			qStrategy = "UseIPv4"
		}
	}

	dnsConfig := map[string]interface{}{
		"servers":       dnsServers,
		"queryStrategy": qStrategy,
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

	// Access Log handling
	if spec.AccessLog != "" {
		if spec.AccessLog == "console" || spec.AccessLog == "stdout" {
			logMap["access"] = ""
		} else {
			logMap["access"] = spec.AccessLog
		}
	} else if spec.LogPath != "" {
		logMap["access"] = spec.LogPath
	} else {
		// When no log path is set, suppress connection-level access logs unless debug/info is explicitly requested
		if logLevel == "warning" || logLevel == "error" || logLevel == "none" {
			logMap["access"] = "none"
		}
	}

	// Error Log handling
	if spec.ErrorLog != "" {
		if spec.ErrorLog == "console" || spec.ErrorLog == "stderr" {
			logMap["error"] = ""
		} else {
			logMap["error"] = spec.ErrorLog
		}
	} else if spec.LogPath != "" {
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
