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
	var primaryOutbound map[string]interface{}
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

		outboundObj, err := BuildSingBoxOutbound(adaptedNode)
		if err != nil {
			return "", nil, fmt.Errorf("failed to build sing-box primary outbound: %w", err)
		}
		primaryOutbound = outboundObj
	}

	// 2. Build Inbounds
	inbounds := BuildSingBoxInbounds(spec)

	// 3. Build Outbounds (Direct, Block + Server nodes)
	outbounds := make([]map[string]interface{}, 0)
	if primaryOutbound != nil {
		outbounds = append(outbounds, primaryOutbound)
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
			proto, _ := ob["protocol"].(string)
			if proto == "" {
				proto = "freedom"
			}
			switch proto {
			case "freedom", "direct":
				outbounds = append(outbounds, map[string]interface{}{"type": "direct", "tag": tag})
			case "blackhole", "block":
				outbounds = append(outbounds, map[string]interface{}{"type": "block", "tag": tag})
			case "hysteria2", "hysteria":
				hyOb := map[string]interface{}{
					"type": "hysteria2",
					"tag":  tag,
				}
				var sMap map[string]interface{}
				if sm, ok := ob["settings"].(map[string]interface{}); ok {
					sMap = sm
				} else if smStr, ok := ob["settings"].(string); ok && smStr != "" {
					_ = json.Unmarshal([]byte(smStr), &sMap)
				}
				if sMap != nil {
					if addr, ok := sMap["address"].(string); ok {
						hyOb["server"] = addr
					}
					if port, ok := sMap["port"].(float64); ok {
						hyOb["server_port"] = int(port)
					} else if port, ok := sMap["port"].(int); ok {
						hyOb["server_port"] = port
					}
					if pwd, ok := sMap["password"].(string); ok {
						hyOb["password"] = pwd
					}
					if obfsType, ok := sMap["obfs_type"].(string); ok && obfsType != "" {
						obfsMap := map[string]interface{}{
							"type": obfsType,
						}
						if obfsPwd, ok := sMap["obfs_password"].(string); ok && obfsPwd != "" {
							obfsMap["password"] = obfsPwd
						}
						hyOb["obfs"] = obfsMap
					}
				}
				tlsObj := map[string]interface{}{
					"enabled": true,
				}
				var tsMap map[string]interface{}
				if tsm, ok := ob["stream_settings"].(map[string]interface{}); ok {
					tsMap = tsm
				} else if tsm, ok := ob["streamSettings"].(map[string]interface{}); ok {
					tsMap = tsm
				} else if tsmStr, ok := ob["stream_settings"].(string); ok && tsmStr != "" {
					_ = json.Unmarshal([]byte(tsmStr), &tsMap)
				} else if tsmStr, ok := ob["streamSettings"].(string); ok && tsmStr != "" {
					_ = json.Unmarshal([]byte(tsmStr), &tsMap)
				}
				if tsMap != nil {
					if tlsSettings, ok := tsMap["tlsSettings"].(map[string]interface{}); ok {
						if sn, ok := tlsSettings["serverName"].(string); ok && sn != "" {
							tlsObj["server_name"] = sn
						}
						if insec, ok := tlsSettings["allowInsecure"].(bool); ok {
							tlsObj["insecure"] = insec
						}
					}
				}
				if _, ok := tlsObj["server_name"]; !ok {
					if srv, ok := hyOb["server"].(string); ok && srv != "" && !strings.Contains(srv, ":") {
						tlsObj["server_name"] = srv
					}
					tlsObj["insecure"] = true
				}
				hyOb["tls"] = tlsObj
				outbounds = append(outbounds, hyOb)
			default:
				outbounds = append(outbounds, map[string]interface{}{"type": "direct", "tag": tag})
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
