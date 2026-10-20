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

		if len(adaptedNode.BackupProfiles) > 0 {
			urltestOb, compiledNodes, err := BuildSingboxMultiNodeFallback(adaptedNode, adaptedNode.BackupProfiles)
			if err != nil {
				return "", nil, err
			}
			primaryOutbounds = append(primaryOutbounds, urltestOb)
			primaryOutbounds = append(primaryOutbounds, compiledNodes...)
		} else if len(adaptedNode.BackupOutbounds) > 0 {
			urltestOb, primaryNodeObj, err := BuildSingboxNodeFallback(adaptedNode)
			if err != nil {
				return "", nil, err
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

			if urltestOb, primaryCompiled, hasFallback := BuildSingboxRawFallback(ob); hasFallback {
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

	// 3.1 Extract endpoints (e.g. WireGuard in Sing-box 1.12+)
	var endpoints []map[string]interface{}
	var finalOutbounds []map[string]interface{}
	for _, ob := range outbounds {
		if obType, ok := ob["type"].(string); ok && obType == "wireguard" {
			endpoints = append(endpoints, ob)
		} else {
			finalOutbounds = append(finalOutbounds, ob)
		}
	}
	outbounds = finalOutbounds

	// 4. Build DNS (modern format for Sing-box 1.12+)
	dnsConfig := buildSingBoxDNS(spec)

	// 5. Build Routing
	isV112 := strings.HasPrefix(spec.CoreVersion, "1.12") || strings.HasPrefix(spec.CoreVersion, "v1.12") || strings.HasPrefix(spec.CoreVersion, "1.13")
	routeConfig, httpClients := BuildSingBoxRoute(spec, isV112)

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

	if len(httpClients) > 0 {
		configObj["http_clients"] = httpClients
	}

	if len(endpoints) > 0 {
		configObj["endpoints"] = endpoints
	}

	// 7. Experimental block (Cache File & Clash API)
	expObj := map[string]interface{}{
		"cache_file": map[string]interface{}{
			"enabled": true,
			"path":    "cache.db",
		},
	}
	if spec.ClashAPIAddress != "" {
		expObj["clash_api"] = map[string]interface{}{
			"external_controller": spec.ClashAPIAddress,
		}
	}
	configObj["experimental"] = expObj

	jsonBytes, err := json.MarshalIndent(configObj, "", "  ")
	if err != nil {
		return "", nil, fmt.Errorf("failed to marshal sing-box config to JSON: %w", err)
	}

	return string(jsonBytes), allWarnings, nil
}

func parseSingboxDNSServer(tag string, serverURL string, detour string) map[string]interface{} {
	obj := map[string]interface{}{
		"tag": tag,
	}
	if detour != "" {
		obj["detour"] = detour
	}

	if strings.HasPrefix(serverURL, "https://") {
		obj["type"] = "https"
		trimmed := strings.TrimPrefix(serverURL, "https://")
		parts := strings.SplitN(trimmed, "/", 2)
		hostPart := parts[0]
		if len(parts) > 1 && parts[1] != "" {
			obj["path"] = "/" + parts[1]
		}
		obj["server_port"] = 443

		knownIPs := map[string]string{
			"dns.google":                "8.8.8.8",
			"cloudflare-dns.com":        "1.1.1.1",
			"one.one.one.one":           "1.1.1.1",
			"dns.adguard-dns.com":       "94.140.14.14",
			"dns.yandex.ru":             "77.88.8.8",
			"common.dot.dns.yandex.net": "77.88.8.8",
		}
		knownDomainsForIP := map[string]string{
			"8.8.8.8":      "dns.google",
			"8.8.4.4":      "dns.google",
			"1.1.1.1":      "cloudflare-dns.com",
			"1.0.0.1":      "cloudflare-dns.com",
			"94.140.14.14": "dns.adguard-dns.com",
			"77.88.8.8":    "dns.yandex.ru",
		}
		if ip, ok := knownIPs[hostPart]; ok {
			obj["server"] = ip
			obj["tls"] = map[string]interface{}{
				"enabled":     true,
				"server_name": hostPart,
			}
		} else if sni, ok := knownDomainsForIP[hostPart]; ok {
			obj["server"] = hostPart
			obj["tls"] = map[string]interface{}{
				"enabled":     true,
				"server_name": sni,
			}
		} else {
			obj["server"] = hostPart
		}
	} else if strings.HasPrefix(serverURL, "tls://") {
		obj["type"] = "tls"
		obj["server"] = strings.TrimPrefix(serverURL, "tls://")
		obj["server_port"] = 853
	} else if strings.HasPrefix(serverURL, "tcp://") {
		obj["type"] = "tcp"
		obj["server"] = strings.TrimPrefix(serverURL, "tcp://")
		obj["server_port"] = 53
	} else if strings.HasPrefix(serverURL, "udp://") {
		obj["type"] = "udp"
		obj["server"] = strings.TrimPrefix(serverURL, "udp://")
		obj["server_port"] = 53
	} else {
		// Plain IP or host without scheme
		obj["type"] = "udp"
		obj["server"] = serverURL
		obj["server_port"] = 53
	}
	return obj
}

func buildSingBoxDNS(spec *ast.ConfigSpec) map[string]interface{} {
	remoteDNS := "https://1.1.1.1/dns-query"
	directDNS := "8.8.8.8"
	strategy := "ipv4_only"

	if spec.DNS != nil {
		if len(spec.DNS.Servers) > 0 {
			remoteDNS = spec.DNS.Servers[0]
			if len(spec.DNS.Servers) > 1 {
				directDNS = spec.DNS.Servers[1]
			}
		}
		if spec.DNS.RemoteServer != "" {
			remoteDNS = spec.DNS.RemoteServer
		}
		if spec.DNS.DirectServer != "" {
			directDNS = spec.DNS.DirectServer
		}
		if spec.DNS.Strategy != "" {
			strategy = spec.DNS.Strategy
		}
	}

	// Direct DNS for local resolution should never use HTTPS DoH without a proxy (causes timeouts in restricted networks).
	// Normalize common public resolvers specified as DoH back to fast UDP port 53.
	if strings.HasPrefix(directDNS, "https://8.8.8.8") || strings.HasPrefix(directDNS, "https://dns.google") {
		directDNS = "8.8.8.8"
	} else if strings.HasPrefix(directDNS, "https://77.88.8.8") || strings.HasPrefix(directDNS, "https://dns.yandex") {
		directDNS = "77.88.8.8"
	}

	directServerObj := parseSingboxDNSServer("dns-direct", directDNS, "")
	servers := []map[string]interface{}{directServerObj}

	finalDNS := "dns-direct"
	dnsRules := []map[string]interface{}{}

	detourTag := ""
	if spec.ServerNode != nil {
		if spec.ServerNode.Name != "" {
			detourTag = spec.ServerNode.Name
		} else {
			detourTag = "proxy"
		}
	} else if spec.Routing != nil && len(spec.Routing.Outbounds) > 0 {
		for _, ob := range spec.Routing.Outbounds {
			t, _ := ob["tag"].(string)
			if t == "" || t == "direct" || t == "block" || t == "custom-direct" || t == "custom-block" {
				continue
			}
			obType, _ := ob["type"].(string)
			sMap := parseMapOrJSON(ob["settings"])
			validBackups, _, _, _ := ExtractSingboxFallbackSettings(sMap, t)
			if obType == "urltest" || obType == "selector" || len(validBackups) > 0 {
				detourTag = t
				break
			}
		}
		if detourTag == "" {
			for _, ob := range spec.Routing.Outbounds {
				t, _ := ob["tag"].(string)
				if t != "" && t != "direct" && t != "block" && t != "custom-direct" && t != "custom-block" {
					detourTag = t
					break
				}
			}
		}
	}

	if detourTag != "" {
		remoteServerObj := parseSingboxDNSServer("dns-remote", remoteDNS, detourTag)
		servers = append([]map[string]interface{}{remoteServerObj}, directServerObj)
		finalDNS = "dns-remote"

		dnsRules = append(dnsRules, map[string]interface{}{
			"domain_suffix": []string{".ru", ".su", ".рф", ".xn--p1ai"},
			"server":        "dns-direct",
		})
	} else if spec.DNS != nil && spec.DNS.DirectServer == "" && spec.DNS.RemoteServer != "" {
		directDNS = spec.DNS.RemoteServer
		directServerObj = parseSingboxDNSServer("dns-direct", directDNS, "")
		servers = []map[string]interface{}{directServerObj}
	}

	if spec.DNS != nil && spec.DNS.FinalServer != "" {
		finalDNS = spec.DNS.FinalServer
	}

	return map[string]interface{}{
		"servers":  servers,
		"rules":    dnsRules,
		"final":    finalDNS,
		"strategy": strategy,
	}
}
