package xray

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"github.com/blackalex1/sentinel-core/pkg/ast"
	"github.com/blackalex1/sentinel-core/pkg/matrix"
)

func collectUsedLocalPorts(spec *ast.ConfigSpec) map[int]bool {
	used := make(map[int]bool)
	if spec.ClientInbound != nil {
		for _, p := range []int{
			spec.ClientInbound.SocksPort,
			spec.ClientInbound.HTTPPort,
			spec.ClientInbound.LanHTTPPort,
			spec.ClientInbound.LanSocksPort,
		} {
			if p > 0 {
				used[p] = true
			}
		}
	}
	for _, sb := range spec.ServerInbounds {
		if sb.Port > 0 {
			used[sb.Port] = true
		}
	}
	return used
}

func allocateFreeLocalUDPPort(used map[int]bool) int {
	for attempt := 0; attempt < 20; attempt++ {
		pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			continue
		}
		addr, ok := pc.LocalAddr().(*net.UDPAddr)
		_ = pc.Close()
		if ok && addr.Port > 0 && !used[addr.Port] {
			used[addr.Port] = true
			return addr.Port
		}
	}
	for p := 49152; p < 65000; p++ {
		if !used[p] {
			used[p] = true
			return p
		}
	}
	return 54321
}

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

	rawJSON := spec.RawJSONConfig
	if rawJSON == "" && spec.ServerNode != nil {
		rawJSON = spec.ServerNode.RawJSONConfig
	}
	if rawJSON != "" {
		if formatted, handled, err := compileRawXrayConfig(rawJSON, spec); handled {
			return formatted, nil, err
		}
	}

	usedLocalPorts := collectUsedLocalPorts(spec)
	primaryOutbound, chainOutbounds, bridgeInbounds, bridgeRoutingRules, allWarnings, err := c.compilePrimaryOrChainOutbounds(spec, usedLocalPorts)
	if err != nil {
		return "", nil, err
	}

	inbounds := BuildXrayInbounds(spec)
	if len(bridgeInbounds) > 0 {
		inbounds = append(inbounds, bridgeInbounds...)
	}

	outbounds := buildInitialXrayOutbounds(primaryOutbound, chainOutbounds)
	observatory, balancers, backupOutboundMap := appendRoutingOutbounds(spec, &outbounds)

	if len(spec.ServerInbounds) > 0 {
		inbounds = append(inbounds, map[string]interface{}{
			"tag":      "api",
			"port":     10085,
			"listen":   "127.0.0.1",
			"protocol": "dokodemo-door",
			"settings": map[string]interface{}{"address": "127.0.0.1"},
		})
	}
	outbounds = appendDefaultXrayOutbounds(outbounds, len(spec.ServerInbounds) > 0)

	routing := finalizeXrayRouting(spec, bridgeRoutingRules, balancers, backupOutboundMap)
	configObj := map[string]interface{}{
		"log":       buildXrayLogConfig(spec),
		"dns":       buildXrayDNSConfig(spec),
		"inbounds":  inbounds,
		"outbounds": outbounds,
		"routing":   routing,
	}
	if len(spec.ServerInbounds) > 0 {
		applyXrayServerStatsPolicy(configObj)
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

func compileRawXrayConfig(rawJSON string, spec *ast.ConfigSpec) (string, bool, error) {
	var rawConfig map[string]interface{}
	if err := json.Unmarshal([]byte(rawJSON), &rawConfig); err != nil || len(rawConfig) == 0 {
		return "", false, nil
	}

	builtInbounds := BuildXrayInbounds(spec)
	var finalInbounds []interface{}
	for _, bi := range builtInbounds {
		finalInbounds = append(finalInbounds, bi)
	}
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
	ensureRawXrayBalancerFallbacks(rawConfig)

	if spec.LogLevel != "" {
		rawConfig["log"] = map[string]interface{}{"loglevel": spec.LogLevel}
	}

	formatted, err := json.MarshalIndent(rawConfig, "", "  ")
	if err != nil {
		return "", true, fmt.Errorf("failed to format raw xray json config: %w", err)
	}
	return string(formatted), true, nil
}

func ensureRawXrayBalancerFallbacks(rawConfig map[string]interface{}) {
	routing, ok := rawConfig["routing"].(map[string]interface{})
	if !ok {
		return
	}
	balancers, ok := routing["balancers"].([]interface{})
	if !ok {
		return
	}
	for _, b := range balancers {
		bMap, ok := b.(map[string]interface{})
		if !ok {
			continue
		}
		if fallback, _ := bMap["fallbackTag"].(string); fallback != "" {
			continue
		}
		if selList, ok := bMap["selector"].([]interface{}); ok && len(selList) > 0 {
			if s, ok := selList[0].(string); ok && s != "" {
				bMap["fallbackTag"] = s
			}
		} else if selList, ok := bMap["selectors"].([]interface{}); ok && len(selList) > 0 {
			if s, ok := selList[0].(string); ok && s != "" {
				bMap["fallbackTag"] = s
			}
		}
	}
}

func (c *Compiler) compilePrimaryOrChainOutbounds(spec *ast.ConfigSpec, usedLocalPorts map[int]bool) (
	primaryOutbound map[string]interface{},
	chainOutbounds []map[string]interface{},
	bridgeInbounds []map[string]interface{},
	bridgeRoutingRules []map[string]interface{},
	allWarnings []matrix.NegotiationWarning,
	err error,
) {
	if len(spec.ChainNodes) >= 2 {
		for i, node := range spec.ChainNodes {
			adaptedNode, warnings, err := c.negotiator.Negotiate(node, ast.CoreXray, spec.CoreVersion, spec.StrictMode)
			if err != nil {
				return nil, nil, nil, nil, nil, fmt.Errorf("feature negotiation failed for chain hop %d: %w", i+1, err)
			}
			allWarnings = append(allWarnings, warnings...)

			tag := chainHopTag(i+1, node.Name)
			if i > 0 && spec.ChainNodes[i-1].Flow == "xtls-rprx-vision" && adaptedNode.Flow == "xtls-rprx-vision" {
				adaptedNode.Flow = ""
			}

			var outboundObj map[string]interface{}
			if i > 0 && strings.EqualFold(adaptedNode.Protocol, ast.ProtoHysteria2) {
				prevTag := chainHopTag(i, spec.ChainNodes[i-1].Name)
				outboundObj, err = buildChainHysteria2Bridge(tag, prevTag, i+1, adaptedNode, spec.CoreVersion, usedLocalPorts, &bridgeInbounds, &bridgeRoutingRules)
			} else {
				outboundObj, err = buildXrayOutboundWithCoreVersion(tag, adaptedNode, spec.CoreVersion)
				if err == nil && i > 0 {
					attachDialerProxy(outboundObj, chainHopTag(i, spec.ChainNodes[i-1].Name))
				}
			}
			if err != nil {
				return nil, nil, nil, nil, nil, fmt.Errorf("failed to build chain hop %d outbound: %w", i+1, err)
			}
			chainOutbounds = append(chainOutbounds, outboundObj)
		}
		return nil, chainOutbounds, bridgeInbounds, bridgeRoutingRules, allWarnings, nil
	}

	if spec.ServerNode != nil {
		adaptedNode, warnings, err := c.negotiator.Negotiate(spec.ServerNode, ast.CoreXray, spec.CoreVersion, spec.StrictMode)
		if err != nil {
			return nil, nil, nil, nil, nil, fmt.Errorf("feature negotiation failed for xray: %w", err)
		}
		allWarnings = append(allWarnings, warnings...)

		primaryTag := "proxy"
		if adaptedNode.Name != "" {
			primaryTag = adaptedNode.Name
		}
		primaryOutbound, err = buildXrayOutboundWithCoreVersion(primaryTag, adaptedNode, spec.CoreVersion)
		if err != nil {
			return nil, nil, nil, nil, nil, fmt.Errorf("failed to build xray primary outbound: %w", err)
		}
	}
	return primaryOutbound, nil, nil, nil, allWarnings, nil
}

func chainHopTag(hopNum int, name string) string {
	if name != "" {
		return fmt.Sprintf("chain-%d-%s", hopNum, name)
	}
	return fmt.Sprintf("chain-hop-%d", hopNum)
}

func buildChainHysteria2Bridge(
	tag, prevTag string,
	hopNum int,
	adaptedNode *ast.ServerProfile,
	coreVersion string,
	usedLocalPorts map[int]bool,
	bridgeInbounds, bridgeRoutingRules *[]map[string]interface{},
) (map[string]interface{}, error) {
	nodeCopy := *adaptedNode
	if !isLoopbackHost(nodeCopy.Address) {
		origAddr := nodeCopy.Address
		origPort := resolveHysteriaTargetPort(nodeCopy.Port, nodeCopy.PortHopping)
		if nodeCopy.SNI == "" {
			nodeCopy.SNI = origAddr
		}
		bridgePort := allocateFreeLocalUDPPort(usedLocalPorts)
		bridgeTag := fmt.Sprintf("hy2-udp-bridge-%d", hopNum)
		nodeCopy.Address = "127.0.0.1"
		nodeCopy.Port = bridgePort
		nodeCopy.PortHopping = ""

		*bridgeInbounds = append(*bridgeInbounds, map[string]interface{}{
			"tag":      bridgeTag,
			"port":     bridgePort,
			"listen":   "127.0.0.1",
			"protocol": "dokodemo-door",
			"settings": map[string]interface{}{
				"address": origAddr,
				"port":    origPort,
				"network": "udp",
			},
		})
		*bridgeRoutingRules = append(*bridgeRoutingRules, map[string]interface{}{
			"type":        "field",
			"inboundTag":  []string{bridgeTag},
			"outboundTag": prevTag,
		})
	}
	return buildXrayOutboundWithCoreVersion(tag, &nodeCopy, coreVersion)
}

func attachDialerProxy(outboundObj map[string]interface{}, prevTag string) {
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

func buildInitialXrayOutbounds(primaryOutbound map[string]interface{}, chainOutbounds []map[string]interface{}) []map[string]interface{} {
	outbounds := make([]map[string]interface{}, 0)
	if len(chainOutbounds) > 0 {
		// Put exit node (last hop) first so it becomes the default outbound for unmatched traffic
		outbounds = append(outbounds, chainOutbounds[len(chainOutbounds)-1])
		outbounds = append(outbounds, chainOutbounds[:len(chainOutbounds)-1]...)
	} else if primaryOutbound != nil {
		outbounds = append(outbounds, primaryOutbound)
	}
	return outbounds
}

func appendRoutingOutbounds(spec *ast.ConfigSpec, outbounds *[]map[string]interface{}) (map[string]interface{}, []map[string]interface{}, map[string]string) {
	backupOutboundMap := make(map[string]string)
	if spec.Routing == nil || len(spec.Routing.Outbounds) == 0 {
		return nil, nil, backupOutboundMap
	}

	var observatorySubjects []string
	var balancers []map[string]interface{}
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

		settingsMap := parseXrayMapField(ob["settings"])
		if settingsMap == nil {
			settingsMap = make(map[string]interface{})
		}
		proto, settingsMap = normalizeXrayOutboundSettings(proto, settingsMap)

		streamSettingsMap := parseXrayMapField(ob["streamSettings"])
		if streamSettingsMap == nil {
			streamSettingsMap = parseXrayMapField(ob["stream_settings"])
		}

		normalizeXrayVlessOrVmessUsers(proto, settingsMap, streamSettingsMap)

		xrayOb := map[string]interface{}{"protocol": proto, "tag": tag}
		if len(settingsMap) > 0 {
			xrayOb["settings"] = settingsMap
		}
		if streamSettingsMap != nil {
			xrayOb["streamSettings"] = streamSettingsMap
		}
		*outbounds = append(*outbounds, xrayOb)

		if backups, pURL, pInt, strat := ExtractXrayFallbackSettings(settingsMap, tag); len(backups) > 0 {
			balancerTag := fmt.Sprintf("balancer-%s", tag)
			backupOutboundMap[tag] = balancerTag
			probeURL = pURL
			probeInterval = pInt
			observatorySubjects = append(observatorySubjects, tag)
			observatorySubjects = append(observatorySubjects, backups...)
			balancers = append(balancers, BuildXrayBalancer(tag, balancerTag, backups, strat))
		}
	}

	var observatory map[string]interface{}
	if len(observatorySubjects) > 0 {
		observatory = BuildXrayObservatory(observatorySubjects, probeURL, probeInterval)
	}
	return observatory, balancers, backupOutboundMap
}

func parseXrayMapField(raw interface{}) map[string]interface{} {
	switch v := raw.(type) {
	case map[string]interface{}:
		return v
	case string:
		if v != "" {
			var m map[string]interface{}
			_ = json.Unmarshal([]byte(v), &m)
			return m
		}
	}
	return nil
}

func normalizeXrayOutboundSettings(proto string, settingsMap map[string]interface{}) (string, map[string]interface{}) {
	if proto == "hysteria2" || proto == "hysteria" {
		if v, ok := settingsMap["version"]; !ok || v == nil || v == 0 || v == float64(0) {
			settingsMap["version"] = 2
		}
		return "hysteria", settingsMap
	}
	if proto == "socks" {
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
				"servers": []map[string]interface{}{{"address": addr, "port": port}},
			}
		}
	}
	return proto, settingsMap
}

func normalizeXrayVlessOrVmessUsers(proto string, settingsMap, streamSettingsMap map[string]interface{}) {
	if proto != "vless" && proto != "vmess" {
		return
	}
	secVal := ""
	if streamSettingsMap != nil {
		secVal, _ = streamSettingsMap["security"].(string)
	}
	vnextList, ok := settingsMap["vnext"].([]interface{})
	if !ok {
		return
	}
	for _, vn := range vnextList {
		vnMap, ok := vn.(map[string]interface{})
		if !ok {
			continue
		}
		users, ok := vnMap["users"].([]interface{})
		if !ok || len(users) == 0 {
			if proto == "vless" {
				vnMap["users"] = []map[string]interface{}{{"id": "00000000-0000-0000-0000-000000000000", "encryption": "none"}}
			} else {
				vnMap["users"] = []map[string]interface{}{{"id": "00000000-0000-0000-0000-000000000000", "security": "auto"}}
			}
			continue
		}
		for _, u := range users {
			uMap, ok := u.(map[string]interface{})
			if !ok {
				continue
			}
			if proto == "vless" {
				if enc, ok := uMap["encryption"].(string); !ok || enc == "" {
					uMap["encryption"] = "none"
				}
				if secVal != "tls" && secVal != "reality" {
					delete(uMap, "flow")
				}
			} else if sec, ok := uMap["security"].(string); !ok || sec == "" {
				uMap["security"] = "auto"
			}
		}
	}
}

func appendDefaultXrayOutbounds(outbounds []map[string]interface{}, hasServerInbounds bool) []map[string]interface{} {
	present := make(map[string]bool, len(outbounds))
	for _, ob := range outbounds {
		if t, _ := ob["tag"].(string); t != "" {
			present[t] = true
		}
	}
	if !present["dns-out"] {
		outbounds = append(outbounds, map[string]interface{}{"protocol": "dns", "tag": "dns-out"})
	}
	if !present["direct"] {
		outbounds = append(outbounds, map[string]interface{}{"protocol": "freedom", "tag": "direct"})
	}
	if !present["block"] {
		outbounds = append(outbounds, map[string]interface{}{"protocol": "blackhole", "tag": "block"})
	}
	if !present["blocked"] {
		outbounds = append(outbounds, map[string]interface{}{"protocol": "blackhole", "tag": "blocked"})
	}
	if hasServerInbounds && !present["api"] {
		outbounds = append(outbounds, map[string]interface{}{"protocol": "blackhole", "tag": "api"})
	}
	return outbounds
}

func finalizeXrayRouting(spec *ast.ConfigSpec, bridgeRoutingRules, balancers []map[string]interface{}, backupOutboundMap map[string]string) map[string]interface{} {
	routing := BuildXrayRouting(spec)
	if len(bridgeRoutingRules) > 0 {
		if existingRules, ok := routing["rules"].([]map[string]interface{}); ok {
			routing["rules"] = append(bridgeRoutingRules, existingRules...)
		} else {
			routing["rules"] = bridgeRoutingRules
		}
	}
	if len(spec.ServerInbounds) > 0 {
		apiRule := map[string]interface{}{
			"type":        "field",
			"inboundTag":  []string{"api"},
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
	return routing
}

func buildXrayDNSConfig(spec *ast.ConfigSpec) map[string]interface{} {
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

	dnsServers := []interface{}{
		map[string]interface{}{
			"address": directDNS,
			"domains": []string{"domain:ru", "domain:su", "domain:xn--p1ai"},
		},
	}
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
	if spec.DNS != nil && (spec.DNS.Strategy == "ipv6_only" || spec.DNS.Strategy == "prefer_ipv6") {
		qStrategy = "UseIPv6"
	}
	return map[string]interface{}{
		"servers":       dnsServers,
		"queryStrategy": qStrategy,
	}
}

func buildXrayLogConfig(spec *ast.ConfigSpec) map[string]interface{} {
	logLevel := strings.ToLower(strings.TrimSpace(spec.LogLevel))
	if logLevel == "warn" {
		logLevel = "warning"
	}
	if logLevel != "debug" && logLevel != "info" && logLevel != "warning" && logLevel != "error" && logLevel != "none" {
		logLevel = "warning"
	}

	logMap := map[string]interface{}{"loglevel": logLevel}
	if spec.AccessLog != "" {
		if spec.AccessLog == "console" || spec.AccessLog == "stdout" {
			logMap["access"] = ""
		} else {
			logMap["access"] = spec.AccessLog
		}
	} else if spec.LogPath != "" {
		logMap["access"] = spec.LogPath
	} else if logLevel == "warning" || logLevel == "error" || logLevel == "none" {
		logMap["access"] = "none"
	}

	if spec.ErrorLog != "" {
		if spec.ErrorLog == "console" || spec.ErrorLog == "stderr" {
			logMap["error"] = ""
		} else {
			logMap["error"] = spec.ErrorLog
		}
	} else if spec.LogPath != "" {
		logMap["error"] = spec.LogPath
	}
	return logMap
}

func applyXrayServerStatsPolicy(configObj map[string]interface{}) {
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
