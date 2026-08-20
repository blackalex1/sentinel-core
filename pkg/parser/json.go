package parser

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/blackalex1/sentinel-core/pkg/ast"
)

type XrayStreamSettings struct {
	Network         string                 `json:"network"`
	Security        string                 `json:"security"`
	RealitySettings map[string]interface{} `json:"realitySettings"`
	TLSSettings     map[string]interface{} `json:"tlsSettings"`
	WSSettings      map[string]interface{} `json:"wsSettings"`
	GRPCSettings    map[string]interface{} `json:"grpcSettings"`
	HTTPSettings    map[string]interface{} `json:"httpSettings"`
	TCPSettings     map[string]interface{} `json:"tcpSettings"`
}

type XrayOutbound struct {
	Tag            string                 `json:"tag"`
	Protocol       string                 `json:"protocol"`
	Settings       map[string]interface{} `json:"settings"`
	StreamSettings *XrayStreamSettings    `json:"streamSettings"`
}

type XrayRoutingRule struct {
	Type        string   `json:"type"`
	OutboundTag string   `json:"outboundTag"`
	BalancerTag string   `json:"balancerTag"`
	InboundTag  []string `json:"inboundTag"`
	Network     string   `json:"network"`
	Port        string   `json:"port"`
	Domain      []string `json:"domain"`
	IP          []string `json:"ip"`
}

type XrayBalancer struct {
	Tag      string   `json:"tag"`
	Selector []string `json:"selector"`
}

type XrayRouting struct {
	DomainStrategy string            `json:"domainStrategy"`
	Rules          []XrayRoutingRule `json:"rules"`
	Balancers      []XrayBalancer    `json:"balancers"`
}

type XrayConfigJSON struct {
	ID        string         `json:"id"`
	Remarks   string         `json:"remarks"`
	Outbounds []XrayOutbound `json:"outbounds"`
	Routing   *XrayRouting   `json:"routing"`
}

func isProxyProto(proto string) bool {
	p := strings.ToLower(proto)
	return p != "direct" && p != "freedom" && p != "block" && p != "blackhole" && p != "loopback" && p != "dns" && p != ""
}

// ParseXrayConfigJSON parses an Xray JSON config object into an ast.ServerProfile.
func ParseXrayConfigJSON(rawJSON string) (*ast.ServerProfile, error) {
	var cfg XrayConfigJSON
	if err := json.Unmarshal([]byte(rawJSON), &cfg); err != nil {
		// Also try unmarshaling directly as an XrayOutbound
		var ob XrayOutbound
		if err2 := json.Unmarshal([]byte(rawJSON), &ob); err2 == nil && ob.Protocol != "" {
			return convertOutboundToProfile(&ob, "")
		}
		return nil, fmt.Errorf("failed to unmarshal xray config json: %w", err)
	}

	if len(cfg.Outbounds) == 0 {
		return nil, fmt.Errorf("no outbounds found in xray config")
	}

	// Collect proxy outbounds and map by tag
	var proxyOutbounds []*XrayOutbound
	outboundByTag := make(map[string]*XrayOutbound)
	for i := range cfg.Outbounds {
		ob := &cfg.Outbounds[i]
		if isProxyProto(ob.Protocol) {
			proxyOutbounds = append(proxyOutbounds, ob)
			if ob.Tag != "" {
				outboundByTag[ob.Tag] = ob
			}
		}
	}

	if len(proxyOutbounds) == 0 {
		return nil, fmt.Errorf("no supported proxy outbound found in xray config")
	}

	var targetOb *XrayOutbound

	// 1. If remarks suggest gRPC/TLS/SIM/Anti-jamming bypass, prioritize matching streamSettings
	remLower := strings.ToLower(cfg.Remarks)
	if strings.Contains(remLower, "sim") || strings.Contains(remLower, "глушил") || strings.Contains(remLower, "grpc") {
		for _, ob := range proxyOutbounds {
			if ob.StreamSettings != nil && strings.ToLower(ob.StreamSettings.Network) == "grpc" {
				targetOb = ob
				break
			}
		}
	}

	// 2. Check routing rules for target outbound
	if targetOb == nil && cfg.Routing != nil {
		for _, rule := range cfg.Routing.Rules {
			if rule.OutboundTag != "" && isProxyProto(rule.OutboundTag) {
				if ob, ok := outboundByTag[rule.OutboundTag]; ok {
					targetOb = ob
					break
				}
			}
		}
		if targetOb == nil {
			for _, b := range cfg.Routing.Balancers {
				for _, sel := range b.Selector {
					for _, ob := range proxyOutbounds {
						if strings.HasPrefix(ob.Tag, sel) || ob.Tag == sel {
							targetOb = ob
							break
						}
					}
					if targetOb != nil {
						break
					}
				}
				if targetOb != nil {
					break
				}
			}
		}
	}

	// 3. Fallback to the first proxy outbound
	if targetOb == nil {
		targetOb = proxyOutbounds[0]
	}

	profile, err := convertOutboundToProfile(targetOb, cfg.Remarks)
	if err != nil {
		return nil, err
	}
	if cfg.Remarks != "" {
		profile.Name = cfg.Remarks
	}
	profile.RawJSONConfig = rawJSON
	return profile, nil
}

func convertOutboundToProfile(ob *XrayOutbound, defaultName string) (*ast.ServerProfile, error) {
	proto := strings.ToLower(ob.Protocol)
	profile := &ast.ServerProfile{
		Protocol: proto,
		Name:     defaultName,
	}
	if profile.Name == "" {
		profile.Name = ob.Tag
	}

	// Parse settings
	if ob.Settings != nil {
		switch proto {
		case ast.ProtoVLESS, ast.ProtoVMess:
			if vnext, ok := ob.Settings["vnext"].([]interface{}); ok && len(vnext) > 0 {
				if firstV, ok := vnext[0].(map[string]interface{}); ok {
					profile.Address, _ = firstV["address"].(string)
					profile.Port = getIntVal(firstV["port"])
					if users, ok := firstV["users"].([]interface{}); ok && len(users) > 0 {
						if firstU, ok := users[0].(map[string]interface{}); ok {
							profile.UUID, _ = firstU["id"].(string)
							profile.Flow, _ = firstU["flow"].(string)
							profile.Encryption, _ = firstU["encryption"].(string)
						}
					}
				}
			}
		case ast.ProtoTrojan, ast.ProtoShadowsocks:
			if servers, ok := ob.Settings["servers"].([]interface{}); ok && len(servers) > 0 {
				if firstS, ok := servers[0].(map[string]interface{}); ok {
					profile.Address, _ = firstS["address"].(string)
					profile.Port = getIntVal(firstS["port"])
					profile.Password, _ = firstS["password"].(string)
					if method, ok := firstS["method"].(string); ok {
						profile.Cipher = method
					}
					if cipher, ok := firstS["cipher"].(string); ok {
						profile.Cipher = cipher
					}
				}
			}
		case ast.ProtoSocks, ast.ProtoHTTP:
			if servers, ok := ob.Settings["servers"].([]interface{}); ok && len(servers) > 0 {
				if firstS, ok := servers[0].(map[string]interface{}); ok {
					profile.Address, _ = firstS["address"].(string)
					profile.Port = getIntVal(firstS["port"])
					if users, ok := firstS["users"].([]interface{}); ok && len(users) > 0 {
						if firstU, ok := users[0].(map[string]interface{}); ok {
							profile.Username, _ = firstU["user"].(string)
							profile.Password, _ = firstU["pass"].(string)
						}
					}
				}
			}
		}
	}

	// Parse streamSettings
	if ob.StreamSettings != nil {
		ss := ob.StreamSettings
		profile.Transport = ss.Network
		profile.Security = ss.Security

		if ss.RealitySettings != nil {
			profile.Security = ast.SecurityReality
			profile.SNI, _ = ss.RealitySettings["serverName"].(string)
			profile.PublicKey, _ = ss.RealitySettings["publicKey"].(string)
			profile.ShortID, _ = ss.RealitySettings["shortId"].(string)
			profile.SpiderX, _ = ss.RealitySettings["spiderX"].(string)
			profile.Fingerprint, _ = ss.RealitySettings["fingerprint"].(string)
		}

		if ss.TLSSettings != nil {
			if profile.Security == "" || profile.Security == ast.SecurityNone {
				profile.Security = ast.SecurityTLS
			}
			if s, ok := ss.TLSSettings["serverName"].(string); ok && s != "" {
				profile.SNI = s
			}
			if fp, ok := ss.TLSSettings["fingerprint"].(string); ok {
				profile.Fingerprint = fp
			}
			if pin, ok := ss.TLSSettings["pinnedPeerCertSha256"].(string); ok {
				profile.PinnedPeerCertSha256 = pin
			}
			if insec, ok := ss.TLSSettings["allowInsecure"].(bool); ok {
				profile.Insecure = insec
			}
			if alpnList, ok := ss.TLSSettings["alpn"].([]interface{}); ok {
				for _, item := range alpnList {
					if str, ok := item.(string); ok && str != "" {
						profile.ALPN = append(profile.ALPN, str)
					}
				}
			}
		}

		if ss.GRPCSettings != nil {
			profile.Transport = ast.TransportGRPC
			profile.ServiceName, _ = ss.GRPCSettings["serviceName"].(string)
			if auth, ok := ss.GRPCSettings["authority"].(string); ok && auth != "" {
				profile.Host = auth
			}
		}

		if ss.WSSettings != nil {
			profile.Transport = ast.TransportWS
			profile.Path, _ = ss.WSSettings["path"].(string)
			if headers, ok := ss.WSSettings["headers"].(map[string]interface{}); ok {
				if host, ok := headers["Host"].(string); ok && host != "" {
					profile.Host = host
				}
			}
		}
	}

	if profile.Address == "" || profile.Port <= 0 {
		return nil, fmt.Errorf("invalid server address '%s' or port %d in outbound %s", profile.Address, profile.Port, ob.Tag)
	}

	profile.Normalize()
	return profile, nil
}

func getIntVal(v interface{}) int {
	switch val := v.(type) {
	case float64:
		return int(val)
	case int:
		return val
	case string:
		p, _ := strconv.Atoi(val)
		return p
	default:
		return 0
	}
}
