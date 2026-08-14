package matrix

import (
	"strings"
	"github.com/blackalex1/sentinel-core/pkg/ast"
)

// Feature identifiers
type Feature string

const (
	FeaturePostQuantumTLS Feature = "post_quantum_tls" // X25519Kyber768 / ML-KEM
	FeatureReality        Feature = "reality"
	FeatureFlowVision     Feature = "flow_vision" // xtls-rprx-vision
	FeatureTUIC           Feature = "tuic_v5"
	FeatureShadowTLS      Feature = "shadowtls"
	FeatureHysteria2      Feature = "hysteria2"
	FeatureSalamander     Feature = "salamander_obfs"
	FeaturePortHopping    Feature = "port_hopping"
	FeatureRuleSet        Feature = "rule_set_srs" // Sing-box 1.12+ binary rule sets
	FeatureXHTTP          Feature = "xhttp_splithttp"
	FeatureHTTPUpgrade    Feature = "http_upgrade"
	FeatureMux            Feature = "multiplex"
	FeatureClashAPI       Feature = "clash_api"
	FeatureRouting        Feature = "routing_rules"    // Complex domain/IP/Geo routing
	FeatureChainedInbound Feature = "chained_inbounds" // Multi-inbound to multi-outbound routing
	FeatureTun            Feature = "tun_interface"    // Native TUN / Wintun support
)

// CoreCapabilities defines supported features for a specific core and version range
type CoreCapabilities struct {
	Core            ast.TargetCore
	MinVersion      string
	MaxVersion      string
	SupportedProtos map[string]bool
	SupportedFeatures map[Feature]bool
}

// GetCapabilities returns the capability profile for a given target core and version
func GetCapabilities(core ast.TargetCore, version string) *CoreCapabilities {
	coreStr := strings.ToLower(string(core))

	switch coreStr {
	case "xray", "xray-core":
		return &CoreCapabilities{
			Core: ast.CoreXray,
			SupportedProtos: map[string]bool{
				ast.ProtoVLESS:       true,
				ast.ProtoVMess:       true,
				ast.ProtoTrojan:      true,
				ast.ProtoShadowsocks: true,
				ast.ProtoWireGuard:   true,
				ast.ProtoHysteria2:   true, // Supported via local loopback chain
				ast.ProtoSocks:       true,
				ast.ProtoHTTP:        true,
				ast.ProtoDirect:      true,
				ast.ProtoBlock:       true,
			},
			SupportedFeatures: map[Feature]bool{
				FeaturePostQuantumTLS: true, // Xray supports X25519Kyber768 and PQ TLS
				FeatureReality:        true,
				FeatureFlowVision:     true,
				FeatureXHTTP:          true,
				FeatureHTTPUpgrade:    true,
				FeatureMux:            true,
				FeatureRouting:        true,
				FeatureChainedInbound: true,
			},
		}

	case "singbox", "sing-box":
		isV112OrNewer := isVersionGe(version, "1.12.0")
		return &CoreCapabilities{
			Core: ast.CoreSingBox,
			SupportedProtos: map[string]bool{
				ast.ProtoVLESS:       true,
				ast.ProtoVMess:       true,
				ast.ProtoTrojan:      true,
				ast.ProtoShadowsocks: true,
				ast.ProtoShadowTLS:   true,
				ast.ProtoHysteria2:   true,
				ast.ProtoTUIC:        true,
				ast.ProtoWireGuard:   true,
				ast.ProtoSocks:       true,
				ast.ProtoHTTP:        true,
				ast.ProtoDirect:      true,
				ast.ProtoBlock:       true,
			},
			SupportedFeatures: map[Feature]bool{
				FeaturePostQuantumTLS: false, // Standard Sing-box does not yet enable Kyber curves by default
				FeatureReality:        true,
				FeatureFlowVision:     true,
				FeatureTUIC:           true,
				FeatureShadowTLS:      true,
				FeatureHysteria2:      true,
				FeatureSalamander:     true,
				FeatureRuleSet:        isV112OrNewer,
				FeatureMux:            true,
				FeatureClashAPI:       true,
				FeatureRouting:        true,
				FeatureChainedInbound: true,
				FeatureTun:            true,
			},
		}

	case "hysteria", "hysteria2", "hy2":
		return &CoreCapabilities{
			Core: ast.CoreHysteria2,
			SupportedProtos: map[string]bool{
				ast.ProtoHysteria2: true,
				ast.ProtoDirect:    true,
				ast.ProtoBlock:     true,
			},
			SupportedFeatures: map[Feature]bool{
				FeatureHysteria2:       true,
				FeatureSalamander:      true,
				FeaturePortHopping:     true,
				FeatureRouting:        false, // Native Hysteria 2 client does not support routing table
				FeatureChainedInbound: false, // Native Hysteria 2 client does not support chained inbounds
				FeatureTun:            false,
			},
		}

	case "wireguard", "wg":
		return &CoreCapabilities{
			Core: ast.CoreWireGuard,
			SupportedProtos: map[string]bool{
				ast.ProtoWireGuard: true,
			},
			SupportedFeatures: map[Feature]bool{},
		}

	default:
		return &CoreCapabilities{
			Core:              core,
			SupportedProtos:   map[string]bool{},
			SupportedFeatures: map[Feature]bool{},
		}
	}
}

// IsProtocolSupported checks if a protocol is supported by the target core
func (c *CoreCapabilities) IsProtocolSupported(proto string) bool {
	return c.SupportedProtos[strings.ToLower(proto)]
}

// IsFeatureSupported checks if a specific feature flag is supported
func (c *CoreCapabilities) IsFeatureSupported(feat Feature) bool {
	return c.SupportedFeatures[feat]
}

// Simple semver comparison helper
func isVersionGe(actual, target string) bool {
	if actual == "" {
		return true // Default assume latest version if unspecified
	}
	actualClean := strings.TrimPrefix(actual, "v")
	targetClean := strings.TrimPrefix(target, "v")
	return actualClean >= targetClean
}
