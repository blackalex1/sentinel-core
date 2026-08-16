package hysteria

import (
	"encoding/json"
	"fmt"
	"github.com/blackalex1/sentinel-core/pkg/ast"
	"github.com/blackalex1/sentinel-core/pkg/matrix"
)

// Compiler compiles an ast.ConfigSpec into a complete native Hysteria 2 JSON/YAML client config.
type Compiler struct {
	negotiator *matrix.Negotiator
}

// NewCompiler creates a new Hysteria2 compiler instance.
func NewCompiler() *Compiler {
	return &Compiler{
		negotiator: matrix.NewNegotiator(),
	}
}

// Compile compiles the given specification into a formatted JSON string for Hysteria 2.
func (c *Compiler) Compile(spec *ast.ConfigSpec) (string, []matrix.NegotiationWarning, error) {
	if spec == nil || spec.ServerNode == nil {
		return "", nil, fmt.Errorf("config spec and server node cannot be nil")
	}

	node := spec.ServerNode
	adaptedNode, warnings, err := c.negotiator.Negotiate(
		node,
		ast.CoreHysteria2,
		spec.CoreVersion,
		spec.StrictMode,
	)
	if err != nil {
		return "", nil, fmt.Errorf("feature negotiation failed for hysteria2: %w", err)
	}

	serverAddr := fmt.Sprintf("%s:%d", adaptedNode.Address, adaptedNode.Port)
	if adaptedNode.PortHopping != "" {
		serverAddr = fmt.Sprintf("%s:%s", adaptedNode.Address, adaptedNode.PortHopping)
	}

	authPass := adaptedNode.Password
	if adaptedNode.Username != "" && adaptedNode.Password != "" {
		authPass = adaptedNode.Username + ":" + adaptedNode.Password
	} else if adaptedNode.Password == "" && adaptedNode.Username != "" {
		authPass = adaptedNode.Username
	}

	configObj := map[string]interface{}{
		"server": serverAddr,
		"auth":   authPass,
	}

	// Bandwidth
	bandwidthMap := make(map[string]interface{})
	if adaptedNode.BandwidthUp != "" {
		bandwidthMap["up"] = adaptedNode.BandwidthUp
	}
	if adaptedNode.BandwidthDown != "" {
		bandwidthMap["down"] = adaptedNode.BandwidthDown
	}
	if len(bandwidthMap) > 0 {
		configObj["bandwidth"] = bandwidthMap
	}

	// TLS Settings
	tlsMap := map[string]interface{}{
		"insecure": adaptedNode.Insecure,
	}
	if adaptedNode.SNI != "" {
		tlsMap["sni"] = adaptedNode.SNI
	}
	configObj["tls"] = tlsMap

	// Obfuscation (Salamander)
	if adaptedNode.ObfsPassword != "" {
		obfsType := "salamander"
		if adaptedNode.ObfsType != "" {
			obfsType = adaptedNode.ObfsType
		}
		configObj["obfs"] = map[string]interface{}{
			"type": obfsType,
			"salamander": map[string]interface{}{
				"password": adaptedNode.ObfsPassword,
			},
		}
	}

	// Inbounds (SOCKS5 / HTTP)
	if spec.ClientInbound != nil {
		cb := spec.ClientInbound
		if cb.SocksPort > 0 {
			configObj["socks5"] = map[string]interface{}{
				"listen": fmt.Sprintf("127.0.0.1:%d", cb.SocksPort),
			}
		}
		if cb.HTTPPort > 0 {
			configObj["http"] = map[string]interface{}{
				"listen": fmt.Sprintf("127.0.0.1:%d", cb.HTTPPort),
			}
		}
	} else {
		configObj["socks5"] = map[string]interface{}{
			"listen": "127.0.0.1:10808",
		}
	}

	jsonBytes, err := json.MarshalIndent(configObj, "", "  ")
	if err != nil {
		return "", nil, fmt.Errorf("failed to marshal hysteria config: %w", err)
	}

	return string(jsonBytes), warnings, nil
}
