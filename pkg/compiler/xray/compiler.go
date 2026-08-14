package xray

import (
	"encoding/json"
	"fmt"
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
	outbounds = append(outbounds,
		map[string]interface{}{"protocol": "freedom", "tag": "direct"},
		map[string]interface{}{"protocol": "blackhole", "tag": "block"},
	)

	// 4. Build Routing
	routing := BuildXrayRouting(spec)

	// 5. Build DNS
	dnsConfig := map[string]interface{}{
		"servers": []string{"https://1.1.1.1/dns-query", "8.8.8.8", "localhost"},
	}

	// 6. Log
	logLevel := spec.LogLevel
	if logLevel == "" {
		logLevel = "warning"
	}
	if logLevel == "warn" {
		logLevel = "warning"
	}

	configObj := map[string]interface{}{
		"log": map[string]interface{}{
			"loglevel": logLevel,
		},
		"dns":       dnsConfig,
		"inbounds":  inbounds,
		"outbounds": outbounds,
		"routing":   routing,
	}

	jsonBytes, err := json.MarshalIndent(configObj, "", "  ")
	if err != nil {
		return "", nil, fmt.Errorf("failed to marshal xray config to JSON: %w", err)
	}

	return string(jsonBytes), allWarnings, nil
}
