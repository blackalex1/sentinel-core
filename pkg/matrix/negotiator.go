package matrix

import (
	"errors"
	"github.com/blackalex1/sentinel-core/pkg/ast"
	"github.com/blackalex1/sentinel-core/pkg/i18n"
)

// NegotiationWarning represents an automatic adaptation or feature downgrade
type NegotiationWarning struct {
	Feature   Feature `json:"feature"`
	Message   string  `json:"message"`
	Action    string  `json:"action"`
}

// Negotiator resolves protocol and feature differences between server profiles and target proxy cores.
type Negotiator struct{}

// NewNegotiator creates a new Negotiator instance.
func NewNegotiator() *Negotiator {
	return &Negotiator{}
}

// AutoNegotiate is a convenience function that executes negotiation using a default Negotiator.
func AutoNegotiate(
	node *ast.ServerProfile,
	targetCore ast.TargetCore,
	version string,
	strictMode bool,
) (*ast.ServerProfile, []NegotiationWarning, error) {
	return NewNegotiator().Negotiate(node, targetCore, version, strictMode)
}

// Negotiate checks compatibility and performs graceful feature adaptation or strict failure.
func (n *Negotiator) Negotiate(
	node *ast.ServerProfile,
	targetCore ast.TargetCore,
	version string,
	strictMode bool,
) (*ast.ServerProfile, []NegotiationWarning, error) {
	if node == nil {
		return nil, nil, errors.New(i18n.TGlobal("ERR_SERVER_NODE_NIL"))
	}

	caps := GetCapabilities(targetCore, version)
	var warnings []NegotiationWarning

	// 1. Check Protocol Support
	if !caps.IsProtocolSupported(node.Protocol) {
		return nil, nil, errors.New(i18n.TGlobal("ERR_UNSUPPORTED_PROTOCOL_SUGGEST", targetCore, node.Protocol))
	}

	// Make a shallow copy of the node for adaptations
	adaptedNode := *node

	// 2. Negotiate Post-Quantum Cryptography & VLESS Encryption (ML-KEM / Kyber768 / vlessenc)
	if node.PostQuantum || (node.Encryption != "" && node.Encryption != "none") {
		if !caps.IsFeatureSupported(FeaturePostQuantumTLS) {
			if strictMode {
				return nil, nil, errors.New(i18n.TGlobal("ERR_PQ_STRICT_MODE", node.Name, targetCore, version))
			}
			// Graceful fallback: disable PQ flag and strip VLESS encryption for non-supporting cores
			adaptedNode.PostQuantum = false
			adaptedNode.Encryption = ""
			warnings = append(warnings, NegotiationWarning{
				Feature: FeaturePostQuantumTLS,
				Message: i18n.TGlobal("PQ_DOWNGRADED_SINGBOX", targetCore),
				Action:  "DOWNGRADED_TO_STANDARD_X25519",
			})
		}
	}

	// 3. Negotiate Reality Security
	if node.Security == ast.SecurityReality {
		if !caps.IsFeatureSupported(FeatureReality) {
			return nil, nil, errors.New(i18n.TGlobal("ERR_REALITY_UNSUPPORTED", targetCore, node.Protocol))
		}
	}

	// 4. Negotiate XTLS Vision Flow
	if node.Flow != "" {
		if !caps.IsFeatureSupported(FeatureFlowVision) {
			if strictMode {
				return nil, nil, errors.New(i18n.TGlobal("ERR_FLOW_VISION_STRICT", targetCore, node.Flow))
			}
			adaptedNode.Flow = ""
			warnings = append(warnings, NegotiationWarning{
				Feature: FeatureFlowVision,
				Message: i18n.TGlobal("FLOW_VISION_STRIPPED", node.Flow, targetCore),
				Action:  "STRIPPED_UNSUPPORTED_FLOW",
			})
		}
	}

	return &adaptedNode, warnings, nil
}
