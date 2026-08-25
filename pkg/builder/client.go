package builder

import (
	"fmt"
	"github.com/blackalex1/sentinel-core/pkg/ast"
	"github.com/blackalex1/sentinel-core/pkg/compiler/hysteria"
	"github.com/blackalex1/sentinel-core/pkg/compiler/singbox"
	"github.com/blackalex1/sentinel-core/pkg/compiler/xray"
	"github.com/blackalex1/sentinel-core/pkg/events"
	"github.com/blackalex1/sentinel-core/pkg/i18n"
	"github.com/blackalex1/sentinel-core/pkg/matrix"
	"github.com/blackalex1/sentinel-core/pkg/routing"
	"github.com/blackalex1/sentinel-core/pkg/security"
)

// BuildResult contains the compiled JSON config and any warnings emitted during compilation
type BuildResult struct {
	TargetCore  ast.TargetCore               `json:"targetCore"`
	ConfigJSON  string                       `json:"configJson"`
	Warnings    []matrix.NegotiationWarning  `json:"warnings,omitempty"`
}

// BuildClientConfig compiles a complete client configuration for the specified target core.
func BuildClientConfig(spec *ast.ConfigSpec) (*BuildResult, error) {
	if spec == nil {
		return nil, fmt.Errorf("config specification cannot be nil")
	}

	targetCore := spec.TargetCore
	if targetCore == "" {
		targetCore = ast.CoreSingBox
	}

	// If no explicit routing spec provided, use the Sentinel Routing Engine Smart Policy
	if spec.Routing == nil {
		engine := routing.NewEngine()
		spec.Routing = engine.CompilePolicy(routing.DefaultSmartPolicy())
	}

	var jsonConfig string
	var warnings []matrix.NegotiationWarning
	var err error

	// Check if native Hysteria2 is requested but routing table or TUN is required
	if targetCore == ast.CoreHysteria2 {
		hasRouting := spec.Routing != nil && len(spec.Routing.Rules) > 0
		hasTun := spec.ClientInbound != nil && (spec.ClientInbound.Mode == ast.InboundModeDesktopTun || spec.ClientInbound.Mode == ast.InboundModeMobileVpn)
		hasServerInbounds := len(spec.ServerInbounds) > 0

		if hasRouting || hasTun || hasServerInbounds {
			if spec.StrictMode {
				return nil, fmt.Errorf("%s", i18n.TGlobal("HY2_STRICT_REJECT"))
			}
			// Auto-switch to Sing-box which natively supports Hysteria 2 + Full Routing Table + TUN
			targetCore = ast.CoreSingBox
			warnings = append(warnings, matrix.NegotiationWarning{
				Feature: matrix.FeatureRouting,
				Message: i18n.TGlobal("HY2_AUTO_SWITCH_SINGBOX"),
				Action:  "AUTO_SWITCH_TO_SINGBOX",
			})
		}
	}

	// Inject active Zero Trust quarantined entities into routing table for cores supporting routing
	if (targetCore == ast.CoreSingBox || targetCore == ast.CoreXray) && spec.Routing != nil {
		blockedEntities := security.GetDefaultSecurityEngine().GetBlockedEntities()
		if len(blockedEntities) > 0 {
			var procNames []string
			for _, be := range blockedEntities {
				if be.CallerID != "" && be.CallerID != "DefaultEntity" {
					procNames = append(procNames, be.CallerID)
				}
			}
			if len(procNames) > 0 {
				quarantineRule := ast.RoutingRule{
					Action:       ast.ActionBlock,
					ProcessNames: procNames,
				}
				spec.Routing.Rules = append([]ast.RoutingRule{quarantineRule}, spec.Routing.Rules...)
			}
		}
	}

	var subWarnings []matrix.NegotiationWarning

	switch targetCore {
	case ast.CoreSingBox:
		c := singbox.NewCompiler()
		jsonConfig, subWarnings, err = c.Compile(spec)
	case ast.CoreXray:
		c := xray.NewCompiler()
		jsonConfig, subWarnings, err = c.Compile(spec)
	case ast.CoreHysteria2:
		c := hysteria.NewCompiler()
		jsonConfig, subWarnings, err = c.Compile(spec)
	default:
		return nil, fmt.Errorf("unsupported target core: %s", targetCore)
	}
	warnings = append(warnings, subWarnings...)

	if err != nil {
		// Emit fatal error event to global bus
		events.GetGlobalBus().Publish(events.NewEvent(
			events.CategoryCompileWarning,
			events.SeverityError,
			events.CodeInvalidConfigSyntax,
			fmt.Sprintf("Compilation failed for core '%s': %v", targetCore, err),
			map[string]interface{}{"targetCore": targetCore},
			events.ActionNone,
		))
		return nil, err
	}

	// Emit any negotiation warnings to global bus
	for _, w := range warnings {
		events.GetGlobalBus().Publish(events.NewEvent(
			events.CategoryCompileWarning,
			events.SeverityWarn,
			events.CodeFeatureDowngrade,
			w.Message,
			map[string]interface{}{
				"feature": w.Feature,
				"action":  w.Action,
			},
			events.ActionNone,
		))
	}

	return &BuildResult{
		TargetCore: targetCore,
		ConfigJSON: jsonConfig,
		Warnings:   warnings,
	}, nil
}

// BuildFailoverClientConfig creates a client configuration with SOCKS5/HTTP inbounds and a multi-node failover/urltest outbound group.
func BuildFailoverClientConfig(profiles []*ast.ServerProfile, targetCore ast.TargetCore, socksPort, httpPort int, healthCheckURL string) (*BuildResult, error) {
	if len(profiles) == 0 {
		return nil, fmt.Errorf("at least one server profile is required")
	}

	if targetCore == "" {
		targetCore = ast.CoreSingBox
	}
	if socksPort <= 0 {
		socksPort = 10808
	}
	if httpPort <= 0 {
		httpPort = 10809
	}
	if healthCheckURL == "" {
		healthCheckURL = "https://api.telegram.org"
	}

	primaryNode := profiles[0]
	primaryCopy := *primaryNode
	primaryCopy.Name = "failover-proxy"
	primaryCopy.HealthCheckURL = healthCheckURL
	primaryCopy.HealthCheckInterval = 15
	primaryCopy.FallbackStrategy = "priority"

	if len(profiles) > 1 {
		primaryCopy.BackupProfiles = profiles[1:]
	}

	spec := &ast.ConfigSpec{
		TargetCore: targetCore,
		ServerNode: &primaryCopy,
		ClientInbound: &ast.ClientInboundSpec{
			Mode:          ast.InboundModeSystemProxy,
			SocksPort:     socksPort,
			HTTPPort:      httpPort,
			ListenAddress: "127.0.0.1",
		},
		Routing: &ast.RoutingSpec{
			DefaultAction: ast.ActionProxy,
			Rules: []ast.RoutingRule{
				{
					Action:      ast.ActionProxy,
					OutboundTag: "failover-proxy",
				},
			},
		},
		LogLevel: "warn",
	}

	return BuildClientConfig(spec)
}

