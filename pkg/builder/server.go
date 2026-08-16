package builder

import (
	"fmt"
	"github.com/blackalex1/sentinel-core/pkg/ast"
	"github.com/blackalex1/sentinel-core/pkg/compiler/hysteria"
	"github.com/blackalex1/sentinel-core/pkg/compiler/singbox"
	"github.com/blackalex1/sentinel-core/pkg/compiler/xray"
)

// BuildServerConfig compiles a complete node server configuration for Sentinel-Panel.
func BuildServerConfig(targetCore ast.TargetCore, serverInbounds []ast.ServerInboundSpec, routing *ast.RoutingSpec, clashAPI string, logPathAndLevel ...string) (string, error) {
	if targetCore == "" {
		targetCore = ast.CoreSingBox
	}

	logPath := ""
	if len(logPathAndLevel) > 0 {
		logPath = logPathAndLevel[0]
	}

	lvl := "info"
	if len(logPathAndLevel) > 1 && logPathAndLevel[1] != "" {
		lvl = logPathAndLevel[1]
	}

	if targetCore == ast.CoreHysteria2 {
		if len(serverInbounds) == 0 {
			return "", fmt.Errorf("at least one server inbound required for hysteria2")
		}
		sc := hysteria.NewServerCompiler()
		// If routing rules exist, forward traffic to local Xray SOCKS5 port (20808)
		forwardPort := 0
		if routing != nil && len(routing.Rules) > 0 {
			forwardPort = 20808
		}
		return sc.CompileServer(serverInbounds[0], forwardPort, lvl)
	}

	spec := &ast.ConfigSpec{
		TargetCore:      targetCore,
		ServerInbounds:  serverInbounds,
		Routing:         routing,
		ClashAPIAddress: clashAPI,
		LogLevel:        lvl,
		LogPath:         logPath,
	}

	if targetCore == ast.CoreXray {
		c := xray.NewCompiler()
		cfgJson, _, err := c.Compile(spec)
		if err != nil {
			return "", fmt.Errorf("failed to build Xray server config: %w", err)
		}
		return cfgJson, nil
	}

	c := singbox.NewCompiler()
	cfgJson, _, err := c.Compile(spec)
	if err != nil {
		return "", fmt.Errorf("failed to build Sing-box server config: %w", err)
	}

	return cfgJson, nil
}
