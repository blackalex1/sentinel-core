package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/blackalex1/sentinel-core/pkg/ast"
	"github.com/blackalex1/sentinel-core/pkg/builder"
	"github.com/blackalex1/sentinel-core/pkg/parser"
	"github.com/blackalex1/sentinel-core/pkg/routing"
)

func handleBuild() {
	fs := flag.NewFlagSet("build", flag.ExitOnError)
	uri := fs.String("uri", "", "Proxy URI")
	core := fs.String("core", "singbox", "Target core (singbox, xray, hysteria2)")
	tun := fs.Bool("tun", false, "Enable TUN mode inbound")
	socksPort := fs.Int("socks", 10808, "SOCKS5 listen port")
	httpPort := fs.Int("http", 10809, "HTTP listen port")
	presetName := fs.String("preset", "", "Named preset or path to .json preset (ru, ads, bittorrent, cn, us, ip_checkers)")
	smart := fs.Bool("smart", true, "Apply Smart Routing policy (AdBlock, RU bypass)")
	bypassRu := fs.Bool("bypass-ru", true, "Bypass Russian domains and GeoIP")
	blockAds := fs.Bool("block-ads", true, "Block ads and trackers")
	_ = fs.Parse(os.Args[2:])

	if *uri == "" {
		fmt.Println("Error: --uri is required")
		exitFunc(1)
		return
	}

	profile, err := parser.ParseURI(*uri)
	if err != nil {
		fmt.Printf("Parse error: %v\n", err)
		exitFunc(1)
		return
	}

	inboundMode := ast.InboundModeSystemProxy
	if *tun {
		inboundMode = ast.InboundModeDesktopTun
	}

	var compiledRouting *ast.RoutingSpec

	if *presetName != "" {
		pm := routing.GetPresetManager()
		// Try to compile named preset or load from file
		spec, err := pm.CompilePreset(*presetName)
		if err != nil {
			// Try as file path
			presetObj, fileErr := pm.LoadPresetFile(*presetName)
			if fileErr != nil {
				fmt.Printf("Error loading preset '%s': %v\n", *presetName, err)
				exitFunc(1)
				return
			}
			table := &routing.RoutingTable{
				DefaultTarget: "proxy",
				Rules:         append([]routing.RoutingRuleRow{{Order: 1, Name: "Private LAN", Enabled: true, Target: "direct", IPs: []string{"geoip:private"}}}, presetObj.GetRules("")...),
			}
			spec = table.CompileToAST()
		}
		compiledRouting = spec
	} else {
		enabledPresets := make([]string, 0)
		if *blockAds {
			enabledPresets = append(enabledPresets, "ads")
		}
		if *bypassRu {
			enabledPresets = append(enabledPresets, "ru")
		}
		mode := routing.ModeSmartRule
		if !*smart {
			mode = routing.ModeGlobalProxy
			enabledPresets = []string{"global_proxy"}
		}
		policy := &routing.RoutingPolicy{
			Mode:           mode,
			EnabledPresets: enabledPresets,
		}
		routingEngine := routing.NewEngine()
		compiledRouting = routingEngine.CompilePolicy(policy)
	}

	spec := &ast.ConfigSpec{
		TargetCore: ast.TargetCore(*core),
		ServerNode: profile,
		ClientInbound: &ast.ClientInboundSpec{
			Mode:      inboundMode,
			SocksPort: *socksPort,
			HTTPPort:  *httpPort,
		},
		Routing: compiledRouting,
	}

	res, err := builder.BuildClientConfig(spec)
	if err != nil {
		fmt.Printf("Build error: %v\n", err)
		exitFunc(1)
		return
	}

	if len(res.Warnings) > 0 {
		fmt.Println("// --- Warnings ---")
		for _, w := range res.Warnings {
			fmt.Printf("// [WARN] %s (%s)\n", w.Message, w.Action)
		}
		fmt.Println("// ----------------")
	}

	fmt.Println(res.ConfigJSON)
}

func handleCompileServer() {
	fs := flag.NewFlagSet("compile-server", flag.ExitOnError)
	specStr := fs.String("spec", "", "ConfigSpec JSON string")
	specFile := fs.String("file", "", "ConfigSpec JSON file path")
	if len(os.Args) > 2 {
		_ = fs.Parse(os.Args[2:])
	}

	var rawJSON []byte
	var err error

	if *specStr != "" {
		rawJSON = []byte(*specStr)
	} else if *specFile != "" {
		rawJSON, err = os.ReadFile(*specFile)
		if err != nil {
			fmt.Printf("File error: %v\n", err)
			exitFunc(1)
			return
		}
	} else {
		rawJSON, err = io.ReadAll(os.Stdin)
		if err != nil {
			fmt.Printf("Stdin error: %v\n", err)
			exitFunc(1)
			return
		}
	}

	var spec ast.ConfigSpec
	if err := json.Unmarshal(rawJSON, &spec); err != nil {
		fmt.Printf("JSON unmarshal error: %v\n", err)
		exitFunc(1)
		return
	}

	cfg, err := builder.BuildServerConfig(spec.TargetCore, spec.ServerInbounds, spec.Routing, spec.ClashAPIAddress, spec.LogPath, spec.LogLevel)
	if err != nil {
		fmt.Printf("Build error: %v\n", err)
		exitFunc(1)
		return
	}

	fmt.Println(cfg)
}
