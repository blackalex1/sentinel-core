package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"github.com/blackalex1/sentinel-core/pkg/adapter"
	"github.com/blackalex1/sentinel-core/pkg/ast"
	"github.com/blackalex1/sentinel-core/pkg/builder"
	"github.com/blackalex1/sentinel-core/pkg/crypto"
	"github.com/blackalex1/sentinel-core/pkg/diagnostics"
	"github.com/blackalex1/sentinel-core/pkg/matrix"
	"github.com/blackalex1/sentinel-core/pkg/parser"
	"github.com/blackalex1/sentinel-core/pkg/routing"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]

	switch command {
	case "parse":
		handleParse()
	case "build":
		handleBuild()
	case "compile-server":
		handleCompileServer()
	case "preset":
		handlePreset()
	case "schema":
		handleSchema()
	case "health":
		handleHealth()
	case "encrypt":
		handleEncrypt()
	case "decrypt":
		handleDecrypt()
	default:
		fmt.Printf("Unknown command '%s'\n", command)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("Sentinel-Core CLI (Universal Proxy Config Engine)")
	fmt.Println("Usage:")
	fmt.Println("  sentinel-core parse --uri <URI>")
	fmt.Println("  sentinel-core build --uri <URI> --core <singbox|xray|hysteria2> [--tun] [--preset ru]")
	fmt.Println("  sentinel-core schema (outputs full configuration capabilities JSON for Panel UI)")
	fmt.Println("  sentinel-core preset list")
	fmt.Println("  sentinel-core preset show <preset_id>")
	fmt.Println("  sentinel-core health [--socks 10808] [--http 10809]")
	fmt.Println("  sentinel-core encrypt --secret <password> --text <plaintext>")
	fmt.Println("  sentinel-core decrypt --secret <password> --payload <ciphertext>")
}

func handleParse() {
	fs := flag.NewFlagSet("parse", flag.ExitOnError)
	uri := fs.String("uri", "", "Proxy URI (vless://, hy2://, trojan://, ss://, etc.)")
	_ = fs.Parse(os.Args[2:])

	if *uri == "" {
		fmt.Println("Error: --uri is required")
		os.Exit(1)
	}

	profile, err := parser.ParseURI(*uri)
	if err != nil {
		fmt.Printf("Parse error: %v\n", err)
		os.Exit(1)
	}

	jsonStr, _ := profile.ToJSON()
	fmt.Println(jsonStr)
}

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
		os.Exit(1)
	}

	profile, err := parser.ParseURI(*uri)
	if err != nil {
		fmt.Printf("Parse error: %v\n", err)
		os.Exit(1)
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
				os.Exit(1)
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
		os.Exit(1)
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

func handleHealth() {
	fs := flag.NewFlagSet("health", flag.ExitOnError)
	socksPort := fs.Int("socks", 10808, "SOCKS port to check")
	httpPort := fs.Int("http", 10809, "HTTP port to check")
	_ = fs.Parse(os.Args[2:])

	report := diagnostics.RunHealthCheck(*socksPort, *httpPort, "one.one.one.one", "test-secret")
	fmt.Printf("Health Check Result: Passed=%v\n", report.Passed)
	fmt.Printf("DNS Resolving: %v (Latency: %d ms)\n", report.DNSResolving, report.DNSLatencyMs)
	fmt.Printf("Crypto Vault OK: %v\n", report.CryptoVaultOK)
	for _, pr := range report.PortResults {
		status := "FREE"
		if !pr.IsFree {
			status = "IN USE"
		}
		fmt.Printf("Port %d: %s\n", pr.Port, status)
	}
	if len(report.Issues) > 0 {
		fmt.Println("Issues:")
		for _, is := range report.Issues {
			fmt.Printf(" - %s\n", is)
		}
	}
}

func handleEncrypt() {
	fs := flag.NewFlagSet("encrypt", flag.ExitOnError)
	secret := fs.String("secret", "", "Master secret key")
	text := fs.String("text", "", "Plaintext to encrypt")
	_ = fs.Parse(os.Args[2:])

	if *secret == "" || *text == "" {
		fmt.Println("Error: --secret and --text are required")
		os.Exit(1)
	}

	vault, err := crypto.NewVault(*secret)
	if err != nil {
		fmt.Printf("Vault error: %v\n", err)
		os.Exit(1)
	}

	enc, err := vault.EncryptString(*text)
	if err != nil {
		fmt.Printf("Encrypt error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(enc)
}

func handleDecrypt() {
	fs := flag.NewFlagSet("decrypt", flag.ExitOnError)
	secret := fs.String("secret", "", "Master secret key")
	payload := fs.String("payload", "", "Ciphertext to decrypt")
	_ = fs.Parse(os.Args[2:])

	if *secret == "" || *payload == "" {
		fmt.Println("Error: --secret and --payload are required")
		os.Exit(1)
	}

	vault, err := crypto.NewVault(*secret)
	if err != nil {
		fmt.Printf("Vault error: %v\n", err)
		os.Exit(1)
	}

	dec, err := vault.DecryptString(*payload)
	if err != nil {
		fmt.Printf("Decrypt error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(dec)
}

func handlePreset() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: sentinel-core preset <list|show|import> [args...]")
		os.Exit(1)
	}

	subCmd := os.Args[2]
	pm := routing.GetPresetManager()

	switch subCmd {
	case "list":
		if len(os.Args) > 3 && os.Args[3] == "--json" {
			presets := routing.GetAvailablePresets()
			bytes, _ := json.MarshalIndent(presets, "", "  ")
			fmt.Println(string(bytes))
			return
		}
		presets := pm.ListPresets()
		fmt.Println("Available Routing Presets:")
		for _, p := range presets {
			rules := p.GetRules("")
			fmt.Printf("  • %-15s : %s\n    %s (Matchers: %d)\n", p.ID, p.Name, p.Description, len(rules))
		}

	case "show":
		if len(os.Args) < 4 {
			fmt.Println("Usage: sentinel-core preset show <preset_id>")
			os.Exit(1)
		}
		id := os.Args[3]
		jsonStr, err := pm.ExportPresetJSON(id)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(jsonStr)

	case "import":
		if len(os.Args) < 4 {
			fmt.Println("Usage: sentinel-core preset import <preset_file.json>")
			os.Exit(1)
		}
		filePath := os.Args[3]
		p, err := pm.LoadPresetFile(filePath)
		if err != nil {
			fmt.Printf("Import failed: %v\n", err)
			os.Exit(1)
		}
		rules := p.GetRules("")
		fmt.Printf("Successfully imported preset '%s' (%s) with %d rules\n", p.ID, p.Name, len(rules))

	default:
		fmt.Printf("Unknown preset command '%s'\n", subCmd)
		os.Exit(1)
	}
}

func handleSchema() {
	fs := flag.NewFlagSet("schema", flag.ExitOnError)
	lang := fs.String("lang", "ru", "Language for schema descriptions (ru, en)")
	if len(os.Args) > 2 {
		_ = fs.Parse(os.Args[2:])
	}
	schema := matrix.GetConfigurationSchema(*lang)
	bytes, err := json.MarshalIndent(schema, "", "  ")
	if err != nil {
		fmt.Printf("Schema error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(bytes))
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
			os.Exit(1)
		}
	} else {
		rawJSON, err = io.ReadAll(os.Stdin)
		if err != nil {
			fmt.Printf("Stdin error: %v\n", err)
			os.Exit(1)
		}
	}

	var spec ast.ConfigSpec
	if err := json.Unmarshal(rawJSON, &spec); err != nil {
		fmt.Printf("JSON unmarshal error: %v\n", err)
		os.Exit(1)
	}

	cfg, err := builder.BuildServerConfig(spec.TargetCore, spec.ServerInbounds, spec.Routing, spec.ClashAPIAddress)
	if err != nil {
		fmt.Printf("Build error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(cfg)
}

// Suppress unused adapter import if needed
var _ = adapter.IngestDBNode

