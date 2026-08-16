package main

import (
	"fmt"
	"os"

	"github.com/blackalex1/sentinel-core/pkg/adapter"
)

var exitFunc = os.Exit

// Version can be set at compile time via -ldflags="-X main.Version=1.x.x"
var Version = "1.0.0"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		exitFunc(1)
		return
	}

	command := os.Args[1]

	switch command {
	case "version", "--version", "-v":
		fmt.Printf("Sentinel-Core v%s\n", Version)
		exitFunc(0)
	case "help", "--help", "-h":
		printUsage()
		exitFunc(0)
	case "parse":
		handleParse()
	case "generate":
		handleGenerate()
	case "build":
		handleBuild()
	case "compile-server":
		handleCompileServer()
	case "preset":
		handlePreset()
	case "schema":
		handleSchema()
	case "security":
		handleSecurity()
	case "supervisor":
		handleSupervisor()
	case "keypair":
		handleKeypair()
	case "ping":
		handlePing()
	case "health":
		handleHealth()
	case "encrypt":
		handleEncrypt()
	case "decrypt":
		handleDecrypt()
	case "vlessenc":
		handleVlessEnc()
	default:
		fmt.Printf("Unknown command '%s'\n", command)
		printUsage()
		exitFunc(1)
	}
}

func printUsage() {
	fmt.Printf("Sentinel-Core CLI (Universal Proxy Config Engine) v%s\n", Version)
	fmt.Println("Usage:")
	fmt.Println("  sentinel-core version")
	fmt.Println("  sentinel-core parse --uri <URI>")
	fmt.Println("  sentinel-core build --uri <URI> --core <singbox|xray|hysteria2> [--tun] [--preset ru]")
	fmt.Println("  sentinel-core schema (outputs full configuration capabilities JSON for Panel UI)")
	fmt.Println("  sentinel-core security schema [--lang ru|en] (outputs UI settings schema for Panel tab)")
	fmt.Println("  sentinel-core security default (outputs default security config JSON)")
	fmt.Println("  sentinel-core preset list")
	fmt.Println("  sentinel-core preset show <preset_id>")
	fmt.Println("  sentinel-core health [--socks 10808] [--http 10809]")
	fmt.Println("  sentinel-core encrypt --secret <password> --text <plaintext>")
	fmt.Println("  sentinel-core decrypt --secret <password> --payload <ciphertext>")
}

// Suppress unused adapter import if needed
var _ = adapter.IngestDBNode

