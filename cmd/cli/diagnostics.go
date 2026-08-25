package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/blackalex1/sentinel-core/pkg/ast"
	"github.com/blackalex1/sentinel-core/pkg/builder"
	"github.com/blackalex1/sentinel-core/pkg/diagnostics"
	"github.com/blackalex1/sentinel-core/pkg/parser"
)

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

func handlePing() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: sentinel-core ping <host> [--port <int>] [--timeout-ms <int>]")
		exitFunc(1)
		return
	}
	host := os.Args[2]
	pingCmd := flag.NewFlagSet("ping", flag.ExitOnError)
	port := pingCmd.Int("port", 443, "Target port")
	timeoutMs := pingCmd.Int("timeout-ms", 3000, "Timeout in milliseconds")
	_ = pingCmd.Parse(os.Args[3:])

	res := diagnostics.PingHostPort(host, *port, time.Duration(*timeoutMs)*time.Millisecond)
	data, _ := json.MarshalIndent(res, "", "  ")
	fmt.Println(string(data))
}

func handleCheckProxies() {
	fs := flag.NewFlagSet("check-proxies", flag.ExitOnError)
	file := fs.String("file", "", "Path to file containing proxies or subscription URIs (one per line)")
	target := fs.String("target", "api.telegram.org", "Target host for probe (e.g. api.telegram.org or cp.cloudflare.com)")
	port := fs.Int("port", 443, "Target port")
	useTLS := fs.Bool("tls", true, "Use TLS for probe")
	timeoutMs := fs.Int("timeout-ms", 3500, "Timeout in milliseconds")
	concurrency := fs.Int("concurrency", 64, "Max concurrent checks")
	_ = fs.Parse(os.Args[2:])

	if *file == "" {
		fmt.Println("Error: --file is required")
		exitFunc(1)
		return
	}

	content, err := os.ReadFile(*file)
	if err != nil {
		fmt.Printf("Error reading file: %v\n", err)
		exitFunc(1)
		return
	}

	var proxies []string
	for _, l := range strings.Split(string(content), "\n") {
		line := strings.TrimSpace(l)
		if line != "" && !strings.HasPrefix(line, "#") && !strings.HasPrefix(line, "//") {
			proxies = append(proxies, line)
		}
	}

	results := diagnostics.BatchCheckProxies(proxies, *target, *port, *useTLS, time.Duration(*timeoutMs)*time.Millisecond, *concurrency)
	data, _ := json.MarshalIndent(results, "", "  ")
	fmt.Println(string(data))
}

func handleBuildFailover() {
	fs := flag.NewFlagSet("build-failover", flag.ExitOnError)
	file := fs.String("file", "", "Path to file containing subscription or JSON array of profiles")
	coreName := fs.String("core", "singbox", "Target core (singbox or xray)")
	socksPort := fs.Int("socks", 10808, "Local SOCKS5 port")
	httpPort := fs.Int("http", 10809, "Local HTTP port")
	healthURL := fs.String("url", "https://api.telegram.org", "Health check URL for failover probing")
	_ = fs.Parse(os.Args[2:])

	if *file == "" {
		fmt.Println("Error: --file is required")
		exitFunc(1)
		return
	}

	content, err := os.ReadFile(*file)
	if err != nil {
		fmt.Printf("Error reading file: %v\n", err)
		exitFunc(1)
		return
	}

	// Try parsing as JSON array of ServerProfile first, fallback to ParseSubscription
	var profiles []*ast.ServerProfile
	if jsonErr := json.Unmarshal(content, &profiles); jsonErr != nil || len(profiles) == 0 {
		subProfiles, subErr := parser.ParseSubscription(string(content))
		if subErr != nil || len(subProfiles) == 0 {
			fmt.Printf("Error parsing profiles or subscription: %v\n", subErr)
			exitFunc(1)
			return
		}
		profiles = subProfiles
	}

	res, err := builder.BuildFailoverClientConfig(profiles, ast.TargetCore(*coreName), *socksPort, *httpPort, *healthURL)
	if err != nil {
		fmt.Printf("Build error: %v\n", err)
		exitFunc(1)
		return
	}

	fmt.Println(res.ConfigJSON)
}


