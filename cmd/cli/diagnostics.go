package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/blackalex1/sentinel-core/pkg/diagnostics"
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
