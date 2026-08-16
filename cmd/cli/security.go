package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/blackalex1/sentinel-core/pkg/security"
	"github.com/blackalex1/sentinel-core/pkg/supervisor"
)

func handleSecurity() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: sentinel-core security <schema|default|validate|journal|quarantine|unquarantine|status>")
		exitFunc(1)
		return
	}

	action := os.Args[2]
	switch action {
	case "schema":
		fs := flag.NewFlagSet("security-schema", flag.ExitOnError)
		lang := fs.String("lang", "ru", "UI schema language (ru or en)")
		_ = fs.Parse(os.Args[3:])
		schema := security.GenerateSecuritySchema(*lang)
		data, _ := json.MarshalIndent(schema, "", "  ")
		fmt.Println(string(data))

	case "default":
		cfg := security.DefaultSecurityConfig()
		jsonStr, _ := cfg.ToJSON()
		fmt.Println(jsonStr)

	case "validate":
		fs := flag.NewFlagSet("security-validate", flag.ExitOnError)
		cfgStr := fs.String("config", "", "JSON security config string")
		_ = fs.Parse(os.Args[3:])
		if *cfgStr == "" {
			fmt.Println("Error: --config is required")
			exitFunc(1)
			return
		}
		_, err := security.FromJSON(*cfgStr)
		if err != nil {
			fmt.Printf("Validation failed: %v\n", err)
			exitFunc(1)
			return
		}
		fmt.Println(`{"valid": true}`)

	case "journal":
		fs := flag.NewFlagSet("security-journal", flag.ExitOnError)
		filePath := fs.String("file", "", "Path to threats.jsonl file")
		lines := fs.Int("lines", 50, "Number of recent lines to display")
		_ = fs.Parse(os.Args[3:])

		tj, err := security.NewThreatJournal(*filePath, "")
		if err != nil {
			fmt.Printf("Error opening journal: %v\n", err)
			exitFunc(1)
			return
		}

		records, err := tj.ReadRecentRecords(*lines)
		if err != nil {
			fmt.Printf("Error reading journal: %v\n", err)
			exitFunc(1)
			return
		}

		for _, r := range records {
			b, _ := json.Marshal(r)
			fmt.Println(string(b))
		}

	case "quarantine":
		fs := flag.NewFlagSet("security-quarantine", flag.ExitOnError)
		client := fs.String("client", "", "Client ID/Email/UUID to quarantine")
		reason := fs.String("reason", "Manual admin quarantine", "Reason for isolation")
		_ = fs.Parse(os.Args[3:])

		if *client == "" {
			fmt.Println("Error: --client is required")
			exitFunc(1)
			return
		}

		// Instant in-memory kick across all active cores
		ctrl := supervisor.GetController()
		_ = ctrl.KickClient(*client)

		// Record in threat journal
		tj, _ := security.NewThreatJournal("", "")
		if tj != nil {
			_ = tj.LogIncident("QUARANTINED", "ADMIN_ACTION", *client, nil, 100, "QUARANTINED", "ADMIN_COMMAND", *reason, "KICKED_AND_ISOLATED")
		}

		fmt.Printf(`{"status": "quarantined", "client": %q, "reason": %q}`+"\n", *client, *reason)

	case "unquarantine":
		fs := flag.NewFlagSet("security-unquarantine", flag.ExitOnError)
		client := fs.String("client", "", "Client ID/Email/UUID to unquarantine")
		_ = fs.Parse(os.Args[3:])

		if *client == "" {
			fmt.Println("Error: --client is required")
			exitFunc(1)
			return
		}

		tj, _ := security.NewThreatJournal("", "")
		if tj != nil {
			_ = tj.LogIncident("UNQUARANTINED", "ADMIN_ACTION", *client, nil, 0, "CLEAN", "ADMIN_COMMAND", "Manual unblock", "UNBLOCKED")
		}

		fmt.Printf(`{"status": "unquarantined", "client": %q}`+"\n", *client)

	case "status":
		fs := flag.NewFlagSet("security-status", flag.ExitOnError)
		nodeID := fs.String("node-id", "", "Custom node ID")
		_ = fs.Parse(os.Args[3:])

		if *nodeID == "" {
			*nodeID, _ = os.Hostname()
		}

		summary := security.NodeSecuritySummary{
			NodeID:             *nodeID,
			QuarantinedClients: []string{},
			SuspiciousClients:  []security.SuspiciousClientEntry{},
			Timestamp:          0,
		}

		data, _ := json.MarshalIndent(summary, "", "  ")
		fmt.Println(string(data))

	case "ssh-sessions":
		cfg := security.DefaultSecurityConfig()
		sm, err := security.NewSecurityManager(cfg)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			exitFunc(1)
			return
		}
		sessions := sm.SSHMonitor().GetActiveSessions()
		data, _ := json.MarshalIndent(sessions, "", "  ")
		fmt.Println(string(data))

	case "ssh-kill":
		fs := flag.NewFlagSet("security-ssh-kill", flag.ExitOnError)
		pid := fs.Int("pid", 0, "SSHD PID to terminate")
		_ = fs.Parse(os.Args[3:])

		if *pid <= 0 {
			fmt.Println("Error: --pid is required and must be > 0")
			exitFunc(1)
			return
		}

		cfg := security.DefaultSecurityConfig()
		sm, _ := security.NewSecurityManager(cfg)
		err := sm.SSHMonitor().KillSSHSession(*pid)
		if err != nil {
			fmt.Printf("Error killing SSH session: %v\n", err)
			exitFunc(1)
			return
		}
		fmt.Printf(`{"status": "killed", "pid": %d}`+"\n", *pid)

	default:
		fmt.Printf("Unknown security action '%s'\n", action)
		exitFunc(1)
	}
}
