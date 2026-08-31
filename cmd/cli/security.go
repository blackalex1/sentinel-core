package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/blackalex1/sentinel-core/pkg/security"
	"github.com/blackalex1/sentinel-core/pkg/security/detector"
	"github.com/blackalex1/sentinel-core/pkg/security/ingest"
	"github.com/blackalex1/sentinel-core/pkg/security/netfilter"
	"github.com/blackalex1/sentinel-core/pkg/security/ssh"
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

	case "parse-iptables":
		fs := flag.NewFlagSet("security-parse-iptables", flag.ExitOnError)
		line := fs.String("line", "", "Raw iptables log line")
		vmid := fs.Int("vmid", 100, "VPN VMID fallback")
		_ = fs.Parse(os.Args[3:])

		ev := netfilter.ParseIptablesLine(*line, *vmid)
		if ev == nil {
			fmt.Println("{}")
			return
		}
		b, _ := json.Marshal(ev)
		fmt.Println(string(b))

	case "classify":
		fs := flag.NewFlagSet("security-classify", flag.ExitOnError)
		eventJSON := fs.String("event", "", "IptablesEvent JSON string")
		policyJSON := fs.String("policy", "", "ClassifierPolicy JSON string")
		lang := fs.String("lang", "ru", "Language (ru or en)")
		_ = fs.Parse(os.Args[3:])

		var ev netfilter.IptablesEvent
		_ = json.Unmarshal([]byte(*eventJSON), &ev)

		policy := netfilter.DefaultClassifierPolicy()
		if *policyJSON != "" {
			_ = json.Unmarshal([]byte(*policyJSON), &policy)
		}

		res := netfilter.ClassifyConnection(ev, policy, *lang)
		b, _ := json.Marshal(res)
		fmt.Println(string(b))

	case "parse-auth":
		fs := flag.NewFlagSet("security-parse-auth", flag.ExitOnError)
		line := fs.String("line", "", "Raw auth.log / secure log line")
		_ = fs.Parse(os.Args[3:])

		ev, ok := ssh.ParseAuthLine(*line)
		if !ok || ev == nil {
			fmt.Println("{}")
			return
		}
		b, _ := json.Marshal(ev)
		fmt.Println(string(b))

	case "find-vpn-client":
		fs := flag.NewFlagSet("security-find-vpn-client", flag.ExitOnError)
		proto := fs.String("proto", "tcp", "Protocol (tcp or udp)")
		containerIP := fs.String("container-ip", "", "Container IP")
		dstIP := fs.String("dst-ip", "", "Destination IP")
		sport := fs.Int("sport", 0, "Source port")
		dpt := fs.Int("dpt", 0, "Destination port")
		dump := fs.String("dump", "", "Optional conntrack dump string")
		_ = fs.Parse(os.Args[3:])

		res := netfilter.FindRealVPNClientIP(*proto, *containerIP, *dstIP, *sport, *dpt, *dump)
		b, _ := json.Marshal(map[string]string{"client_ip": res})
		fmt.Println(string(b))

	case "find-proxy-client":
		fs := flag.NewFlagSet("security-find-proxy-client", flag.ExitOnError)
		coreType := fs.String("core", "xray", "Core type (xray, singbox, hysteria, hysteria-ip)")
		linesJSON := fs.String("lines", "[]", "JSON array of log lines")
		clientIP := fs.String("client-ip", "", "Client IP")
		dstIP := fs.String("dst-ip", "", "Destination IP")
		emailArg := fs.String("email", "", "Email or User ID")
		dpt := fs.Int("dpt", 0, "Destination port")
		maxAge := fs.Int("max-age", 300, "Max age in seconds")
		_ = fs.Parse(os.Args[3:])

		var lines []string
		_ = json.Unmarshal([]byte(*linesJSON), &lines)

		if *coreType == "hysteria-ip" || (*coreType == "hysteria" && *emailArg != "") {
			ip := detector.FindClientIPForEmailInHysteriaLog(lines, *emailArg, *maxAge)
			b, _ := json.Marshal(map[string]string{"client_ip": ip, "ip": ip})
			fmt.Println(string(b))
		} else if *coreType == "hysteria" {
			email := detector.FindEmailInHysteriaLog(lines, *dstIP, *dpt, *maxAge)
			b, _ := json.Marshal(map[string]string{"email": email})
			fmt.Println(string(b))
		} else {
			email, ip, tag := detector.FindEmailAndIPInXrayLog(lines, *clientIP, *dstIP, *dpt, *maxAge)
			b, _ := json.Marshal(map[string]string{"email": email, "ip": ip, "inbound_tag": tag})
			fmt.Println(string(b))
		}


	case "parse-router":
		fs := flag.NewFlagSet("security-parse-router", flag.ExitOnError)
		line := fs.String("line", "", "Raw router line")
		_ = fs.Parse(os.Args[3:])

		if ev := netfilter.ParseRouterConntrackLine(*line); ev != nil {
			b, _ := json.Marshal(ev)
			fmt.Println(string(b))
			return
		}
		if ev := netfilter.ParseRouterIptablesLine(*line); ev != nil {
			b, _ := json.Marshal(ev)
			fmt.Println(string(b))
			return
		}
		fmt.Println("{}")

	case "process-traffic-line":
		fs := flag.NewFlagSet("security-process-traffic-line", flag.ExitOnError)
		source := fs.String("source", "proxmox_iptables", "Log source (proxmox_iptables, router_conntrack, router_syslog, auth_ssh)")
		line := fs.String("line", "", "Raw log line")
		_ = fs.Parse(os.Args[3:])

		pipeline := ingest.GetDefaultSecurityPipeline()
		var ev *ingest.SecurityEvent
		switch *source {
		case "proxmox_iptables":
			ev = pipeline.ProcessProxmoxIptablesLine(*line)
		case "router_conntrack":
			ev = pipeline.ProcessRouterConntrackLine(*line)
		case "router_syslog":
			ev = pipeline.ProcessRouterIptablesLine(*line)
		case "auth_ssh":
			ev = pipeline.ProcessAuthLogLine(*line)
		}

		if ev != nil {
			b, _ := json.Marshal(ev)
			fmt.Println(string(b))
		} else {
			fmt.Println("{}")
		}

	default:
		fmt.Printf("Unknown security action '%s'\n", action)
		exitFunc(1)
	}
}

