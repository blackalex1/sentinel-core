package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/blackalex1/sentinel-core/pkg/supervisor"
)

func handleSupervisor() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: sentinel-core supervisor <status|traffic|kick|logs|start|stop|restart|validate|version> [options]")
		exitFunc(1)
		return
	}
	action := os.Args[2]
	ctrl := supervisor.GetController()

	switch action {
	case "status":
		status := ctrl.GetStatus()
		data, _ := json.MarshalIndent(status, "", "  ")
		fmt.Println(string(data))
	case "traffic":
		traffic, err := ctrl.GetUnifiedTraffic()
		if err != nil {
			fmt.Printf("Traffic error: %v\n", err)
			exitFunc(1)
			return
		}
		data, _ := json.MarshalIndent(traffic, "", "  ")
		fmt.Println(string(data))
	case "kick":
		kickCmd := flag.NewFlagSet("kick", flag.ExitOnError)
		client := kickCmd.String("client", "", "Client email to disconnect")
		_ = kickCmd.Parse(os.Args[3:])
		if *client == "" {
			fmt.Println("Error: --client is required")
			exitFunc(1)
			return
		}
		if err := ctrl.KickClient(*client); err != nil {
			fmt.Printf("Kick error: %v\n", err)
			exitFunc(1)
			return
		}
		fmt.Println(`{"success": true}`)
	case "logs":
		logsCmd := flag.NewFlagSet("logs", flag.ExitOnError)
		path := logsCmd.String("path", "", "Path to core log file")
		linesCount := logsCmd.Int("lines", 100, "Number of tail lines to retrieve")
		_ = logsCmd.Parse(os.Args[3:])
		if *path == "" {
			fmt.Println("Error: --path is required")
			exitFunc(1)
			return
		}
		lines, err := supervisor.ReadCoreLogs(*path, *linesCount)
		if err != nil {
			fmt.Printf("Logs error: %v\n", err)
			exitFunc(1)
			return
		}
		data, _ := json.MarshalIndent(lines, "", "  ")
		fmt.Println(string(data))
	case "start":
		startCmd := flag.NewFlagSet("start", flag.ExitOnError)
		core := startCmd.String("core", "", "Core name (xray, sing-box, hysteria2)")
		bin := startCmd.String("bin", "", "Path to binary")
		config := startCmd.String("config", "", "Path to config file")
		_ = startCmd.Parse(os.Args[3:])
		if *core == "" || *bin == "" {
			fmt.Println("Error: --core and --bin are required")
			exitFunc(1)
			return
		}
		pm := supervisor.GetProcessManager()
		if err := pm.StartCore(*core, *bin, *config); err != nil {
			fmt.Printf("Start error: %v\n", err)
			exitFunc(1)
			return
		}
		fmt.Println(`{"success": true}`)
	case "stop":
		stopCmd := flag.NewFlagSet("stop", flag.ExitOnError)
		core := stopCmd.String("core", "", "Core name (xray, sing-box, hysteria2)")
		_ = stopCmd.Parse(os.Args[3:])
		if *core == "" {
			fmt.Println("Error: --core is required")
			exitFunc(1)
			return
		}
		pm := supervisor.GetProcessManager()
		if err := pm.StopCore(*core); err != nil {
			fmt.Printf("Stop error: %v\n", err)
			exitFunc(1)
			return
		}
		fmt.Println(`{"success": true}`)
	case "restart":
		restartCmd := flag.NewFlagSet("restart", flag.ExitOnError)
		core := restartCmd.String("core", "", "Core name (xray, sing-box, hysteria2)")
		bin := restartCmd.String("bin", "", "Path to binary")
		config := restartCmd.String("config", "", "Path to config file")
		_ = restartCmd.Parse(os.Args[3:])
		if *core == "" || *bin == "" {
			fmt.Println("Error: --core and --bin are required")
			exitFunc(1)
			return
		}
		pm := supervisor.GetProcessManager()
		if err := pm.RestartCore(*core, *bin, *config); err != nil {
			fmt.Printf("Restart error: %v\n", err)
			exitFunc(1)
			return
		}
		fmt.Println(`{"success": true}`)
	case "validate":
		valCmd := flag.NewFlagSet("validate", flag.ExitOnError)
		core := valCmd.String("core", "", "Core name (xray, sing-box, hysteria2)")
		bin := valCmd.String("bin", "", "Path to binary")
		config := valCmd.String("config", "", "Path to config file")
		_ = valCmd.Parse(os.Args[3:])
		if *core == "" || *bin == "" || *config == "" {
			fmt.Println("Error: --core, --bin and --config are required")
			exitFunc(1)
			return
		}
		pm := supervisor.GetProcessManager()
		valid, out, err := pm.ValidateCoreConfig(*core, *bin, *config)
		res := map[string]any{
			"valid":  valid,
			"output": out,
		}
		if err != nil {
			res["error"] = err.Error()
		}
		data, _ := json.MarshalIndent(res, "", "  ")
		fmt.Println(string(data))
	case "version":
		verCmd := flag.NewFlagSet("version", flag.ExitOnError)
		core := verCmd.String("core", "", "Core name (xray, sing-box, hysteria2)")
		bin := verCmd.String("bin", "", "Path to binary")
		_ = verCmd.Parse(os.Args[3:])
		if *core == "" || *bin == "" {
			fmt.Println("Error: --core and --bin are required")
			exitFunc(1)
			return
		}
		pm := supervisor.GetProcessManager()
		v := pm.DetectCoreVersion(*core, *bin)
		res := map[string]string{"version": v}
		data, _ := json.MarshalIndent(res, "", "  ")
		fmt.Println(string(data))
	default:
		fmt.Printf("Unknown supervisor action '%s'\n", action)
		exitFunc(1)
	}
}
