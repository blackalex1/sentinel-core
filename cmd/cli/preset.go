package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/blackalex1/sentinel-core/pkg/routing"
)

func handlePreset() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: sentinel-core preset <list|show|import> [args...]")
		exitFunc(1)
		return
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
			exitFunc(1)
			return
		}
		id := os.Args[3]
		jsonStr, err := pm.ExportPresetJSON(id)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			exitFunc(1)
			return
		}
		fmt.Println(jsonStr)

	case "import":
		if len(os.Args) < 4 {
			fmt.Println("Usage: sentinel-core preset import <preset_file.json>")
			exitFunc(1)
			return
		}
		filePath := os.Args[3]
		p, err := pm.LoadPresetFile(filePath)
		if err != nil {
			fmt.Printf("Import failed: %v\n", err)
			exitFunc(1)
			return
		}
		rules := p.GetRules("")
		fmt.Printf("Successfully imported preset '%s' (%s) with %d rules\n", p.ID, p.Name, len(rules))

	default:
		fmt.Printf("Unknown preset command '%s'\n", subCmd)
		exitFunc(1)
	}
}
