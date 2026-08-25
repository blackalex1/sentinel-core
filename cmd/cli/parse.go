package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/blackalex1/sentinel-core/pkg/ast"
	"github.com/blackalex1/sentinel-core/pkg/parser"
)

func handleParse() {
	fs := flag.NewFlagSet("parse", flag.ExitOnError)
	uri := fs.String("uri", "", "Proxy URI (vless://, hy2://, trojan://, ss://, etc.)")
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

	jsonStr, _ := profile.ToJSON()
	fmt.Println(jsonStr)
}

func handleGenerate() {
	fs := flag.NewFlagSet("generate", flag.ExitOnError)
	profileStr := fs.String("profile", "", "ServerProfile JSON string")
	if len(os.Args) > 2 {
		_ = fs.Parse(os.Args[2:])
	}

	var rawJSON []byte
	var err error

	if *profileStr != "" {
		rawJSON = []byte(*profileStr)
	} else {
		rawJSON, err = io.ReadAll(os.Stdin)
		if err != nil {
			fmt.Printf("Stdin error: %v\n", err)
			exitFunc(1)
			return
		}
	}

	var p ast.ServerProfile
	if err := json.Unmarshal(rawJSON, &p); err != nil {
		fmt.Printf("JSON error: %v\n", err)
		exitFunc(1)
		return
	}

	uri, err := parser.GenerateURI(&p)
	if err != nil {
		fmt.Printf("Generate error: %v\n", err)
		exitFunc(1)
		return
	}

	fmt.Println(uri)
}

func handleParseSubscription() {
	fs := flag.NewFlagSet("parse-subscription", flag.ExitOnError)
	file := fs.String("file", "", "Path to file containing subscription (or leave empty for stdin)")
	raw := fs.String("content", "", "Raw or base64 subscription string")
	_ = fs.Parse(os.Args[2:])

	var content string
	if *raw != "" {
		content = *raw
	} else if *file != "" {
		bytes, err := os.ReadFile(*file)
		if err != nil {
			fmt.Printf("Error reading file: %v\n", err)
			exitFunc(1)
			return
		}
		content = string(bytes)
	} else {
		bytes, err := io.ReadAll(os.Stdin)
		if err != nil {
			fmt.Printf("Stdin error: %v\n", err)
			exitFunc(1)
			return
		}
		content = string(bytes)
	}

	profiles, err := parser.ParseSubscription(content)
	if err != nil {
		fmt.Printf("Subscription parse error: %v\n", err)
		exitFunc(1)
		return
	}

	jsonBytes, _ := json.MarshalIndent(profiles, "", "  ")
	fmt.Println(string(jsonBytes))
}

