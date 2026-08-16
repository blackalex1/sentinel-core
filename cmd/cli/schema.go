package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/blackalex1/sentinel-core/pkg/matrix"
)

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
		exitFunc(1)
		return
	}
	fmt.Println(string(bytes))
}
