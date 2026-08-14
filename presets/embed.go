package presets

import "embed"

// BuiltinFS embeds all official routing preset JSON files (Single Source of Truth)
//
//go:embed *.json
var BuiltinFS embed.FS
