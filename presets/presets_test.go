package presets

import (
	"encoding/json"
	"testing"
)

func TestBuiltinPresets_ValidJSON(t *testing.T) {
	entries, err := BuiltinFS.ReadDir(".")
	if err != nil {
		t.Fatalf("failed to read embedded presets dir: %v", err)
	}

	if len(entries) == 0 {
		t.Fatalf("expected embedded JSON presets, got 0")
	}

	for _, entry := range entries {
		if entry.IsDir() || entry.Name() == "embed.go" || entry.Name() == "presets_test.go" {
			continue
		}
		data, err := BuiltinFS.ReadFile(entry.Name())
		if err != nil {
			t.Fatalf("failed to read embedded preset %s: %v", entry.Name(), err)
		}

		var obj map[string]interface{}
		if err := json.Unmarshal(data, &obj); err != nil {
			t.Fatalf("preset %s contains invalid JSON: %v", entry.Name(), err)
		}

		if obj["id"] == nil {
			t.Fatalf("preset %s missing required 'id' field", entry.Name())
		}
	}
}
