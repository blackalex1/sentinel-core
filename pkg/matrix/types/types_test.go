package types

import (
	"encoding/json"
	"testing"
)

func TestTypes_JSONMarshaling(t *testing.T) {
	schema := ConfigurationSchema{
		Language: "en",
		Engines: []EngineOption{
			{ID: "test-engine", Name: "Test Engine", Description: "Engine description", Protocols: []string{"vless"}},
		},
		Protocols: map[string]ProtocolCapability{
			"vless": {
				Protocol:            "vless",
				DisplayName:         "VLESS",
				DefaultPort:         443,
				SupportedEngines:    []string{"test-engine"},
				SupportedTransports: []string{"tcp"},
				SupportedSecurity:   []string{"reality"},
			},
		},
		SniffingOptions: []SniffingOption{
			{ID: "tls", DisplayName: "TLS", Description: "TLS Sniffing", Default: true},
		},
	}

	data, err := json.Marshal(schema)
	if err != nil {
		t.Fatalf("failed to marshal ConfigurationSchema: %v", err)
	}

	var decoded ConfigurationSchema
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal ConfigurationSchema: %v", err)
	}

	if decoded.Language != "en" {
		t.Errorf("expected language 'en', got '%s'", decoded.Language)
	}
	if len(decoded.Engines) != 1 || decoded.Engines[0].ID != "test-engine" {
		t.Errorf("unexpected engines in decoded schema: %+v", decoded.Engines)
	}
	if vless, exists := decoded.Protocols["vless"]; !exists || vless.DefaultPort != 443 {
		t.Errorf("unexpected protocols in decoded schema: %+v", decoded.Protocols)
	}
	if len(decoded.SniffingOptions) != 1 || decoded.SniffingOptions[0].ID != "tls" {
		t.Errorf("unexpected sniffing options in decoded schema: %+v", decoded.SniffingOptions)
	}
}
