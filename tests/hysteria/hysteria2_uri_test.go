package hysteria_test

import (
	"strings"
	"testing"

	"github.com/blackalex1/sentinel-core/pkg/ast"
	"github.com/blackalex1/sentinel-core/pkg/parser"
)

// 1. Parse all variations of hy2:// and hysteria2:// URIs
func TestHysteria2_URI_ParsingAllParameters(t *testing.T) {
	testCases := []struct {
		name          string
		rawURI        string
		expectedProto string
		expectedHost  string
		expectedPort  int
		expectedPass  string
		expectedObfs  string
		expectedHop   string
		expectedInsec bool
	}{
		{
			name:          "Standard hy2:// scheme",
			rawURI:        "hy2://myPass123@node1.hy2.net:8443?sni=node1.hy2.net&insecure=1&obfs=salamander&obfs-password=obfspass&mport=20000-40000#Node1",
			expectedProto: ast.ProtoHysteria2,
			expectedHost:  "node1.hy2.net",
			expectedPort:  8443,
			expectedPass:  "myPass123",
			expectedObfs:  "obfspass",
			expectedHop:   "20000-40000",
			expectedInsec: true,
		},
		{
			name:          "Full hysteria2:// scheme with user:pass",
			rawURI:        "hysteria2://alice:SecretToken77@198.51.100.10:443?ports=30000-50000&obfs=salamander&obfs-password=salPass#Node2",
			expectedProto: ast.ProtoHysteria2,
			expectedHost:  "198.51.100.10",
			expectedPort:  443,
			expectedPass:  "SecretToken77",
			expectedObfs:  "salPass",
			expectedHop:   "30000-50000",
			expectedInsec: false,
		},
		{
			name:          "Minimal hy2:// without query parameters",
			rawURI:        "hy2://basicPassword@simple.vpn:8443#SimpleNode",
			expectedProto: ast.ProtoHysteria2,
			expectedHost:  "simple.vpn",
			expectedPort:  8443,
			expectedPass:  "basicPassword",
			expectedObfs:  "",
			expectedHop:   "",
			expectedInsec: false,
		},
		{
			name:          "Hysteria 2 with bandwidth limits & pinSHA256",
			rawURI:        "hy2://pass@node.net:443?up=100mbps&down=1000mbps&pinSHA256=abcdef1234567890#FastNode",
			expectedProto: ast.ProtoHysteria2,
			expectedHost:  "node.net",
			expectedPort:  443,
			expectedPass:  "pass",
			expectedInsec: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			profile, err := parser.ParseURI(tc.rawURI)
			if err != nil {
				t.Fatalf("failed to parse URI: %v", err)
			}

			if profile.Protocol != tc.expectedProto {
				t.Errorf("expected protocol %s, got %s", tc.expectedProto, profile.Protocol)
			}
			if profile.Address != tc.expectedHost {
				t.Errorf("expected host %s, got %s", tc.expectedHost, profile.Address)
			}
			if profile.Port != tc.expectedPort {
				t.Errorf("expected port %d, got %d", tc.expectedPort, profile.Port)
			}
			if profile.Password != tc.expectedPass {
				t.Errorf("expected password %s, got %s", tc.expectedPass, profile.Password)
			}
			if tc.expectedObfs != "" && profile.ObfsPassword != tc.expectedObfs {
				t.Errorf("expected obfs %s, got %s", tc.expectedObfs, profile.ObfsPassword)
			}
			if tc.expectedHop != "" && profile.PortHopping != tc.expectedHop {
				t.Errorf("expected port hopping %s, got %s", tc.expectedHop, profile.PortHopping)
			}
			if profile.Insecure != tc.expectedInsec {
				t.Errorf("expected insecure %v, got %v", tc.expectedInsec, profile.Insecure)
			}
		})
	}
}

// 2. Generator and Roundtrip Test for Hysteria 2
func TestHysteria2_URI_GenerationAndRoundtrip(t *testing.T) {
	orig := &ast.ServerProfile{
		Protocol:      ast.ProtoHysteria2,
		Address:       "hy2.sentinel.internal",
		Port:          8443,
		Password:      "MyGeneratedPass123",
		SNI:           "hy2.sentinel.internal",
		Insecure:      true,
		ObfsType:      "salamander",
		ObfsPassword:  "SalamanderKey456",
		PortHopping:   "25000-35000",
		BandwidthUp:   "50 mbps",
		BandwidthDown: "250 mbps",
		Name:          "Generated-Hy2-Node",
	}

	generatedURI, err := parser.GenerateURI(orig)
	if err != nil {
		t.Fatalf("failed to generate URI: %v", err)
	}

	if !strings.HasPrefix(generatedURI, "hy2://") && !strings.HasPrefix(generatedURI, "hysteria2://") {
		t.Fatalf("expected hy2:// or hysteria2:// prefix, got: %s", generatedURI)
	}

	// Parse it back and compare fields
	parsed, err := parser.ParseURI(generatedURI)
	if err != nil {
		t.Fatalf("failed to parse generated URI: %v", err)
	}

	if parsed.Address != orig.Address || parsed.Port != orig.Port {
		t.Errorf("endpoint mismatch: %s:%d vs %s:%d", parsed.Address, parsed.Port, orig.Address, orig.Port)
	}
	if parsed.Password != orig.Password {
		t.Errorf("password mismatch: %s vs %s", parsed.Password, orig.Password)
	}
	if parsed.ObfsPassword != orig.ObfsPassword {
		t.Errorf("obfs password mismatch: %s vs %s", parsed.ObfsPassword, orig.ObfsPassword)
	}
	if parsed.PortHopping != orig.PortHopping {
		t.Errorf("port hopping mismatch: %s vs %s", parsed.PortHopping, orig.PortHopping)
	}
	if parsed.Insecure != orig.Insecure {
		t.Errorf("insecure mismatch: %v vs %v", parsed.Insecure, orig.Insecure)
	}
	if parsed.Name != orig.Name {
		t.Errorf("name mismatch: %s vs %s", parsed.Name, orig.Name)
	}

	t.Logf("✅ Hysteria 2 URI generation & roundtrip verified: %s", generatedURI)
}

// 3. Error cases for invalid Hysteria 2 URIs
func TestHysteria2_URI_InvalidInputs(t *testing.T) {
	invalidURIs := []string{
		"hy2://:invalidport@host:99999",
		"hy2://user@:443",
		"hy2://",
	}

	for _, inv := range invalidURIs {
		_, err := parser.ParseURI(inv)
		if err == nil {
			t.Errorf("expected error for invalid URI '%s', got nil", inv)
		}
	}
}
