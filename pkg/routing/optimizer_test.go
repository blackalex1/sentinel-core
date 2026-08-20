package routing

import (
	"reflect"
	"testing"
)

func TestOptimizeCIDRs(t *testing.T) {
	input := []string{
		"10.0.0.0/8",
		"10.1.2.0/24",
		"10.5.0.1/32",
		"192.168.1.1",
		"192.168.1.0/24",
		"geoip:ru",
		"geoip:ru",
	}

	result := OptimizeCIDRs(input)

	// Expected: geoip:ru (deduplicated), 10.0.0.0/8 (covers 10.1.2.0/24 and 10.5.0.1/32), 192.168.1.0/24 (covers 192.168.1.1/32)
	expected := []string{
		"geoip:ru",
		"10.0.0.0/8",
		"192.168.1.0/24",
	}

	if !reflect.DeepEqual(result, expected) {
		t.Errorf("OptimizeCIDRs mismatch.\nGot:      %v\nExpected: %v", result, expected)
	}
}

func TestOptimizeDomains(t *testing.T) {
	input := []string{
		"domain:google.com",
		"mail.google.com",
		"api.sub.google.com",
		"geosite:yandex",
		"geosite:yandex",
		"yandex.ru",
		"music.yandex.ru",
	}

	result := OptimizeDomains(input)

	// Expected: geosite:yandex (deduplicated), domain:google.com (covers subdomains), domain:yandex.ru (covers music.yandex.ru)
	expected := []string{
		"geosite:yandex",
		"domain:google.com",
		"yandex.ru",
	}

	if !reflect.DeepEqual(result, expected) {
		t.Errorf("OptimizeDomains mismatch.\nGot:      %v\nExpected: %v", result, expected)
	}
}

func TestOptimizeRules(t *testing.T) {
	rules := []RoutingRuleRow{
		{
			Name:    "Redundant Rule",
			Enabled: true,
			Target:  "direct",
			IPs:     []string{"10.0.0.0/8", "10.1.0.0/16"},
			Domains: []string{"example.com", "sub.example.com"},
		},
		{
			Name:    "Disabled Rule",
			Enabled: false,
			Target:  "block",
		},
	}

	optimized := OptimizeRules(rules)
	if len(optimized) != 1 {
		t.Fatalf("expected 1 enabled optimized rule, got %d", len(optimized))
	}

	if len(optimized[0].IPs) != 1 || optimized[0].IPs[0] != "10.0.0.0/8" {
		t.Errorf("expected merged IPs [10.0.0.0/8], got %v", optimized[0].IPs)
	}
	if len(optimized[0].Domains) != 1 || optimized[0].Domains[0] != "example.com" {
		t.Errorf("expected merged Domains [example.com], got %v", optimized[0].Domains)
	}
}
