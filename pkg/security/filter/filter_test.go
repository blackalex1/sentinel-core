package filter

import (
	"testing"
)

func TestBloomFilter(t *testing.T) {
	bf := NewBloomFilter(1024, 4)

	bf.Add("malware-domain.xyz")
	bf.Add("phishing-portal.com")

	if !bf.MayContain("malware-domain.xyz") {
		t.Fatalf("expected Bloom filter to contain added item")
	}
	if !bf.MayContain("phishing-portal.com") {
		t.Fatalf("expected Bloom filter to contain added item")
	}
	if bf.MayContain("totally-safe-google.com") {
		// With 1024 bits and 2 items, false positive rate is negligible
		t.Logf("Note: false positive on un-added domain (statistically rare but valid)")
	}
}

func TestThreatEngineCategories(t *testing.T) {
	engine := NewThreatEngine(
		true,
		true, // Malware
		true, // Phishing
		true, // Miners
		false, // Ads
		[]string{"custom-danger.com"},
		[]string{"allowed-exception.com"},
		[]string{"198.51.100.0/24"},
	)

	// Malware test
	res := engine.CheckHost("c2-panel.su")
	if !res.Blocked || res.Category != CategoryMalware {
		t.Fatalf("expected c2-panel.su to be blocked as MALWARE, got: %+v", res)
	}

	// Subdomain of miner test
	res = engine.CheckHost("pool1.us.minexmr.com")
	if !res.Blocked || res.Category != CategoryMiner {
		t.Fatalf("expected subdomain of minexmr.com to be blocked as CRYPTO_MINER, got: %+v", res)
	}

	// Custom blocked domain
	res = engine.CheckHost("custom-danger.com")
	if !res.Blocked || res.Category != CategoryCustom {
		t.Fatalf("expected custom-danger.com to be blocked as CUSTOM_BLOCK")
	}

	// Whitelisted exception
	res = engine.CheckHost("allowed-exception.com")
	if res.Blocked {
		t.Fatalf("expected whitelisted domain to NOT be blocked")
	}

	// Benign domain
	res = engine.CheckHost("github.com")
	if res.Blocked {
		t.Fatalf("expected github.com to NOT be blocked")
	}

	// Blocked IP subnet
	res = engine.CheckHost("198.51.100.42")
	if !res.Blocked {
		t.Fatalf("expected IP 198.51.100.42 in subnet 198.51.100.0/24 to be blocked")
	}
}
