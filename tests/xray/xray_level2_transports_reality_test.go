package xray_test

import (
	"testing"

	"github.com/blackalex1/sentinel-core/pkg/ast"
	"github.com/blackalex1/sentinel-core/pkg/builder"
	"github.com/blackalex1/sentinel-core/pkg/parser"
)

// Level 2: Modern XHTTP / SplitHTTP Multiplexed Transport
func TestXray_Level2_XHTTP_SplitHTTP_Transport(t *testing.T) {
	node := &ast.ServerProfile{
		Protocol:  ast.ProtoVLESS,
		Address:   "198.51.100.20",
		Port:      443,
		UUID:      "b9f3857a-ce20-4e1e-b5e0-6f3d141fa2b2",
		Transport: "xhttp",
		Path:      "/splithttp-stream",
		Host:      "xhttp.example.com",
		Security:  "reality",
		PublicKey: "1pxvjj6jjhkkN40PM83ViQTJeC9VMDVe7oceMZuWNQY",
		SNI:       "www.google.com",
		Name:      "VLESS-XHTTP-Reality",
	}

	spec := buildClientTestSpec(node)
	res, err := builder.BuildClientConfig(spec)
	if err != nil {
		t.Fatalf("BuildClientConfig failed: %v", err)
	}

	runXraySyntaxCheck(t, "Level 2 XHTTP / SplitHTTP Transport", res.ConfigJSON)
	t.Logf("✅ Level 2: Modern XHTTP / SplitHTTP transport verified")
}

// Level 2: WebSocket with Early Data & Custom Headers for CDN
func TestXray_Level2_WebSocket_EarlyData(t *testing.T) {
	node := &ast.ServerProfile{
		Protocol:  ast.ProtoVLESS,
		Address:   "cdn.cloudflare.com",
		Port:      443,
		UUID:      "b9f3857a-ce20-4e1e-b5e0-6f3d141fa2b2",
		Transport: "ws",
		Path:      "/vless-early-data-path?ed=2048",
		Host:      "my-worker.workers.dev",
		Security:  "tls",
		SNI:       "my-worker.workers.dev",
		Name:      "VLESS-WS-EarlyData",
	}

	spec := buildClientTestSpec(node)
	res, err := builder.BuildClientConfig(spec)
	if err != nil {
		t.Fatalf("BuildClientConfig failed: %v", err)
	}

	runXraySyntaxCheck(t, "Level 2 WebSocket Early Data", res.ConfigJSON)
	t.Logf("✅ Level 2: WebSocket Early Data for CDN verified")
}

// Level 2: uTLS Fingerprint Matrix (Chrome, Firefox, Safari, iOS, Android, Edge, Randomized)
func TestXray_Level2_uTLS_Fingerprints(t *testing.T) {
	fps := []string{"chrome", "firefox", "safari", "ios", "android", "edge", "randomized"}

	for _, fp := range fps {
		t.Run("uTLS_"+fp, func(t *testing.T) {
			raw := "vless://b9f3857a-ce20-4e1e-b5e0-6f3d141fa2b2@198.51.100.50:443?type=tcp&security=reality&pbk=1pxvjj6jjhkkN40PM83ViQTJeC9VMDVe7oceMZuWNQY&sni=www.apple.com&sid=0123456789abcdef&flow=xtls-rprx-vision&fp=" + fp + "#Node-" + fp
			profile, err := parser.ParseURI(raw)
			if err != nil {
				t.Fatalf("ParseURI failed for fp %s: %v", fp, err)
			}

			spec := buildClientTestSpec(profile)
			res, err := builder.BuildClientConfig(spec)
			if err != nil {
				t.Fatalf("BuildClientConfig failed: %v", err)
			}

			runXraySyntaxCheck(t, "Level 2 uTLS "+fp, res.ConfigJSON)
		})
	}
}
