package wireguard

import (
	"strings"
	"testing"

	"github.com/blackalex1/sentinel-core/pkg/ast"
)

func TestBuildWireGuardConf_NilNode(t *testing.T) {
	_, err := BuildWireGuardConf(nil)
	if err == nil {
		t.Fatal("expected error for nil node, got nil")
	}
}

func TestBuildWireGuardConf_FullProfile(t *testing.T) {
	node := &ast.ServerProfile{
		Protocol:      "wireguard",
		Address:       "198.51.100.1",
		Port:          51820,
		PrivateKey:    "aGVsbG93b3JsZDExMTExMTExMTExMTExMTExMTExMTExMQ==",
		PeerPublicKey: "YnllaGVsbG93b3JsZDExMTExMTExMTExMTExMTExMTExMQ==",
		PreSharedKey:  "cHJlc2hhcmVka2V5MTExMTExMTExMTExMTExMTExMTExMQ==",
		LocalAddress:  []string{"10.0.0.2/32", "fd00::2/128"},
		MTU:           1420,
	}

	conf, err := BuildWireGuardConf(node)
	if err != nil {
		t.Fatalf("failed to build WireGuard config: %v", err)
	}

	expectedSnippets := []string{
		"[Interface]",
		"PrivateKey = aGVsbG93b3JsZDExMTExMTExMTExMTExMTExMTExMTExMQ==",
		"Address = 10.0.0.2/32, fd00::2/128",
		"MTU = 1420",
		"[Peer]",
		"PublicKey = YnllaGVsbG93b3JsZDExMTExMTExMTExMTExMTExMTExMQ==",
		"PresharedKey = cHJlc2hhcmVka2V5MTExMTExMTExMTExMTExMTExMTExMQ==",
		"Endpoint = 198.51.100.1:51820",
		"AllowedIPs = 0.0.0.0/0, ::/0",
		"PersistentKeepalive = 25",
	}

	for _, snippet := range expectedSnippets {
		if !strings.Contains(conf, snippet) {
			t.Errorf("expected snippet %q in config, got:\n%s", snippet, conf)
		}
	}
}

func TestBuildWireGuardConf_MinimalProfile(t *testing.T) {
	node := &ast.ServerProfile{
		Protocol: "wireguard",
		Address:  "192.0.2.1",
		Port:     51820,
	}

	conf, err := BuildWireGuardConf(node)
	if err != nil {
		t.Fatalf("failed to build minimal WireGuard config: %v", err)
	}

	if !strings.Contains(conf, "[Interface]") || !strings.Contains(conf, "[Peer]") {
		t.Errorf("missing section headers in config: %s", conf)
	}
	if !strings.Contains(conf, "Endpoint = 192.0.2.1:51820") {
		t.Errorf("expected Endpoint in config: %s", conf)
	}
	if strings.Contains(conf, "PrivateKey =") {
		t.Errorf("unexpected PrivateKey in minimal config: %s", conf)
	}
	if strings.Contains(conf, "Address =") {
		t.Errorf("unexpected Address in minimal config: %s", conf)
	}
	if strings.Contains(conf, "MTU =") {
		t.Errorf("unexpected MTU in minimal config: %s", conf)
	}
	if strings.Contains(conf, "PublicKey =") {
		t.Errorf("unexpected PublicKey in minimal config: %s", conf)
	}
	if strings.Contains(conf, "PresharedKey =") {
		t.Errorf("unexpected PresharedKey in minimal config: %s", conf)
	}
}
