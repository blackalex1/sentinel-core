package tests

import (
	"testing"
	"github.com/blackalex1/sentinel-core/pkg/ast"
	"github.com/blackalex1/sentinel-core/pkg/parser"
)

func TestParseURI_VLESSReality(t *testing.T) {
	raw := "vless://a6c8e874-5182-4916-9ea6-f7723933c091@95.163.241.10:443?type=tcp&security=reality&pbk=xM8v9Uj77U7D32q_YtQ5vA3B7X2_Z1y8K9w0O3P4Q5R&fp=chrome&sni=gateway.icloud.com&sid=0123456789abcdef&spx=%2F&flow=xtls-rprx-vision#MyVLESS"

	p, err := parser.ParseURI(raw)
	if err != nil {
		t.Fatalf("failed to parse VLESS reality URI: %v", err)
	}

	if p.Protocol != ast.ProtoVLESS {
		t.Errorf("expected protocol vless, got %s", p.Protocol)
	}
	if p.Address != "95.163.241.10" {
		t.Errorf("expected address 95.163.241.10, got %s", p.Address)
	}
	if p.Port != 443 {
		t.Errorf("expected port 443, got %d", p.Port)
	}
	if p.PublicKey != "xM8v9Uj77U7D32q_YtQ5vA3B7X2_Z1y8K9w0O3P4Q5R" {
		t.Errorf("expected public key, got %s", p.PublicKey)
	}
	if p.ShortID != "0123456789abcdef" {
		t.Errorf("expected short id, got %s", p.ShortID)
	}
	if p.Flow != "xtls-rprx-vision" {
		t.Errorf("expected flow xtls-rprx-vision, got %s", p.Flow)
	}
	if p.Name != "MyVLESS" {
		t.Errorf("expected name MyVLESS, got %s", p.Name)
	}
}

func TestParseURI_Hysteria2(t *testing.T) {
	raw := "hy2://mypassword@45.67.89.10:8443?sni=fast.cdn.com&insecure=1&obfs=salamander&obfs-password=obfspass&mport=20000-40000#MyHy2"

	p, err := parser.ParseURI(raw)
	if err != nil {
		t.Fatalf("failed to parse Hysteria2 URI: %v", err)
	}

	if p.Protocol != ast.ProtoHysteria2 {
		t.Errorf("expected protocol hysteria2, got %s", p.Protocol)
	}
	if p.Password != "mypassword" {
		t.Errorf("expected password mypassword, got %s", p.Password)
	}
	if p.PortHopping != "20000-40000" {
		t.Errorf("expected port hopping 20000-40000, got %s", p.PortHopping)
	}
	if p.ObfsPassword != "obfspass" {
		t.Errorf("expected obfs password obfspass, got %s", p.ObfsPassword)
	}
}

func TestParseURI_Shadowsocks(t *testing.T) {
	raw := "ss://YWVzLTEyOC1nY206dGVzdHBhc3N3b3Jk@123.45.67.89:8388#MySSNode"

	p, err := parser.ParseURI(raw)
	if err != nil {
		t.Fatalf("failed to parse Shadowsocks URI: %v", err)
	}

	if p.Protocol != ast.ProtoShadowsocks {
		t.Errorf("expected protocol shadowsocks, got %s", p.Protocol)
	}
	if p.Cipher != "aes-128-gcm" {
		t.Errorf("expected cipher aes-128-gcm, got %s", p.Cipher)
	}
	if p.Password != "testpassword" {
		t.Errorf("expected password testpassword, got %s", p.Password)
	}
	if p.Address != "123.45.67.89" {
		t.Errorf("expected address 123.45.67.89, got %s", p.Address)
	}
}
