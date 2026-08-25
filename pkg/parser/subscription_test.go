package parser

import (
	"encoding/base64"
	"testing"

	"github.com/blackalex1/sentinel-core/pkg/ast"
)

func TestParseSubscription(t *testing.T) {
	rawSubscription := `
# Russian Mobile White-List VLESS reality test
vless://11111111-2222-3333-4444-555555555555@198.51.100.1:443?security=reality&sni=google.com&pbk=abcd1234efgh5678abcd1234efgh5678abcd1234efg&sid=12345678&fp=chrome&type=tcp&flow=xtls-rprx-vision#Finland-Reality

// Another node
vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@198.51.100.2:8443?security=reality&sni=microsoft.com&pbk=1111222233334444555566667777888899990000aaa&sid=87654321&fp=safari&type=grpc&serviceName=vless-grpc#Germany-Reality

hy2://mysecretpassword@198.51.100.3:443?sni=apple.com&insecure=1#Hysteria2-Node
`

	profiles, err := ParseSubscription(rawSubscription)
	if err != nil {
		t.Fatalf("unexpected error parsing subscription: %v", err)
	}

	if len(profiles) != 3 {
		t.Fatalf("expected 3 profiles, got %d", len(profiles))
	}

	// 1. Verify VLESS Reality 1
	p1 := profiles[0]
	if p1.Protocol != ast.ProtoVLESS {
		t.Errorf("expected ProtoVLESS, got %v", p1.Protocol)
	}
	if p1.Address != "198.51.100.1" || p1.Port != 443 {
		t.Errorf("p1 address/port mismatch: %s:%d", p1.Address, p1.Port)
	}
	if p1.SNI != "google.com" || p1.Security != "reality" {
		t.Errorf("p1 reality mismatch: sni=%s, security=%s", p1.SNI, p1.Security)
	}
	if p1.Name != "Finland-Reality" {
		t.Errorf("p1 name mismatch: %s", p1.Name)
	}

	// 2. Verify VLESS Reality 2 (gRPC)
	p2 := profiles[1]
	if p2.Protocol != ast.ProtoVLESS || p2.Transport != "grpc" || p2.ServiceName != "vless-grpc" {
		t.Errorf("p2 grpc mismatch: proto=%v, transport=%s, service=%s", p2.Protocol, p2.Transport, p2.ServiceName)
	}

	// 3. Verify Base64 encoded subscription
	b64Sub := base64.StdEncoding.EncodeToString([]byte(rawSubscription))
	b64Profiles, err := ParseSubscription(b64Sub)
	if err != nil {
		t.Fatalf("error parsing base64 subscription: %v", err)
	}
	if len(b64Profiles) != 3 {
		t.Fatalf("expected 3 profiles from base64, got %d", len(b64Profiles))
	}
}
