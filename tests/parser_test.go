package tests

import (
	"testing"
	"github.com/blackalex1/sentinel-core/pkg/ast"
	"github.com/blackalex1/sentinel-core/pkg/parser"
)

func TestParseURI_VLESSReality(t *testing.T) {
	raw := "vless://00000000-0000-0000-0000-000000000001@198.51.100.10:443?type=tcp&security=reality&pbk=xM8v9Uj77U7D32q_YtQ5vA3B7X2_Z1y8K9w0O3P4Q5R&fp=chrome&sni=gateway.example.com&sid=0123456789abcdef&spx=%2F&flow=xtls-rprx-vision#MyVLESS"

	p, err := parser.ParseURI(raw)
	if err != nil {
		t.Fatalf("failed to parse VLESS reality URI: %v", err)
	}

	if p.Protocol != ast.ProtoVLESS {
		t.Errorf("expected protocol vless, got %s", p.Protocol)
	}
	if p.Address != "198.51.100.10" {
		t.Errorf("expected address 198.51.100.10, got %s", p.Address)
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
	raw := "hy2://mypassword@198.51.100.11:8443?sni=cdn.example.com&insecure=1&obfs=salamander&obfs-password=obfspass&mport=20000-40000#MyHy2"

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
	raw := "ss://YWVzLTEyOC1nY206dGVzdHBhc3N3b3Jk@198.51.100.12:8388#MySSNode"

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
	if p.Address != "198.51.100.12" {
		t.Errorf("expected address 198.51.100.12, got %s", p.Address)
	}
}

func TestParseURI_UnicodeAndEmoji(t *testing.T) {
	raw := "vless://00000000-0000-0000-0000-000000000001@198.51.100.1:443?type=tcp&security=reality&pbk=xM8v9Uj77U7D32q_YtQ5vA3B7X2_Z1y8K9w0O3P4Q5R&fp=chrome&sni=gateway.example.com&sid=0123456789abcdef&spx=%2F&flow=xtls-rprx-vision#Mock Server | 🇩🇪 EU [⚡]"

	p, err := parser.ParseURI(raw)
	if err != nil {
		t.Fatalf("failed to parse VLESS with Unicode/emoji name: %v", err)
	}

	if p.Name != "Mock Server | 🇩🇪 EU [⚡]" {
		t.Errorf("expected name 'Mock Server | 🇩🇪 EU [⚡]', got '%s'", p.Name)
	}
	if p.Address != "198.51.100.1" {
		t.Errorf("expected address 198.51.100.1, got %s", p.Address)
	}
	if p.Port != 443 {
		t.Errorf("expected port 443, got %d", p.Port)
	}
}

func TestParseXrayConfigJSON(t *testing.T) {
	jsonConfig := `{"remarks":"Mock Server 1","outbounds":[{"tag":"proxy-1","protocol":"vless","settings":{"vnext":[{"address":"198.51.100.2","port":59985,"users":[{"id":"00000000-0000-0000-0000-000000000002","flow":"xtls-rprx-vision"}]}]},"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"serverName":"gateway.example.com","publicKey":"mock-public-key-abcdef","shortId":"4acb4c423d47ae19","fingerprint":"qq"}}},{"tag":"direct","protocol":"freedom"}]}`

	p, err := parser.ParseURI(jsonConfig)
	if err != nil {
		t.Fatalf("failed to parse Xray JSON config: %v", err)
	}

	if p.Name != "Mock Server 1" {
		t.Errorf("expected name 'Mock Server 1', got '%s'", p.Name)
	}
	if p.Address != "198.51.100.2" {
		t.Errorf("expected address '198.51.100.2', got '%s'", p.Address)
	}
	if p.Port != 59985 {
		t.Errorf("expected port 59985, got %d", p.Port)
	}
	if p.Security != "reality" {
		t.Errorf("expected security reality, got %s", p.Security)
	}
	if p.SNI != "gateway.example.com" {
		t.Errorf("expected SNI gateway.example.com, got %s", p.SNI)
	}
}

func TestParseXrayConfigJSON_GRPC(t *testing.T) {
	jsonConfig := `{"remarks":"Mock Server 2","outbounds":[{"tag":"proxy-5","protocol":"vless","settings":{"vnext":[{"address":"198.51.100.3","port":59522,"users":[{"id":"00000000-0000-0000-0000-000000000003","flow":""}]}]},"streamSettings":{"network":"grpc","grpcSettings":{"authority":"","mode":false,"serviceName":"mock.v1.Service"},"security":"tls","tlsSettings":{"fingerprint":"firefox","pinnedPeerCertSha256":"AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99","serverName":"grpc.example.com"}}}]}`

	p, err := parser.ParseURI(jsonConfig)
	if err != nil {
		t.Fatalf("failed to parse gRPC Xray JSON config: %v", err)
	}

	if p.Name != "Mock Server 2" {
		t.Errorf("expected name 'Mock Server 2', got '%s'", p.Name)
	}
	if p.Address != "198.51.100.3" {
		t.Errorf("expected address '198.51.100.3', got '%s'", p.Address)
	}
	if p.Port != 59522 {
		t.Errorf("expected port 59522, got %d", p.Port)
	}
	if p.Transport != "grpc" {
		t.Errorf("expected transport grpc, got %s", p.Transport)
	}
	if p.ServiceName != "mock.v1.Service" {
		t.Errorf("expected serviceName 'mock.v1.Service', got '%s'", p.ServiceName)
	}
	if p.PinnedPeerCertSha256 != "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99" {
		t.Errorf("expected pinned cert, got '%s'", p.PinnedPeerCertSha256)
	}
}





