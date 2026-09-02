package adapter

import (
	"testing"
	"github.com/blackalex1/sentinel-core/pkg/crypto"
)

func TestIngestDBNode_Plain(t *testing.T) {
	raw := &RawDBNode{
		ID:        "node-1",
		Name:      "Test VLESS Node",
		Protocol:  "vless",
		Address:   "198.51.100.1",
		Port:      443,
		Transport: "tcp",
		Security:  "reality",
		Parameters: map[string]interface{}{
			"uuid":         "a6c8e874-a4ee-4c38-89c0-6d427d1421bf",
			"public_key":   "myPublicKey123",
			"sni":          "example.com",
			"flow":         "xtls-rprx-vision",
			"fingerprint":  "chrome",
			"short_id":     "abcd1234",
			"spider_x":     "/auth",
			"alpn":         []string{"h2", "http/1.1"},
			"insecure":     "1",
			"post_quantum": true,
			"mux":          true,
		},
	}

	profile, err := IngestDBNode(raw, nil)
	if err != nil {
		t.Fatalf("failed to ingest DB node: %v", err)
	}

	if profile.Protocol != "vless" || profile.Address != "198.51.100.1" || profile.Port != 443 {
		t.Fatalf("unexpected profile values: %+v", profile)
	}
	if profile.UUID != "a6c8e874-a4ee-4c38-89c0-6d427d1421bf" || profile.PublicKey != "myPublicKey123" {
		t.Fatalf("unexpected credentials: %+v", profile)
	}
	if profile.ShortID != "abcd1234" || profile.SpiderX != "/auth" || profile.Fingerprint != "chrome" {
		t.Fatalf("unexpected reality fields: %+v", profile)
	}
	if !profile.Insecure || !profile.PostQuantum || !profile.Mux || len(profile.ALPN) != 2 {
		t.Fatalf("unexpected flags or alpn: %+v", profile)
	}
}

func TestIngestDBNode_Encrypted(t *testing.T) {
	vault, err := crypto.NewVault("MyMasterSecret12345678901234567")
	if err != nil {
		t.Fatalf("failed to create vault: %v", err)
	}

	encParams, err := vault.EncryptMap(map[string]interface{}{
		"uuid":       "enc-uuid-1234",
		"public_key": "enc-pubkey-5678",
	})
	if err != nil {
		t.Fatalf("failed to encrypt map: %v", err)
	}

	raw := &RawDBNode{
		ID:         "node-enc-1",
		Name:       "Encrypted Node",
		Protocol:   "vless",
		Address:    "198.51.100.2",
		Port:       443,
		Parameters: encParams,
	}

	// Ingest without vault -> error
	_, err = IngestDBNode(raw, nil)
	if err == nil {
		t.Fatalf("expected error when vault is missing for encrypted node")
	}

	// Ingest with wrong vault -> error
	wrongVault, _ := crypto.NewVault("WrongSecret12345678901234567")
	_, err = IngestDBNode(raw, wrongVault)
	if err == nil {
		t.Fatalf("expected error decrypting with wrong vault")
	}

	// Ingest with correct vault -> success
	profile, err := IngestDBNode(raw, vault)
	if err != nil {
		t.Fatalf("failed to ingest encrypted DB node: %v", err)
	}

	if profile.UUID != "enc-uuid-1234" || profile.PublicKey != "enc-pubkey-5678" {
		t.Fatalf("unexpected decrypted parameters: %+v", profile)
	}
}

func TestIngestDBNode_RawJSONStringParams(t *testing.T) {
	raw := &RawDBNode{
		ID:         "node-json-str",
		Name:       "JSON String Params",
		Protocol:   "trojan",
		Address:    "198.51.100.3",
		Port:       443,
		Parameters: `{"password": "trojan-pass-123", "service_name": "grpc-svc", "alpn": "h2,http/1.1"}`,
	}

	profile, err := IngestDBNode(raw, nil)
	if err != nil {
		t.Fatalf("failed to ingest JSON string params: %v", err)
	}

	if profile.Password != "trojan-pass-123" || profile.ServiceName != "grpc-svc" || len(profile.ALPN) != 2 {
		t.Fatalf("unexpected parsed parameters: %+v", profile)
	}

	// Invalid JSON string
	rawInvalid := &RawDBNode{
		ID:         "node-invalid-json",
		Protocol:   "trojan",
		Address:    "198.51.100.3",
		Port:       443,
		Parameters: `{invalid-json-string`,
	}
	_, err = IngestDBNode(rawInvalid, nil)
	if err == nil {
		t.Fatalf("expected error on invalid JSON string parameters")
	}
}

func TestIngestDBNode_PortParsing(t *testing.T) {
	// Float64 port
	rawFloat := &RawDBNode{
		Protocol: "vless",
		Address:  "1.1.1.1",
		Port:     float64(8443),
		Parameters: map[string]interface{}{
			"uuid":       "uuid-123",
			"public_key": "pub-123",
		},
	}
	pFloat, err := IngestDBNode(rawFloat, nil)
	if err != nil || pFloat.Port != 8443 {
		t.Fatalf("float64 port parsing failed: %v, profile: %+v", err, pFloat)
	}

	// String port
	rawStr := &RawDBNode{
		Protocol: "vless",
		Address:  "1.1.1.1",
		Port:     "2087",
		Parameters: map[string]interface{}{
			"uuid":       "uuid-123",
			"public_key": "pub-123",
		},
	}
	pStr, err := IngestDBNode(rawStr, nil)
	if err != nil || pStr.Port != 2087 {
		t.Fatalf("string port parsing failed: %v, profile: %+v", err, pStr)
	}

	// Invalid string port
	rawBadStr := &RawDBNode{
		Protocol: "vless",
		Address:  "1.1.1.1",
		Port:     "not_a_port",
	}
	_, err = IngestDBNode(rawBadStr, nil)
	if err == nil {
		t.Fatalf("expected error on invalid string port")
	}

	// Unsupported port type
	rawNilPort := &RawDBNode{
		Protocol: "vless",
		Address:  "1.1.1.1",
		Port:     nil,
	}
	_, err = IngestDBNode(rawNilPort, nil)
	if err == nil {
		t.Fatalf("expected error on nil port")
	}
}

func TestIngestDBNode_AllProtocolsAndFields(t *testing.T) {
	// 1. Shadowsocks & ShadowTLS
	ssNode := &RawDBNode{
		Protocol: "shadowsocks",
		Address:  "198.51.100.1",
		Port:     8388,
		Parameters: map[string]interface{}{
			"password":            "ss-secret",
			"cipher":              "2022-blake3-aes-128-gcm",
			"shadow_tls_version":  "3",
			"shadow_tls_password": "stls-password",
			"shadow_tls_sni":      "gateway.icloud.com",
		},
	}
	pSS, err := IngestDBNode(ssNode, nil)
	if err != nil {
		t.Fatalf("failed shadowsocks ingestion: %v", err)
	}
	if pSS.ShadowTLSVersion != 3 || pSS.ShadowTLSPassword != "stls-password" || pSS.ShadowTLSSNI != "gateway.icloud.com" {
		t.Errorf("unexpected shadowtls fields: %+v", pSS)
	}

	// 2. Hysteria 2
	hyNode := &RawDBNode{
		Protocol: "hysteria2",
		Address:  "198.51.100.1",
		Port:     443,
		Parameters: map[string]interface{}{
			"password":       "hy2-secret",
			"bandwidth_up":   "50mbps",
			"bandwidth_down": "200mbps",
			"obfs_type":      "salamander",
			"obfs_password":  "obfs-pass",
			"port_hopping":   "20000-30000",
		},
	}
	pHY, err := IngestDBNode(hyNode, nil)
	if err != nil {
		t.Fatalf("failed hysteria2 ingestion: %v", err)
	}
	if pHY.BandwidthUp != "50mbps" || pHY.ObfsType != "salamander" || pHY.PortHopping != "20000-30000" {
		t.Errorf("unexpected hy2 fields: %+v", pHY)
	}

	// 3. TUIC
	tuicNode := &RawDBNode{
		Protocol: "tuic",
		Address:  "198.51.100.1",
		Port:     443,
		Parameters: map[string]interface{}{
			"uuid":                "tuic-uuid-1234",
			"password":            "tuic-pass",
			"congestion_control":  "bbr",
			"udp_relay_mode":      "native",
			"zero_rtt_handshake": "true",
		},
	}
	pTUIC, err := IngestDBNode(tuicNode, nil)
	if err != nil {
		t.Fatalf("failed tuic ingestion: %v", err)
	}
	if pTUIC.CongestionControl != "bbr" || pTUIC.UDPRelayMode != "native" || !pTUIC.ZeroRTTHandshake {
		t.Errorf("unexpected tuic fields: %+v", pTUIC)
	}

	// 4. WireGuard
	wgNode := &RawDBNode{
		Protocol: "wireguard",
		Address:  "198.51.100.1",
		Port:     51820,
		Parameters: map[string]interface{}{
			"private_key":     "priv-wg-key",
			"peer_public_key": "peer-wg-key",
			"preshared_key":   "psk-wg-key",
			"mtu":             1420,
			"local_address":   []interface{}{"10.0.0.2/32", "fd00::2/128"},
		},
	}
	pWG, err := IngestDBNode(wgNode, nil)
	if err != nil {
		t.Fatalf("failed wireguard ingestion: %v", err)
	}
	if pWG.PrivateKey != "priv-wg-key" || pWG.MTU != 1420 || len(pWG.LocalAddress) != 2 {
		t.Errorf("unexpected wireguard fields: %+v", pWG)
	}

	// 5. VMess with Path & Username
	vmessNode := &RawDBNode{
		Protocol: "vmess",
		Address:  "198.51.100.1",
		Port:     443,
		Parameters: map[string]interface{}{
			"uuid":     "vmess-uuid-1234",
			"username": "user1",
			"path":     "/websocket",
		},
	}
	pVMess, err := IngestDBNode(vmessNode, nil)
	if err != nil {
		t.Fatalf("failed vmess ingestion: %v", err)
	}
	if pVMess.Username != "user1" || pVMess.Path != "/websocket" {
		t.Errorf("unexpected vmess fields: %+v", pVMess)
	}
}

func TestIngestDBNode_ValidationErrors(t *testing.T) {
	// Nil node
	_, err := IngestDBNode(nil, nil)
	if err == nil {
		t.Fatalf("expected error for nil raw node")
	}

	// Missing address / validation failure
	invalidNode := &RawDBNode{
		Protocol: "vless",
		Address:  "", // invalid
		Port:     443,
		Parameters: map[string]interface{}{
			"uuid": "uuid-123",
		},
	}
	_, err = IngestDBNode(invalidNode, nil)
	if err == nil {
		t.Fatalf("expected validation error on empty address")
	}
}

func TestIngestFromJSON(t *testing.T) {
	jsonValid := `{
		"id": "json-node-1",
		"name": "JSON VLESS",
		"protocol": "vless",
		"address": "198.51.100.1",
		"port": 443,
		"parameters": {
			"uuid": "a6c8e874-a4ee-4c38-89c0-6d427d1421bf",
			"public_key": "pubkey123"
		}
	}`

	profile, err := IngestFromJSON(jsonValid, nil)
	if err != nil {
		t.Fatalf("failed to ingest from valid JSON: %v", err)
	}
	if profile.ID != "json-node-1" || profile.Protocol != "vless" {
		t.Fatalf("unexpected profile values: %+v", profile)
	}

	// Invalid JSON
	_, err = IngestFromJSON(`{invalid-json`, nil)
	if err == nil {
		t.Fatalf("expected error on invalid JSON")
	}
}
