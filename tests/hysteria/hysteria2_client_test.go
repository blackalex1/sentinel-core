package hysteria_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"testing"

	"github.com/blackalex1/sentinel-core/pkg/ast"
	"github.com/blackalex1/sentinel-core/pkg/builder"
	"github.com/blackalex1/sentinel-core/pkg/compiler/hysteria"
	"github.com/blackalex1/sentinel-core/pkg/compiler/singbox"
	"github.com/blackalex1/sentinel-core/pkg/parser"
	"github.com/blackalex1/sentinel-core/pkg/routing"
)

func findCoreBin(name string) string {
	candidates := []string{
		"../../bin/" + name,
		"../../bin/" + name + ".exe",
		"../../../panel/bin/" + name,
		"../../../panel/bin/" + name + ".exe",
		"../../panel/bin/" + name,
		"../../panel/bin/" + name + ".exe",
		"../bin/" + name,
		"../bin/" + name + ".exe",
		"bin/" + name,
		"bin/" + name + ".exe",
	}
	for _, c := range candidates {
		if fi, err := os.Stat(c); err == nil && !fi.IsDir() {
			return c
		}
	}
	if lp, err := exec.LookPath(name); err == nil {
		return lp
	}
	return ""
}

// 1. Standard Hysteria 2 Native Client with Password Auth
func TestHysteria2_Client_StandardPassword(t *testing.T) {
	rawURI := "hy2://SuperSecretPass123@node.hy2.network:8443?sni=node.hy2.network&insecure=0#Standard-Hy2"
	profile, err := parser.ParseURI(rawURI)
	if err != nil {
		t.Fatalf("failed to parse URI: %v", err)
	}

	spec := &ast.ConfigSpec{
		TargetCore: ast.CoreHysteria2,
		LogLevel:   "info",
		ClientInbound: &ast.ClientInboundSpec{
			Mode:      ast.InboundModeSystemProxy,
			SocksPort: 10818,
			HTTPPort:  10819,
		},
		ServerNode: profile,
	}

	comp := hysteria.NewCompiler()
	cfgJSON, warnings, err := comp.Compile(spec)
	if err != nil {
		t.Fatalf("failed to compile native Hysteria 2 client config: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(cfgJSON), &parsed); err != nil {
		t.Fatalf("invalid JSON generated: %v\nJSON:\n%s", err, cfgJSON)
	}

	if parsed["server"] != "node.hy2.network:8443" {
		t.Errorf("expected server node.hy2.network:8443, got %v", parsed["server"])
	}
	if parsed["auth"] != "SuperSecretPass123" {
		t.Errorf("expected auth SuperSecretPass123, got %v", parsed["auth"])
	}

	socks5Map, ok := parsed["socks5"].(map[string]interface{})
	if !ok || socks5Map["listen"] != "127.0.0.1:10818" {
		t.Errorf("expected socks5 listen 127.0.0.1:10818, got %v", socks5Map)
	}

	httpMap, ok := parsed["http"].(map[string]interface{})
	if !ok || httpMap["listen"] != "127.0.0.1:10819" {
		t.Errorf("expected http listen 127.0.0.1:10819, got %v", httpMap)
	}

	t.Logf("✅ Hysteria 2 Standard Password Client verified (%d warnings)", len(warnings))
}

// 2. Hysteria 2 Native Client with Obfuscation (Salamander) and Multi-Port (Port Hopping)
func TestHysteria2_Client_SalamanderObfs_PortHopping(t *testing.T) {
	rawURI := "hy2://mypassword@198.51.100.11:8443?sni=cdn.example.com&insecure=1&obfs=salamander&obfs-password=obfspassword123&mport=20000-40000#Salamander-Hopping"
	profile, err := parser.ParseURI(rawURI)
	if err != nil {
		t.Fatalf("failed to parse URI: %v", err)
	}

	if profile.PortHopping != "20000-40000" {
		t.Errorf("expected port hopping 20000-40000, got %s", profile.PortHopping)
	}
	if profile.ObfsPassword != "obfspassword123" {
		t.Errorf("expected obfs password obfspassword123, got %s", profile.ObfsPassword)
	}

	spec := &ast.ConfigSpec{
		TargetCore: ast.CoreHysteria2,
		LogLevel:   "debug",
		ClientInbound: &ast.ClientInboundSpec{
			Mode:      ast.InboundModeSystemProxy,
			SocksPort: 10818,
		},
		ServerNode: profile,
	}

	comp := hysteria.NewCompiler()
	cfgJSON, _, err := comp.Compile(spec)
	if err != nil {
		t.Fatalf("failed to compile Hysteria 2 obfs config: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(cfgJSON), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if parsed["server"] != "198.51.100.11:20000-40000" {
		t.Errorf("expected server 198.51.100.11:20000-40000, got %v", parsed["server"])
	}

	obfsMap, ok := parsed["obfs"].(map[string]interface{})
	if !ok || obfsMap["type"] != "salamander" {
		t.Fatalf("expected salamander obfs, got %v", obfsMap)
	}
	salMap := obfsMap["salamander"].(map[string]interface{})
	if salMap["password"] != "obfspassword123" {
		t.Errorf("expected salamander password obfspassword123, got %v", salMap["password"])
	}

	tlsMap := parsed["tls"].(map[string]interface{})
	if tlsMap["sni"] != "cdn.example.com" || tlsMap["insecure"] != true {
		t.Errorf("unexpected tls configuration: %v", tlsMap)
	}

	t.Logf("✅ Hysteria 2 Salamander & Port-Hopping verified")
}

// 3. Hysteria 2 Bandwidth Limits (Up / Down) and Pinned SHA256 Certificate
func TestHysteria2_Client_BandwidthAndPinnedCert(t *testing.T) {
	rawURI := "hy2://authkey999@node.vpn:443?upmbps=100&downmbps=500&pinSHA256=11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff#BwLimitNode"
	profile, err := parser.ParseURI(rawURI)
	if err != nil {
		t.Fatalf("failed to parse URI: %v", err)
	}

	spec := &ast.ConfigSpec{
		TargetCore: ast.CoreHysteria2,
		ServerNode: profile,
	}

	comp := hysteria.NewCompiler()
	cfgJSON, _, err := comp.Compile(spec)
	if err != nil {
		t.Fatalf("failed to compile config: %v", err)
	}

	var parsed map[string]interface{}
	json.Unmarshal([]byte(cfgJSON), &parsed)

	bwMap, ok := parsed["bandwidth"].(map[string]interface{})
	if !ok || (bwMap["up"] != "100" && bwMap["up"] != "100 mbps") || (bwMap["down"] != "500" && bwMap["down"] != "500 mbps") {
		t.Errorf("expected bandwidth 100/500 mbps, got %v", bwMap)
	}

	tlsMap := parsed["tls"].(map[string]interface{})
	if tlsMap["pinSHA256"] != "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff" {
		t.Errorf("expected pinSHA256, got %v", tlsMap["pinSHA256"])
	}

	t.Logf("✅ Hysteria 2 Bandwidth and Certificate Pinning verified")
}

// 4. Sing-box Compilation with Hysteria 2 Outbound + Full Smart Routing Table
func TestHysteria2_SingBox_CompilationWithSmartRouting(t *testing.T) {
	rawURI := "hy2://mypassword@198.51.100.11:8443?sni=cdn.example.com&obfs=salamander&obfs-password=obfspass&mport=20000-40000#SingBox-Hy2"
	profile, err := parser.ParseURI(rawURI)
	if err != nil {
		t.Fatalf("failed to parse URI: %v", err)
	}

	engine := routing.NewEngine()
	policy := routing.DefaultSmartPolicy()

	spec := &ast.ConfigSpec{
		TargetCore: ast.CoreSingBox,
		LogLevel:   "info",
		ClientInbound: &ast.ClientInboundSpec{
			Mode:      ast.InboundModeSystemProxy,
			SocksPort: 10818,
			HTTPPort:  10819,
		},
		ServerNode: profile,
		Routing:    engine.CompilePolicy(policy),
		DNS: &ast.DNSSpec{
			RemoteServer: "https://1.1.1.1/dns-query",
			DirectServer: "8.8.8.8",
			Strategy:     "ipv4_only",
		},
	}

	sc := singbox.NewCompiler()
	sbJSON, _, err := sc.Compile(spec)
	if err != nil {
		t.Fatalf("singbox.Compile failed: %v", err)
	}

	var sbMap map[string]interface{}
	if err := json.Unmarshal([]byte(sbJSON), &sbMap); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	outbounds := sbMap["outbounds"].([]interface{})
	primaryOB := outbounds[0].(map[string]interface{})
	if primaryOB["type"] != "hysteria2" {
		t.Fatalf("expected hysteria2 outbound, got %v", primaryOB["type"])
	}
	if primaryOB["server"] != "198.51.100.11" {
		t.Errorf("unexpected server: %v", primaryOB["server"])
	}
	if primaryOB["server_ports"] == nil {
		t.Errorf("expected server_ports in outbound, got nil")
	}

	// Live Sing-box syntax check with real binary
	sbBin := findCoreBin("sing-box")
	if sbBin != "" {
		tmpFile, _ := os.CreateTemp("", "sb-hy2-*.json")
		tmpFile.WriteString(sbJSON)
		tmpFile.Close()
		defer os.Remove(tmpFile.Name())

		cmd := exec.Command(sbBin, "check", "-c", tmpFile.Name())
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("Sing-box live syntax check failed: %v\nOutput: %s\nConfig:\n%s", err, string(out), sbJSON)
		}
	}

	t.Logf("✅ Hysteria 2 in Sing-box (with Smart Routing & Live Binary Check) verified")
}

// 5. Auto-negotiation of Target Core: Standalone vs Sing-box Routing
func TestHysteria2_AutoSwitchToSingBoxWithRouting(t *testing.T) {
	rawURI := "hy2://mypassword@198.51.100.11:8443#Hy2AutoSwitch"
	profile, _ := parser.ParseURI(rawURI)

	engine := routing.NewEngine()
	policy := routing.DefaultSmartPolicy()

	spec := &ast.ConfigSpec{
		TargetCore: ast.CoreHysteria2, // User requests native Hysteria2
		ServerNode: profile,
		Routing:    engine.CompilePolicy(policy), // But routing rules are present
	}

	res, err := builder.BuildClientConfig(spec)
	if err != nil {
		t.Fatalf("BuildClientConfig failed: %v", err)
	}

	// Builder must gracefully auto-switch target core to Sing-box
	if res.TargetCore != ast.CoreSingBox {
		t.Errorf("expected auto-switch to Sing-box, got: %s", res.TargetCore)
	}
	if len(res.Warnings) == 0 {
		t.Errorf("expected negotiation warning about auto-switch")
	}

	t.Logf("✅ Hysteria 2 graceful auto-switch to Sing-box verified")
}
