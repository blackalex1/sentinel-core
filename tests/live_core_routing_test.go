package tests

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blackalex1/sentinel-core/pkg/ast"
	"github.com/blackalex1/sentinel-core/pkg/builder"
	"github.com/blackalex1/sentinel-core/pkg/compiler/singbox"
	"github.com/blackalex1/sentinel-core/pkg/compiler/xray"
	"github.com/blackalex1/sentinel-core/pkg/crypto"
	"github.com/blackalex1/sentinel-core/pkg/matrix"
	"github.com/blackalex1/sentinel-core/pkg/routing"
)

// Helper to find binaries
func getBinPath(rel string) string {
	abs, err := filepath.Abs(rel)
	if err == nil {
		if _, err := os.Stat(abs); err == nil {
			return abs
		}
	}
	// Check panel/bin
	panelBin, err := filepath.Abs("../../panel/bin/" + filepath.Base(rel))
	if err == nil {
		if _, err := os.Stat(panelBin); err == nil {
			return panelBin
		}
	}
	return ""
}

func TestDirectPath_SingBox_Inbound_To_VLESS_Outbound(t *testing.T) {
	singboxBin := getBinPath("../../panel/bin/sing-box.exe")
	if singboxBin == "" {
		t.Skip("sing-box.exe not found, skipping live check")
	}

	kp, err := crypto.GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("failed to generate reality keys: %v", err)
	}

	// 1. Create Outbound via singbox compiler
	vlessOutbound, err := singbox.BuildSingBoxOutbound(&ast.ServerProfile{
		Protocol:  ast.ProtoVLESS,
		Name:      "vless-proxy",
		Address:   "1.1.1.1",
		Port:      443,
		UUID:      "b9f3857a-ce20-4e1e-b5e0-6f3d141fa2b2",
		Transport: "tcp",
		Security:  "reality",
		SNI:       "www.apple.com",
		PublicKey: kp.PublicKey,
		ShortID:   "0123456789abcdef",
	})
	if err != nil {
		t.Fatalf("failed to build singbox outbound: %v", err)
	}

	// 2. Create Routing Table with Direct Path Outbound (VLESS)
	table := routing.NewRoutingTable("direct")
	table.AddRule(routing.RoutingRuleRow{
		Order:   1,
		Name:    "Route to VLESS Outbound",
		Enabled: true,
		Target:  "vless-proxy",
		Domains: []string{"domain:example.com"},
	})

	routingAST := table.CompileToAST()
	routingAST.Outbounds = []map[string]interface{}{vlessOutbound}

	serverInbounds := []ast.ServerInboundSpec{
		{
			Tag:        "vless-in",
			Port:       38888,
			Protocol:   "vless",
			Transport:  "tcp",
			Security:   "reality",
			SNI:        "www.apple.com",
			PrivateKey: kp.PrivateKey,
			ShortIDs:   []string{"0123456789abcdef"},
			Clients: []ast.ServerInboundClient{
				{
					ID:   "b9f3857a-ce20-4e1e-b5e0-6f3d141fa2b2",
					UUID: "b9f3857a-ce20-4e1e-b5e0-6f3d141fa2b2",
					Flow: "xtls-rprx-vision",
				},
			},
		},
	}

	cfgJSON, err := builder.BuildServerConfig(ast.CoreSingBox, serverInbounds, routingAST, "")
	if err != nil {
		t.Fatalf("failed to compile Sing-box server config: %v", err)
	}

	// Verify the compiled JSON contains direct intra-core inbound and outbound
	if !strings.Contains(cfgJSON, `"vless-proxy"`) {
		t.Errorf("compiled singbox config missing vless-proxy outbound: %s", cfgJSON)
	}
	if !strings.Contains(cfgJSON, `"vless-in"`) {
		t.Errorf("compiled singbox config missing vless-in inbound: %s", cfgJSON)
	}

	// 3. Validate configuration with real sing-box binary
	tmpFile, err := os.CreateTemp("", "singbox-direct-*.json")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(cfgJSON); err != nil {
		t.Fatalf("failed to write temp config: %v", err)
	}
	tmpFile.Close()

	cmd := exec.Command(singboxBin, "check", "-c", tmpFile.Name())
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("sing-box check failed: %v, output:\n%s\nConfig:\n%s", err, string(out), cfgJSON)
	}
	t.Logf("Sing-box direct path config validated successfully with real binary: %s", strings.TrimSpace(string(out)))
}

func TestDirectPath_Xray_Inbound_To_VLESS_MLKEM_Outbound(t *testing.T) {
	xrayBin := getBinPath("../../panel/bin/xray.exe")
	if xrayBin == "" {
		t.Skip("xray.exe not found, skipping live check")
	}

	kp, err := crypto.GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("failed to generate reality keys: %v", err)
	}

	mlkemEnc := "mlkem768x25519plus.native.0rtt.rVcAgVdddyPMjQYWf9CINzDMpMAxMCDOVxMMVBonLuEkmABb2Gh7qaF3BwQpUUk-Q6mZJAo2AYgjB1s2FjGTRVBgtWResCaOdOwwPOiwkZBevHY8zqEAQvWrppKYudKUCOW6kaxRl_zFu_h7jLuTduZAUMynqUm8B1CWqOw16lAApxaVctvMDhZzVDOIyPhSdYez_SjLe4yA7VSZlPLIXInLwVA261uHtjFIuRotDlg0MwbJVBS24cqRsRR9ksMNgmObN6QF8IWk9OaSnNeqVrSvXioNjbu-WxKKYbAJiLiGA-VO8AJUUTQFUQs0lRCsZuaBnmMwsFgXNHIenuwC87yqcuuTiVmaWrtCu1W7HVlMbCwpTgMHmCNFdepRCItiifwx-djLvbYd9HyWMSaTChw9P1EQqQZYe3uW-PsOX5u0JHZO3ZU32CZZJcM46VrGmEadzxogtGMWv2WXNXrPY_WRrZKWBgx99blWCKdOQlhYjTNLtkoTRuJGQmZicEg85CVkM0kpopQfHDo3uLE0BIICt9GxoroQ_1cAjpV4iYy1CLK7shAkLQtXNGBidFZ-kqI8w3NykkokzCsE-tlWepBUoHA3a1yq3KKpmSeYQEBaeuAwVOpvD7nGEmnEIlu-6RazZKtMRmc0c5oZ4fQJp7cVjJx5TayGiXYYJmWsMglBeQkNOaSE55xCMlsIpZepEOUtCCsJSAiyYSI3LRTMx0YY8khgW6JEDZGVIeyeL7vLpTasgcCr3YaiSZlLjPs53MLGB-NxB2uphYy0VyQmSmkVXvQru0O5o1eYiSMUgMi9VKkxCvg1tDo1oYugRTWX13MVAxxnr7i-OPIoVTOlAGsBcZqfZfC5uAaoDdBtrvaxUshaxGkqaSQZzcVxGOusbgidhFYxPioY3wGsoZokSZKvFwJn-bYp00FvvlCsHUNi3bkrcGFzWcCBGWFza1BtPlC-YdtwywygsXxZs1BKT_a_VDNVgHwkEtSGiZRogRtsW-YsYmzG_DstHHW127aZryKWnVxP0lQi40i87MUIkIC2FCCILMSVY1gRDblKnYuwt1AD99FOFWYVQjquLepRL6yQyUpbG2LL10nODMWuL-yCE8wtAqyhFQiQW1BqpXXCfmwdxzJkb5smauRFQpou1XtUAXNrhKdn1TiqeKRfOSxRXkrLFZOC1ec3jAOIElTEt4gVnGuNsnxnASRvZRIIGoqj6KAaG2KLE3FalbURjAxCwoGLf4DKCbx3H9vFQCEs96eippAkK2JfhUyfW-pE0Ek3hEDF2hi3kZFxe6kpYAYwfdwCNiuoq1WZYDsC-llqQtm3rhNRSIsHq6BASrUvNlIkfAglMsM1XARFNjiMgRV4C1inJMZ26rKQO9yayYycc3scjOt1vPBioWJG-cvP84qEYprH6ZOUUiko56eYMEAuYWyn8phNw8WkEmkPe_xag4aq3np-TmDHt1Up6CiPk-oPOJYNiEondRaABFNCGqHEg5SNPxUu3bqc5cHDRnKRgDoU98VaVqkrGtktqVCP4CCSdi-4NLcbx0GLXl1bzklmmXSQCtsNcOeWL6yR_es"

	vlessOutbound, err := xray.BuildXrayOutbound(&ast.ServerProfile{
		Protocol:    ast.ProtoVLESS,
		Name:        "vless-mlkem-out",
		Address:     "192.168.1.92",
		Port:        27789,
		UUID:        "b9f3857a-ce20-4e1e-b5e0-6f3d141fa2b2",
		Transport:   "tcp",
		Security:    "reality",
		Encryption:  mlkemEnc,
		PostQuantum: true,
		SNI:         "www.apple.com",
		PublicKey:   kp.PublicKey,
		ShortID:     "0123456789abcdef",
	})
	if err != nil {
		t.Fatalf("failed to build xray outbound: %v", err)
	}

	table := routing.NewRoutingTable("direct")
	table.AddRule(routing.RoutingRuleRow{
		Order:   1,
		Name:    "Route to PQ VLESS Outbound",
		Enabled: true,
		Target:  "vless-mlkem-out",
		Domains: []string{"domain:secure-target.com"},
	})

	routingAST := table.CompileToAST()
	routingAST.Outbounds = []map[string]interface{}{vlessOutbound}

	serverInbounds := []ast.ServerInboundSpec{
		{
			Tag:        "vless-in",
			Port:       39999,
			Protocol:   "vless",
			Transport:  "tcp",
			Security:   "reality",
			SNI:        "www.apple.com",
			PrivateKey: kp.PrivateKey,
			ShortIDs:   []string{"0123456789abcdef"},
			Clients: []ast.ServerInboundClient{
				{
					ID:   "b9f3857a-ce20-4e1e-b5e0-6f3d141fa2b2",
					UUID: "b9f3857a-ce20-4e1e-b5e0-6f3d141fa2b2",
					Flow: "xtls-rprx-vision",
				},
			},
		},
	}

	cfgJSON, err := builder.BuildServerConfig(ast.CoreXray, serverInbounds, routingAST, "")
	if err != nil {
		t.Fatalf("failed to compile Xray server config: %v", err)
	}

	// Verify encryption field is present in Xray outbound
	if !strings.Contains(cfgJSON, "mlkem768x25519plus") {
		t.Errorf("compiled Xray config missing mlkem encryption in outbound: %s", cfgJSON)
	}

	// 2. Validate configuration with real xray binary
	tmpFile, err := os.CreateTemp("", "xray-direct-*.json")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(cfgJSON); err != nil {
		t.Fatalf("failed to write temp config: %v", err)
	}
	tmpFile.Close()

	cmd := exec.Command(xrayBin, "-test", "-config", tmpFile.Name())
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("xray -test failed: %v, output:\n%s\nConfig:\n%s", err, string(out), cfgJSON)
	}
	t.Logf("Xray direct path ML-KEM config validated successfully with real binary: %s", strings.TrimSpace(string(out)))
}

func TestNegotiator_Rejection_And_Adaptation(t *testing.T) {
	node := &ast.ServerProfile{
		Protocol:    ast.ProtoVLESS,
		Name:        "mlkem-node",
		Address:     "1.2.3.4",
		Port:        443,
		UUID:        "b9f3857a-ce20-4e1e-b5e0-6f3d141fa2b2",
		Security:    "reality",
		Encryption:  "mlkem768x25519plus.native...",
		PostQuantum: true,
	}

	// Strict mode: Sing-box must reject ML-KEM
	_, _, err := matrix.AutoNegotiate(node, ast.CoreSingBox, "1.11.0", true)
	if err == nil {
		t.Fatal("expected strict negotiation to fail for Sing-box with ML-KEM, but got nil")
	}

	// Soft mode: Sing-box must adapt (strip ML-KEM) and produce warnings
	adapted, warnings, err := matrix.AutoNegotiate(node, ast.CoreSingBox, "1.11.0", false)
	if err != nil {
		t.Fatalf("expected soft negotiation to succeed for Sing-box, got err: %v", err)
	}
	if adapted.PostQuantum {
		t.Error("expected PostQuantum to be downgraded to false for Sing-box")
	}
	if len(warnings) == 0 {
		t.Error("expected negotiation warning for Sing-box feature downgrade")
	}

	// Xray: Must support ML-KEM without error
	xrayAdapted, xrayWarnings, err := matrix.AutoNegotiate(node, ast.CoreXray, "24.11.0", true)
	if err != nil {
		t.Fatalf("expected Xray to support ML-KEM, got err: %v", err)
	}
	if !xrayAdapted.PostQuantum {
		t.Error("expected Xray to keep PostQuantum = true")
	}
	if len(xrayWarnings) > 0 {
		t.Errorf("unexpected warnings for Xray: %v", xrayWarnings)
	}
}
