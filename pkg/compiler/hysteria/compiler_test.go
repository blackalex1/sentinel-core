package hysteria

import (
	"strings"
	"testing"

	"github.com/blackalex1/sentinel-core/pkg/ast"
)

// --- Client Compiler Tests ---

func TestHysteriaClientCompiler_NilSpec(t *testing.T) {
	c := NewCompiler()
	_, _, err := c.Compile(nil)
	if err == nil {
		t.Fatal("expected error for nil spec, got nil")
	}

	specWithoutNode := &ast.ConfigSpec{
		TargetCore: ast.CoreHysteria2,
	}
	_, _, err = c.Compile(specWithoutNode)
	if err == nil {
		t.Fatal("expected error for nil server node, got nil")
	}
}

func TestHysteriaClientCompiler_NegotiationError(t *testing.T) {
	c := NewCompiler()
	// Using strict mode with an unsupported protocol or unsupported feature for Hysteria2
	spec := &ast.ConfigSpec{
		TargetCore: ast.CoreHysteria2,
		StrictMode: true,
		ServerNode: &ast.ServerProfile{
			Protocol: ast.ProtoVLESS, // Hysteria2 target core does not support VLESS
			Address:  "example.com",
			Port:     443,
		},
	}
	_, _, err := c.Compile(spec)
	if err == nil {
		t.Fatal("expected negotiation error for unsupported protocol in strict mode, got nil")
	}
}

func TestHysteriaClientCompiler_FullFeatures(t *testing.T) {
	c := NewCompiler()
	spec := &ast.ConfigSpec{
		TargetCore: ast.CoreHysteria2,
		ServerNode: &ast.ServerProfile{
			Protocol:      ast.ProtoHysteria2,
			Address:       "hy2.example.com",
			Port:          443,
			PortHopping:   "20000-40000",
			Password:      "mypassword123",
			BandwidthUp:   "50mbps",
			BandwidthDown: "200mbps",
			SNI:           "hy2.example.com",
			Insecure:      true,
			ObfsType:      "custom-salamander",
			ObfsPassword:  "obfspass123",
		},
		ClientInbound: &ast.ClientInboundSpec{
			SocksPort: 1080,
			HTTPPort:  8080,
		},
	}

	cfg, warnings, err := c.Compile(spec)
	if err != nil {
		t.Fatalf("failed to compile Hysteria2 client config: %v", err)
	}
	_ = warnings

	expectedSnippets := []string{
		`"server": "hy2.example.com:20000-40000"`,
		`"auth": "mypassword123"`,
		`"up": "50mbps"`,
		`"down": "200mbps"`,
		`"sni": "hy2.example.com"`,
		`"insecure": true`,
		`"type": "custom-salamander"`,
		`"password": "obfspass123"`,
		`"listen": "127.0.0.1:1080"`,
		`"listen": "127.0.0.1:8080"`,
	}

	for _, snippet := range expectedSnippets {
		if !strings.Contains(cfg, snippet) {
			t.Errorf("expected snippet %q in client config, got:\n%s", snippet, cfg)
		}
	}
}

func TestHysteriaClientCompiler_MinimalAndDefaults(t *testing.T) {
	c := NewCompiler()
	spec := &ast.ConfigSpec{
		TargetCore: ast.CoreHysteria2,
		ServerNode: &ast.ServerProfile{
			Protocol:     ast.ProtoHysteria2,
			Address:      "hy2.example.com",
			Port:         8443,
			Password:     "pass",
			ObfsPassword: "default-obfs-pass",
		},
		// No ClientInbound -> fallback to socks5 default 10808
	}

	cfg, _, err := c.Compile(spec)
	if err != nil {
		t.Fatalf("failed to compile minimal Hysteria2 client config: %v", err)
	}

	expectedSnippets := []string{
		`"server": "hy2.example.com:8443"`,
		`"auth": "pass"`,
		`"type": "salamander"`,
		`"listen": "127.0.0.1:10808"`,
	}

	for _, snippet := range expectedSnippets {
		if !strings.Contains(cfg, snippet) {
			t.Errorf("expected snippet %q in minimal client config, got:\n%s", snippet, cfg)
		}
	}
}

// --- Server Compiler Tests ---

func TestHysteriaServerCompiler_PortHopAndListenAddress(t *testing.T) {
	sc := NewServerCompiler()

	// 1. PortHop matching Port
	ib1 := ast.ServerInboundSpec{
		Port:          443,
		PortHop:       "443-500",
		ListenAddress: "0.0.0.0",
		Protocol:      "hysteria2",
	}
	cfg1, err := sc.CompileServer(ib1, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(cfg1, `"listen": ":443"`) {
		t.Errorf("expected :443 listen, got:\n%s", cfg1)
	}

	// 2. ListenAddress without PortHop
	ib2 := ast.ServerInboundSpec{
		Port:          8443,
		ListenAddress: "192.168.1.100",
		Protocol:      "hysteria2",
	}
	cfg2, err := sc.CompileServer(ib2, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(cfg2, `"listen": "192.168.1.100:8443"`) {
		t.Errorf("expected 192.168.1.100:8443 listen, got:\n%s", cfg2)
	}

	// 3. PortHop not matching start port -> falls back to default :port
	ib3 := ast.ServerInboundSpec{
		Port:     8443,
		PortHop:  "443-500",
		Protocol: "hysteria2",
	}
	cfg3, err := sc.CompileServer(ib3, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(cfg3, `"listen": ":8443"`) {
		t.Errorf("expected :8443 listen, got:\n%s", cfg3)
	}
}

func TestHysteriaServerCompiler_AdminPortAndLogLevel(t *testing.T) {
	sc := NewServerCompiler()

	// Custom AdminPort and custom LogLevel
	ib1 := ast.ServerInboundSpec{
		Port:      443,
		AdminPort: 9999,
	}
	cfg1, err := sc.CompileServer(ib1, 0, "debug")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(cfg1, `"127.0.0.1:9999"`) || !strings.Contains(cfg1, `"level": "debug"`) {
		t.Errorf("expected custom adminPort and loglevel, got:\n%s", cfg1)
	}

	// Default AdminPort and empty LogLevel
	ib2 := ast.ServerInboundSpec{
		Port: 1443,
	}
	cfg2, err := sc.CompileServer(ib2, 0, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expectedAdminPort := 10100 + (1443 % 1000)
	if !strings.Contains(cfg2, `"level": "info"`) {
		t.Errorf("expected default level info, got:\n%s", cfg2)
	}
	if !strings.Contains(cfg2, `"127.0.0.1:10543"`) {
		t.Errorf("expected adminPort %d, got:\n%s", expectedAdminPort, cfg2)
	}
}

func TestHysteriaServerCompiler_TLS(t *testing.T) {
	sc := NewServerCompiler()

	ib := ast.ServerInboundSpec{
		Port:     443,
		CertPath: "/etc/ssl/cert.pem",
		KeyPath:  "/etc/ssl/key.pem",
		SNI:      "example.com",
	}
	cfg, err := sc.CompileServer(ib, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(cfg, `"/etc/ssl/cert.pem"`) || !strings.Contains(cfg, `"/etc/ssl/key.pem"`) || !strings.Contains(cfg, `"sni": "example.com"`) {
		t.Errorf("expected TLS parameters in config, got:\n%s", cfg)
	}
}

func TestHysteriaServerCompiler_AuthVariants(t *testing.T) {
	sc := NewServerCompiler()

	// 1. AuthURL
	ib1 := ast.ServerInboundSpec{
		Port:    443,
		AuthURL: "https://auth.example.com/check",
	}
	cfg1, err := sc.CompileServer(ib1, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(cfg1, `"type": "http"`) || !strings.Contains(cfg1, `"https://auth.example.com/check"`) {
		t.Errorf("expected HTTP auth with AuthURL, got:\n%s", cfg1)
	}

	// 2. Webhook via client email / ID / http URL password
	ibWebhook1 := ast.ServerInboundSpec{
		Port: 443,
		Clients: []ast.ServerInboundClient{
			{Email: "http_webhook", Password: "https://webhook.example.com/auth"},
		},
	}
	cfgWebhook1, err := sc.CompileServer(ibWebhook1, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(cfgWebhook1, `"type": "http"`) || !strings.Contains(cfgWebhook1, `"https://webhook.example.com/auth"`) {
		t.Errorf("expected HTTP auth via webhook client email, got:\n%s", cfgWebhook1)
	}

	ibWebhook2 := ast.ServerInboundSpec{
		Port: 443,
		Clients: []ast.ServerInboundClient{
			{ID: "webhook", Password: "http://webhook.internal/auth"},
		},
	}
	cfgWebhook2, err := sc.CompileServer(ibWebhook2, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(cfgWebhook2, `"type": "http"`) || !strings.Contains(cfgWebhook2, `"http://webhook.internal/auth"`) {
		t.Errorf("expected HTTP auth via webhook client ID, got:\n%s", cfgWebhook2)
	}

	// 3. Userpass with multiple clients (email, uuid, default)
	ibUserpass := ast.ServerInboundSpec{
		Port: 443,
		Clients: []ast.ServerInboundClient{
			{Email: "user1@example.com", Password: "pass1"},
			{UUID: "uuid-user-2", Password: "pass2"},
			{Password: "pass3"}, // neither email nor uuid -> fallback "user"
		},
	}
	cfgUserpass, err := sc.CompileServer(ibUserpass, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(cfgUserpass, `"type": "userpass"`) ||
		!strings.Contains(cfgUserpass, `"user1@example.com": "pass1"`) ||
		!strings.Contains(cfgUserpass, `"uuid-user-2": "pass2"`) ||
		!strings.Contains(cfgUserpass, `"user": "pass3"`) {
		t.Errorf("expected userpass map with all users, got:\n%s", cfgUserpass)
	}

	// 4. No clients -> default secret password
	ibNoClients := ast.ServerInboundSpec{
		Port: 443,
	}
	cfgNoClients, err := sc.CompileServer(ibNoClients, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(cfgNoClients, `"type": "password"`) || !strings.Contains(cfgNoClients, `"default-secret"`) {
		t.Errorf("expected default password auth, got:\n%s", cfgNoClients)
	}
}

func TestHysteriaServerCompiler_ObfsAndBandwidth(t *testing.T) {
	sc := NewServerCompiler()

	ib := ast.ServerInboundSpec{
		Port:          443,
		ObfsType:      "custom-obfs",
		ObfsPassword:  "secret-obfs",
		BandwidthUp:   "100mbps",
		BandwidthDown: "500mbps",
	}
	cfg, err := sc.CompileServer(ib, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(cfg, `"type": "custom-obfs"`) || !strings.Contains(cfg, `"password": "secret-obfs"`) {
		t.Errorf("expected custom obfs, got:\n%s", cfg)
	}
	if !strings.Contains(cfg, `"up": "100mbps"`) || !strings.Contains(cfg, `"down": "500mbps"`) {
		t.Errorf("expected bandwidth settings, got:\n%s", cfg)
	}
}

func TestHysteriaServerCompiler_Masquerade(t *testing.T) {
	sc := NewServerCompiler()

	// 1. File
	ibFile := ast.ServerInboundSpec{
		Port:      443,
		MasqType:  "file",
		MasqValue: "/var/www/html",
	}
	cfgFile, _ := sc.CompileServer(ibFile, 0)
	if !strings.Contains(cfgFile, `"type": "file"`) || !strings.Contains(cfgFile, `"/var/www/html"`) {
		t.Errorf("expected file masquerade, got:\n%s", cfgFile)
	}

	// 2. Proxy
	ibProxy := ast.ServerInboundSpec{
		Port:      443,
		MasqType:  "proxy",
		MasqValue: "https://bing.com",
	}
	cfgProxy, _ := sc.CompileServer(ibProxy, 0)
	if !strings.Contains(cfgProxy, `"type": "proxy"`) || !strings.Contains(cfgProxy, `"https://bing.com"`) || !strings.Contains(cfgProxy, `"rewriteHost": true`) {
		t.Errorf("expected proxy masquerade, got:\n%s", cfgProxy)
	}

	// 3. String / status / drop with status codes 403, 444, 500
	ib403 := ast.ServerInboundSpec{
		Port:           443,
		MasqType:       "status",
		MasqStatusCode: 403,
	}
	cfg403, _ := sc.CompileServer(ib403, 0)
	if !strings.Contains(cfg403, `"statusCode": 403`) || !strings.Contains(cfg403, `"content": "Forbidden"`) {
		t.Errorf("expected 403 Forbidden masquerade, got:\n%s", cfg403)
	}

	ib444 := ast.ServerInboundSpec{
		Port:           443,
		MasqType:       "drop",
		MasqStatusCode: 444,
	}
	cfg444, _ := sc.CompileServer(ib444, 0)
	if !strings.Contains(cfg444, `"statusCode": 444`) || !strings.Contains(cfg444, `"content": "Connection dropped"`) {
		t.Errorf("expected 444 Connection dropped masquerade, got:\n%s", cfg444)
	}

	ibCustomStatus := ast.ServerInboundSpec{
		Port:           443,
		MasqType:       "string",
		MasqStatusCode: 502,
	}
	cfgCustomStatus, _ := sc.CompileServer(ibCustomStatus, 0)
	if !strings.Contains(cfgCustomStatus, `"statusCode": 502`) || !strings.Contains(cfgCustomStatus, `"content": "Not Found"`) {
		t.Errorf("expected 502 Not Found masquerade, got:\n%s", cfgCustomStatus)
	}

	// 4. Default with MasqValue (proxy)
	ibDefVal := ast.ServerInboundSpec{
		Port:      443,
		MasqValue: "https://news.ycombinator.com",
	}
	cfgDefVal, _ := sc.CompileServer(ibDefVal, 0)
	if !strings.Contains(cfgDefVal, `"type": "proxy"`) || !strings.Contains(cfgDefVal, `"https://news.ycombinator.com"`) {
		t.Errorf("expected default proxy masquerade with value, got:\n%s", cfgDefVal)
	}

	// 5. Default without MasqValue (404 string)
	ibDefEmpty := ast.ServerInboundSpec{
		Port: 443,
	}
	cfgDefEmpty, _ := sc.CompileServer(ibDefEmpty, 0)
	if !strings.Contains(cfgDefEmpty, `"type": "string"`) || !strings.Contains(cfgDefEmpty, `"statusCode": 404`) {
		t.Errorf("expected default 404 string masquerade, got:\n%s", cfgDefEmpty)
	}
}

func TestHysteriaServerCompiler_Outbounds(t *testing.T) {
	sc := NewServerCompiler()

	// 1. Inbound SocksPort specified with credentials
	ib1 := ast.ServerInboundSpec{
		Port:          443,
		SocksPort:     10808,
		SocksUsername: "sentinel_user",
		SocksPassword: "sentinel_password",
	}
	cfg1, err := sc.CompileServer(ib1, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(cfg1, `"name": "xray-routing"`) ||
		!strings.Contains(cfg1, `"addr": "127.0.0.1:10808"`) ||
		!strings.Contains(cfg1, `"username": "sentinel_user"`) ||
		!strings.Contains(cfg1, `"password": "sentinel_password"`) {
		t.Errorf("expected outbounds with credentials, got:\n%s", cfg1)
	}

	// 2. ForwardToXraySocksPort argument used when inbound.SocksPort is 0
	ib2 := ast.ServerInboundSpec{
		Port: 443,
	}
	cfg2, err := sc.CompileServer(ib2, 20808)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(cfg2, `"addr": "127.0.0.1:20808"`) {
		t.Errorf("expected forwardToXraySocksPort 20808 in outbounds, got:\n%s", cfg2)
	}

	// 3. No socksPort (0) -> outbounds omitted
	cfg3, err := sc.CompileServer(ib2, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(cfg3, `"outbounds"`) {
		t.Errorf("outbounds should be omitted when socksPort is 0, got:\n%s", cfg3)
	}
}
