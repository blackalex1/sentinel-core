package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func captureOutput(f func()) string {
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	outChan := make(chan string)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		outChan <- buf.String()
	}()

	func() {
		defer func() {
			_ = recover()
		}()
		f()
	}()

	_ = w.Close()
	os.Stdout = oldStdout
	return <-outChan
}

func mockStdin(input string, f func()) {
	oldStdin := os.Stdin
	r, w, _ := os.Pipe()
	os.Stdin = r

	go func() {
		_, _ = w.Write([]byte(input))
		_ = w.Close()
	}()

	f()

	_ = r.Close()
	os.Stdin = oldStdin
}

func runWithExitCapture(f func()) (exitCode int, out string) {
	oldExit := exitFunc
	exitCode = 0
	exitFunc = func(code int) {
		exitCode = code
		panic("cli_exit")
	}
	defer func() {
		exitFunc = oldExit
	}()

	out = captureOutput(f)
	return
}

func TestCLI_PrintUsage(t *testing.T) {
	out := captureOutput(func() {
		printUsage()
	})
	if !strings.Contains(out, "Sentinel-Core CLI") {
		t.Errorf("expected usage info in output, got: %s", out)
	}
}

func TestCLI_Main_Dispatch(t *testing.T) {
	origArgs := os.Args
	defer func() { os.Args = origArgs }()

	// 1. keypair via main()
	os.Args = []string{"sentinel-core", "keypair"}
	outKey := captureOutput(func() {
		main()
	})
	if !strings.Contains(outKey, "privateKey") {
		t.Errorf("expected keypair output from main, got: %s", outKey)
	}

	// 2. vlessenc via main()
	os.Args = []string{"sentinel-core", "vlessenc"}
	outVless := captureOutput(func() {
		main()
	})
	if !strings.Contains(outVless, "x25519") {
		t.Errorf("expected vlessenc output from main, got: %s", outVless)
	}

	// 3. schema via main()
	os.Args = []string{"sentinel-core", "schema", "--lang=en"}
	outSchema := captureOutput(func() {
		main()
	})
	if !strings.Contains(outSchema, "engines") {
		t.Errorf("expected schema output from main, got: %s", outSchema)
	}

	// 4. health via main()
	os.Args = []string{"sentinel-core", "health", "--socks=59976", "--http=59975"}
	outHealth := captureOutput(func() {
		main()
	})
	if !strings.Contains(outHealth, "Health Check Result") {
		t.Errorf("expected health output from main, got: %s", outHealth)
	}

	// 5. ping via main()
	os.Args = []string{"sentinel-core", "ping", "127.0.0.1", "--port=59974", "--timeout-ms=50"}
	outPing := captureOutput(func() {
		main()
	})
	if !strings.Contains(outPing, "success") {
		t.Errorf("expected ping output from main, got: %s", outPing)
	}

	// 6. encrypt via main()
	os.Args = []string{"sentinel-core", "encrypt", "--secret=Pass123", "--text=PlainText"}
	outEnc := captureOutput(func() {
		main()
	})
	var encRes struct {
		Payload string `json:"payload"`
	}
	_ = json.Unmarshal([]byte(strings.TrimSpace(outEnc)), &encRes)

	// 7. decrypt via main()
	os.Args = []string{"sentinel-core", "decrypt", "--secret=Pass123", "--payload=" + encRes.Payload}
	outDec := captureOutput(func() {
		main()
	})
	if !strings.Contains(outDec, "PlainText") {
		t.Errorf("expected decrypt output from main, got: %s", outDec)
	}

	// 8. preset via main()
	os.Args = []string{"sentinel-core", "preset", "list", "--json"}
	outPreset := captureOutput(func() {
		main()
	})
	if !strings.Contains(outPreset, "ru") {
		t.Errorf("expected preset output from main, got: %s", outPreset)
	}

	// 9. supervisor via main()
	os.Args = []string{"sentinel-core", "supervisor", "status"}
	outSuper := captureOutput(func() {
		main()
	})
	if !strings.Contains(outSuper, "sing-box") {
		t.Errorf("expected supervisor output from main, got: %s", outSuper)
	}

	// 10. parse via main()
	uri := "vless://a6c8e874-a4ee-4c38-89c0-6d427d1421bf@198.51.100.1:443?security=reality&sni=example.com&fp=chrome&pbk=myPublicKey123&type=tcp#TestNode"
	os.Args = []string{"sentinel-core", "parse", "--uri", uri}
	outParse := captureOutput(func() {
		main()
	})
	if !strings.Contains(outParse, "198.51.100.1") {
		t.Errorf("expected parse output from main, got: %s", outParse)
	}

	// 11. generate via main()
	os.Args = []string{"sentinel-core", "generate", "--profile", strings.TrimSpace(outParse)}
	outGen := captureOutput(func() {
		main()
	})
	if !strings.HasPrefix(strings.TrimSpace(outGen), "vless://") {
		t.Errorf("expected generate output from main, got: %s", outGen)
	}

	// 12. build via main()
	os.Args = []string{"sentinel-core", "build", "--uri", uri, "--core", "singbox"}
	outBuild := captureOutput(func() {
		main()
	})
	if !strings.Contains(outBuild, "inbounds") {
		t.Errorf("expected build output from main, got: %s", outBuild)
	}

	// 13. compile-server via main()
	specJSON := `{"targetCore":"singbox","serverInbounds":[{"protocol":"vless","port":443,"uuid":"a6c8e874-a4ee-4c38-89c0-6d427d1421bf"}]}`
	os.Args = []string{"sentinel-core", "compile-server", "--spec", specJSON}
	outCompile := captureOutput(func() {
		main()
	})
	if !strings.Contains(outCompile, "inbounds") {
		t.Errorf("expected compile-server output from main, got: %s", outCompile)
	}
}

func TestCLI_Build_OptionsAndWarnings(t *testing.T) {
	origArgs := os.Args
	defer func() { os.Args = origArgs }()

	trojanURI := "trojan://password123@198.51.100.1:443?security=reality&pbk=pubkey123&sni=example.com#TrojanReality"
	os.Args = []string{"sentinel-core", "build", "--uri", trojanURI, "--core", "singbox", "--block-ads=true", "--bypass-ru=true"}
	out := captureOutput(func() {
		handleBuild()
	})
	if !strings.Contains(out, "inbounds") {
		t.Errorf("expected valid config output, got: %s", out)
	}

	// Build error with invalid server node parameters
	badURI := "vless://invalid-uuid-missing-address"
	os.Args = []string{"sentinel-core", "build", "--uri", badURI}
	code, outErr := runWithExitCapture(func() {
		handleBuild()
	})
	if code != 1 {
		t.Errorf("expected build error for bad URI, got code=%d, out=%s", code, outErr)
	}
}

func TestCLI_CompileServer_Stdin(t *testing.T) {
	origArgs := os.Args
	defer func() { os.Args = origArgs }()

	specJSON := `{"targetCore":"singbox","serverInbounds":[{"protocol":"vless","port":443,"uuid":"a6c8e874-a4ee-4c38-89c0-6d427d1421bf"}]}`
	os.Args = []string{"sentinel-core", "compile-server"}

	var out string
	mockStdin(specJSON, func() {
		out = captureOutput(func() {
			handleCompileServer()
		})
	})

	if !strings.Contains(out, "inbounds") {
		t.Errorf("expected server config from stdin, got: %s", out)
	}
}

func TestCLI_Generate_Stdin(t *testing.T) {
	origArgs := os.Args
	defer func() { os.Args = origArgs }()

	profileJSON := `{"protocol":"vless","address":"198.51.100.1","port":443,"uuid":"a6c8e874-a4ee-4c38-89c0-6d427d1421bf","security":"reality","sni":"example.com","public_key":"myPublicKey123"}`
	os.Args = []string{"sentinel-core", "generate"}

	var out string
	mockStdin(profileJSON, func() {
		out = captureOutput(func() {
			handleGenerate()
		})
	})

	if !strings.HasPrefix(strings.TrimSpace(out), "vless://") {
		t.Errorf("expected generated URI from stdin, got: %s", out)
	}

	// Generate with unsupported protocol
	badProfileJSON := `{"protocol":"unsupported-protocol","address":"198.51.100.1","port":443}`
	os.Args = []string{"sentinel-core", "generate", "--profile", badProfileJSON}
	code, outBad := runWithExitCapture(func() {
		handleGenerate()
	})
	if code != 1 || !strings.Contains(outBad, "Generate error") {
		t.Errorf("expected generate error, got code=%d, out=%s", code, outBad)
	}
}

func TestCLI_Preset_ListAndShow(t *testing.T) {
	origArgs := os.Args
	defer func() { os.Args = origArgs }()

	// Plain list
	os.Args = []string{"sentinel-core", "preset", "list"}
	out := captureOutput(func() {
		handlePreset()
	})
	if !strings.Contains(out, "Available Routing Presets:") {
		t.Errorf("expected preset list header, got: %s", out)
	}

	// Show
	os.Args = []string{"sentinel-core", "preset", "show", "ads"}
	outShow := captureOutput(func() {
		handlePreset()
	})
	if !strings.Contains(outShow, `"id": "ads"`) {
		t.Errorf("expected ads preset, got: %s", outShow)
	}
}

func TestCLI_Supervisor_Extended(t *testing.T) {
	origArgs := os.Args
	defer func() { os.Args = origArgs }()

	// Traffic
	os.Args = []string{"sentinel-core", "supervisor", "traffic"}
	out := captureOutput(func() {
		handleSupervisor()
	})
	if !strings.Contains(out, "{") {
		t.Errorf("expected traffic JSON, got: %s", out)
	}

	// Logs
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "test.log")
	_ = os.WriteFile(logFile, []byte("line 1\nline 2\n"), 0644)
	os.Args = []string{"sentinel-core", "supervisor", "logs", "--path", logFile, "--lines=5"}
	outLogs := captureOutput(func() {
		handleSupervisor()
	})
	if !strings.Contains(outLogs, "line 1") {
		t.Errorf("expected logs, got: %s", outLogs)
	}

	dummyBin, err := exec.LookPath("powershell")
	if err != nil {
		dummyBin, err = exec.LookPath("cmd")
	}
	if err == nil {
		cfgFile := filepath.Join(tmpDir, "cfg.json")
		_ = os.WriteFile(cfgFile, []byte(`{"inbounds":[]}`), 0644)

		// Start
		os.Args = []string{"sentinel-core", "supervisor", "start", "--core", "xray", "--bin", dummyBin, "--config", cfgFile}
		_ = captureOutput(func() { handleSupervisor() })

		// Restart
		os.Args = []string{"sentinel-core", "supervisor", "restart", "--core", "xray", "--bin", dummyBin, "--config", cfgFile}
		_ = captureOutput(func() { handleSupervisor() })

		// Stop
		os.Args = []string{"sentinel-core", "supervisor", "stop", "--core", "xray"}
		_ = captureOutput(func() { handleSupervisor() })

		// Validate
		os.Args = []string{"sentinel-core", "supervisor", "validate", "--core", "hysteria2", "--bin", dummyBin, "--config", cfgFile}
		outVal := captureOutput(func() { handleSupervisor() })
		if !strings.Contains(outVal, "valid") {
			t.Errorf("expected validation result, got: %s", outVal)
		}

		// Version
		os.Args = []string{"sentinel-core", "supervisor", "version", "--core", "sing-box", "--bin", dummyBin}
		outVer := captureOutput(func() { handleSupervisor() })
		if !strings.Contains(outVer, "version") {
			t.Errorf("expected version result, got: %s", outVer)
		}

		// Start with non-existent binary -> error
		os.Args = []string{"sentinel-core", "supervisor", "start", "--core", "xray", "--bin", "non_existent_binary_xyz.exe"}
		code, outStartErr := runWithExitCapture(func() { handleSupervisor() })
		if code != 1 || !strings.Contains(outStartErr, "Start error") {
			t.Errorf("expected start error, got code=%d, out=%s", code, outStartErr)
		}

		// Restart with non-existent binary -> error
		os.Args = []string{"sentinel-core", "supervisor", "restart", "--core", "xray", "--bin", "non_existent_binary_xyz.exe"}
		code, outRestartErr := runWithExitCapture(func() { handleSupervisor() })
		if code != 1 || !strings.Contains(outRestartErr, "Restart error") {
			t.Errorf("expected restart error, got code=%d, out=%s", code, outRestartErr)
		}
	}
}

func TestCLI_ErrorBranches(t *testing.T) {
	origArgs := os.Args
	defer func() { os.Args = origArgs }()

	// 1. main no args (< 2)
	os.Args = []string{"sentinel-core"}
	code, _ := runWithExitCapture(func() { main() })
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}

	// 2. main unknown command
	os.Args = []string{"sentinel-core", "unknown-cmd"}
	code, _ = runWithExitCapture(func() { main() })
	if code != 1 {
		t.Errorf("expected exit code 1 for unknown command, got %d", code)
	}

	// 3. parse missing uri
	os.Args = []string{"sentinel-core", "parse"}
	code, _ = runWithExitCapture(func() { handleParse() })
	if code != 1 {
		t.Errorf("expected exit code 1 for missing uri, got %d", code)
	}

	// 4. parse invalid uri
	os.Args = []string{"sentinel-core", "parse", "--uri", "invalid://broken"}
	code, _ = runWithExitCapture(func() { handleParse() })
	if code != 1 {
		t.Errorf("expected exit code 1 for invalid uri, got %d", code)
	}

	// 5. build missing uri
	os.Args = []string{"sentinel-core", "build"}
	code, _ = runWithExitCapture(func() { handleBuild() })
	if code != 1 {
		t.Errorf("expected exit code 1 for missing build uri, got %d", code)
	}

	// 6. build invalid uri
	os.Args = []string{"sentinel-core", "build", "--uri", "invalid://broken"}
	code, _ = runWithExitCapture(func() { handleBuild() })
	if code != 1 {
		t.Errorf("expected exit code 1 for invalid build uri, got %d", code)
	}

	// 7. build invalid preset file
	vlessURI := "vless://a6c8e874-a4ee-4c38-89c0-6d427d1421bf@198.51.100.1:443?security=reality&sni=example.com&fp=chrome&pbk=myPublicKey123&type=tcp"
	os.Args = []string{"sentinel-core", "build", "--uri", vlessURI, "--preset", "non_existent_preset_xyz.json"}
	code, _ = runWithExitCapture(func() { handleBuild() })
	if code != 1 {
		t.Errorf("expected exit code 1 for missing preset file, got %d", code)
	}

	// 8. encrypt missing flags
	os.Args = []string{"sentinel-core", "encrypt"}
	code, _ = runWithExitCapture(func() { handleEncrypt() })
	if code != 1 {
		t.Errorf("expected exit code 1 for missing encrypt flags, got %d", code)
	}

	// 9. decrypt missing flags
	os.Args = []string{"sentinel-core", "decrypt"}
	code, _ = runWithExitCapture(func() { handleDecrypt() })
	if code != 1 {
		t.Errorf("expected exit code 1 for missing decrypt flags, got %d", code)
	}

	// 10. decrypt error
	os.Args = []string{"sentinel-core", "decrypt", "--secret", "secret", "--payload", "invalid-enc-payload"}
	code, _ = runWithExitCapture(func() { handleDecrypt() })
	if code != 1 {
		t.Errorf("expected exit code 1 for invalid decrypt payload, got %d", code)
	}

	// 11. preset < 3 args
	os.Args = []string{"sentinel-core", "preset"}
	code, _ = runWithExitCapture(func() { handlePreset() })
	if code != 1 {
		t.Errorf("expected exit code 1 for preset < 3 args, got %d", code)
	}

	// 12. preset show < 4 args
	os.Args = []string{"sentinel-core", "preset", "show"}
	code, _ = runWithExitCapture(func() { handlePreset() })
	if code != 1 {
		t.Errorf("expected exit code 1 for preset show < 4 args, got %d", code)
	}

	// 13. preset show invalid id
	os.Args = []string{"sentinel-core", "preset", "show", "non_existent_id_xyz"}
	code, _ = runWithExitCapture(func() { handlePreset() })
	if code != 1 {
		t.Errorf("expected exit code 1 for preset show invalid id, got %d", code)
	}

	// 14. preset import < 4 args
	os.Args = []string{"sentinel-core", "preset", "import"}
	code, _ = runWithExitCapture(func() { handlePreset() })
	if code != 1 {
		t.Errorf("expected exit code 1 for preset import < 4 args, got %d", code)
	}

	// 15. preset import non existent file
	os.Args = []string{"sentinel-core", "preset", "import", "non_existent_file.json"}
	code, _ = runWithExitCapture(func() { handlePreset() })
	if code != 1 {
		t.Errorf("expected exit code 1 for preset import invalid file, got %d", code)
	}

	// 16. preset unknown command
	os.Args = []string{"sentinel-core", "preset", "unknown"}
	code, _ = runWithExitCapture(func() { handlePreset() })
	if code != 1 {
		t.Errorf("expected exit code 1 for unknown preset command, got %d", code)
	}

	// 17. compile-server non existent file
	os.Args = []string{"sentinel-core", "compile-server", "--file", "non_existent_spec.json"}
	code, _ = runWithExitCapture(func() { handleCompileServer() })
	if code != 1 {
		t.Errorf("expected exit code 1 for missing spec file, got %d", code)
	}

	// 18. compile-server invalid JSON
	os.Args = []string{"sentinel-core", "compile-server", "--spec", "{invalid-json"}
	code, _ = runWithExitCapture(func() { handleCompileServer() })
	if code != 1 {
		t.Errorf("expected exit code 1 for invalid spec JSON, got %d", code)
	}

	// 19. generate invalid JSON
	os.Args = []string{"sentinel-core", "generate", "--profile", "{invalid-json"}
	code, _ = runWithExitCapture(func() { handleGenerate() })
	if code != 1 {
		t.Errorf("expected exit code 1 for invalid profile JSON, got %d", code)
	}

	// 20. ping < 3 args
	os.Args = []string{"sentinel-core", "ping"}
	code, _ = runWithExitCapture(func() { handlePing() })
	if code != 1 {
		t.Errorf("expected exit code 1 for ping < 3 args, got %d", code)
	}

	// 21. supervisor < 3 args
	os.Args = []string{"sentinel-core", "supervisor"}
	code, _ = runWithExitCapture(func() { handleSupervisor() })
	if code != 1 {
		t.Errorf("expected exit code 1 for supervisor < 3 args, got %d", code)
	}

	// 22. supervisor kick missing client
	os.Args = []string{"sentinel-core", "supervisor", "kick"}
	code, _ = runWithExitCapture(func() { handleSupervisor() })
	if code != 1 {
		t.Errorf("expected exit code 1 for supervisor kick missing client, got %d", code)
	}

	// 23. supervisor logs missing path
	os.Args = []string{"sentinel-core", "supervisor", "logs"}
	code, _ = runWithExitCapture(func() { handleSupervisor() })
	if code != 1 {
		t.Errorf("expected exit code 1 for supervisor logs missing path, got %d", code)
	}

	// 24. supervisor start missing args
	os.Args = []string{"sentinel-core", "supervisor", "start"}
	code, _ = runWithExitCapture(func() { handleSupervisor() })
	if code != 1 {
		t.Errorf("expected exit code 1 for supervisor start missing args, got %d", code)
	}

	// 25. supervisor stop missing args
	os.Args = []string{"sentinel-core", "supervisor", "stop"}
	code, _ = runWithExitCapture(func() { handleSupervisor() })
	if code != 1 {
		t.Errorf("expected exit code 1 for supervisor stop missing args, got %d", code)
	}

	// 26. supervisor restart missing args
	os.Args = []string{"sentinel-core", "supervisor", "restart"}
	code, _ = runWithExitCapture(func() { handleSupervisor() })
	if code != 1 {
		t.Errorf("expected exit code 1 for supervisor restart missing args, got %d", code)
	}

	// 27. supervisor validate missing args
	os.Args = []string{"sentinel-core", "supervisor", "validate"}
	code, _ = runWithExitCapture(func() { handleSupervisor() })
	if code != 1 {
		t.Errorf("expected exit code 1 for supervisor validate missing args, got %d", code)
	}

	// 28. supervisor version missing args
	os.Args = []string{"sentinel-core", "supervisor", "version"}
	code, _ = runWithExitCapture(func() { handleSupervisor() })
	if code != 1 {
		t.Errorf("expected exit code 1 for supervisor version missing args, got %d", code)
	}

	// 29. supervisor unknown subCmd
	os.Args = []string{"sentinel-core", "supervisor", "unknown-action"}
	code, _ = runWithExitCapture(func() { handleSupervisor() })
	if code != 1 {
		t.Errorf("expected exit code 1 for unknown supervisor action, got %d", code)
	}
}
