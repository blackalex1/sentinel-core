package main

/*
#include <stdlib.h>
*/
import "C"
import (
	"encoding/json"
	"time"
	"unsafe"
	"github.com/blackalex1/sentinel-core/pkg/adapter"
	"github.com/blackalex1/sentinel-core/pkg/ast"
	"github.com/blackalex1/sentinel-core/pkg/builder"
	"github.com/blackalex1/sentinel-core/pkg/crypto"
	"github.com/blackalex1/sentinel-core/pkg/diagnostics"
	"github.com/blackalex1/sentinel-core/pkg/matrix"
	"github.com/blackalex1/sentinel-core/pkg/parser"
	"github.com/blackalex1/sentinel-core/pkg/routing"
	"github.com/blackalex1/sentinel-core/pkg/security"
	"github.com/blackalex1/sentinel-core/pkg/supervisor"
)

func safeGoString(s *C.char) string {
	if s == nil {
		return ""
	}
	return C.GoString(s)
}

//export SentinelBuildConfig
func SentinelBuildConfig(specJSON *C.char) *C.char {
	goSpecJSON := safeGoString(specJSON)

	var spec ast.ConfigSpec
	if err := json.Unmarshal([]byte(goSpecJSON), &spec); err != nil {
		errResp, _ := json.Marshal(map[string]string{"error": err.Error()})
		return C.CString(string(errResp))
	}

	res, err := builder.BuildClientConfig(&spec)
	if err != nil {
		errResp, _ := json.Marshal(map[string]string{"error": err.Error()})
		return C.CString(string(errResp))
	}

	respBytes, _ := json.Marshal(res)
	return C.CString(string(respBytes))
}

//export SentinelBuildServerConfig
func SentinelBuildServerConfig(specJSON *C.char) *C.char {
	goSpecJSON := safeGoString(specJSON)

	var spec ast.ConfigSpec
	if err := json.Unmarshal([]byte(goSpecJSON), &spec); err != nil {
		errResp, _ := json.Marshal(map[string]string{"error": err.Error()})
		return C.CString(string(errResp))
	}

	cfg, err := builder.BuildServerConfig(spec.TargetCore, spec.ServerInbounds, spec.Routing, spec.ClashAPIAddress, spec.LogPath, spec.LogLevel)
	if err != nil {
		errResp, _ := json.Marshal(map[string]string{"error": err.Error()})
		return C.CString(string(errResp))
	}

	respBytes, _ := json.Marshal(map[string]string{"config": cfg})
	return C.CString(string(respBytes))
}

//export SentinelParseURI
func SentinelParseURI(rawURI *C.char) *C.char {
	goURI := safeGoString(rawURI)
	profile, err := parser.ParseURI(goURI)
	if err != nil {
		errResp, _ := json.Marshal(map[string]string{"error": err.Error()})
		return C.CString(string(errResp))
	}

	jsonBytes, _ := json.Marshal(profile)
	return C.CString(string(jsonBytes))
}

//export SentinelGenerateURI
func SentinelGenerateURI(profileJSON *C.char) *C.char {
	goJSON := safeGoString(profileJSON)
	var p ast.ServerProfile
	if err := json.Unmarshal([]byte(goJSON), &p); err != nil {
		errResp, _ := json.Marshal(map[string]string{"error": err.Error()})
		return C.CString(string(errResp))
	}
	uri, err := parser.GenerateURI(&p)
	if err != nil {
		errResp, _ := json.Marshal(map[string]string{"error": err.Error()})
		return C.CString(string(errResp))
	}
	respBytes, _ := json.Marshal(map[string]string{"uri": uri})
	return C.CString(string(respBytes))
}

//export SentinelGenerateX25519Keys
func SentinelGenerateX25519Keys() *C.char {
	kp, err := crypto.GenerateX25519KeyPair()
	if err != nil {
		errResp, _ := json.Marshal(map[string]string{"error": err.Error()})
		return C.CString(string(errResp))
	}
	respBytes, _ := json.Marshal(kp)
	return C.CString(string(respBytes))
}

//export SentinelGenerateVlessEncKeys
func SentinelGenerateVlessEncKeys() *C.char {
	keys, err := crypto.GenerateVlessEncKeys()
	if err != nil {
		errResp, _ := json.Marshal(map[string]any{"success": false, "error": err.Error()})
		return C.CString(string(errResp))
	}
	res := map[string]any{
		"success":  true,
		"x25519":   keys.X25519,
		"mlkem768": keys.MLKEM768,
	}
	bytes, _ := json.Marshal(res)
	return C.CString(string(bytes))
}

//export SentinelGetCoresStatus
func SentinelGetCoresStatus() *C.char {
	ctrl := supervisor.GetController()
	status := ctrl.GetStatus()
	jsonBytes, _ := json.Marshal(status)
	return C.CString(string(jsonBytes))
}

//export SentinelGetUnifiedTraffic
func SentinelGetUnifiedTraffic() *C.char {
	ctrl := supervisor.GetController()
	traffic, err := ctrl.GetUnifiedTraffic()
	if err != nil {
		errResp, _ := json.Marshal(map[string]string{"error": err.Error()})
		return C.CString(string(errResp))
	}
	jsonBytes, _ := json.Marshal(traffic)
	return C.CString(string(jsonBytes))
}

//export SentinelKickClient
func SentinelKickClient(clientEmail *C.char) *C.char {
	email := safeGoString(clientEmail)
	ctrl := supervisor.GetController()
	err := ctrl.KickClient(email)
	if err != nil {
		errResp, _ := json.Marshal(map[string]string{"error": err.Error()})
		return C.CString(string(errResp))
	}
	return C.CString(`{"success": true}`)
}

//export SentinelGetCoreLogs
func SentinelGetCoreLogs(logPath *C.char, maxLines C.int) *C.char {
	path := safeGoString(logPath)
	lines, err := supervisor.ReadCoreLogs(path, int(maxLines))
	if err != nil {
		errResp, _ := json.Marshal(map[string]string{"error": err.Error()})
		return C.CString(string(errResp))
	}
	jsonBytes, _ := json.Marshal(lines)
	return C.CString(string(jsonBytes))
}

//export SentinelPing
func SentinelPing(host *C.char, port C.int, timeoutMs C.int) *C.char {
	address := safeGoString(host)
	res := diagnostics.PingHostPort(address, int(port), time.Duration(timeoutMs)*time.Millisecond)
	jsonBytes, _ := json.Marshal(res)
	return C.CString(string(jsonBytes))
}

//export SentinelEncrypt
func SentinelEncrypt(data *C.char, secret *C.char) *C.char {
	plain := safeGoString(data)
	sec := safeGoString(secret)
	v, err := crypto.NewVault(sec)
	if err != nil {
		errResp, _ := json.Marshal(map[string]string{"error": err.Error()})
		return C.CString(string(errResp))
	}
	payload, err := v.EncryptString(plain)
	if err != nil {
		errResp, _ := json.Marshal(map[string]string{"error": err.Error()})
		return C.CString(string(errResp))
	}
	res, _ := json.Marshal(map[string]string{"payload": payload})
	return C.CString(string(res))
}

//export SentinelDecrypt
func SentinelDecrypt(payload *C.char, secret *C.char) *C.char {
	cipherPayload := safeGoString(payload)
	sec := safeGoString(secret)
	v, err := crypto.NewVault(sec)
	if err != nil {
		errResp, _ := json.Marshal(map[string]string{"error": err.Error()})
		return C.CString(string(errResp))
	}
	plain, err := v.DecryptString(cipherPayload)
	if err != nil {
		errResp, _ := json.Marshal(map[string]string{"error": err.Error()})
		return C.CString(string(errResp))
	}
	res, _ := json.Marshal(map[string]string{"plaintext": plain})
	return C.CString(string(res))
}

//export SentinelListPresets
func SentinelListPresets() *C.char {
	presets := routing.GetAvailablePresets()
	jsonBytes, _ := json.Marshal(presets)
	return C.CString(string(jsonBytes))
}

//export SentinelGetPreset
func SentinelGetPreset(presetID *C.char) *C.char {
	id := safeGoString(presetID)
	pm := routing.GetPresetManager()
	p, err := pm.GetPreset(id)
	if err != nil {
		errResp, _ := json.Marshal(map[string]string{"error": err.Error()})
		return C.CString(string(errResp))
	}
	jsonBytes, _ := json.Marshal(p)
	return C.CString(string(jsonBytes))
}

//export SentinelGetConfigurationSchema
func SentinelGetConfigurationSchema(lang *C.char) *C.char {
	goLang := safeGoString(lang)
	schema := matrix.GetConfigurationSchema(goLang)
	jsonBytes, _ := json.Marshal(schema)
	return C.CString(string(jsonBytes))
}

//export SentinelEncryptPayload
func SentinelEncryptPayload(plaintext *C.char, secret *C.char) *C.char {
	goPlaintext := safeGoString(plaintext)
	goSecret := safeGoString(secret)

	vault, err := crypto.NewVault(goSecret)
	if err != nil {
		errResp, _ := json.Marshal(map[string]string{"error": err.Error()})
		return C.CString(string(errResp))
	}

	enc, err := vault.EncryptString(goPlaintext)
	if err != nil {
		errResp, _ := json.Marshal(map[string]string{"error": err.Error()})
		return C.CString(string(errResp))
	}

	return C.CString(enc)
}

//export SentinelDecryptPayload
func SentinelDecryptPayload(ciphertext *C.char, secret *C.char) *C.char {
	goCipher := safeGoString(ciphertext)
	goSecret := safeGoString(secret)

	vault, err := crypto.NewVault(goSecret)
	if err != nil {
		errResp, _ := json.Marshal(map[string]string{"error": err.Error()})
		return C.CString(string(errResp))
	}

	dec, err := vault.DecryptString(goCipher)
	if err != nil {
		errResp, _ := json.Marshal(map[string]string{"error": err.Error()})
		return C.CString(string(errResp))
	}

	return C.CString(dec)
}

//export SentinelRunHealthCheck
func SentinelRunHealthCheck(socksPort C.int, httpPort C.int, secret *C.char) *C.char {
	goSecret := safeGoString(secret)
	report := diagnostics.RunHealthCheck(int(socksPort), int(httpPort), "1.1.1.1", goSecret)
	bytes, _ := json.Marshal(report)
	return C.CString(string(bytes))
}

//export SentinelStartCore
func SentinelStartCore(core *C.char, bin *C.char, config *C.char) *C.char {
	goCore := safeGoString(core)
	goBin := safeGoString(bin)
	goConfig := safeGoString(config)
	pm := supervisor.GetProcessManager()
	if err := pm.StartCore(goCore, goBin, goConfig); err != nil {
		errResp, _ := json.Marshal(map[string]any{"success": false, "error": err.Error()})
		return C.CString(string(errResp))
	}
	return C.CString(`{"success": true}`)
}

//export SentinelStopCore
func SentinelStopCore(core *C.char) *C.char {
	goCore := safeGoString(core)
	pm := supervisor.GetProcessManager()
	if err := pm.StopCore(goCore); err != nil {
		errResp, _ := json.Marshal(map[string]any{"success": false, "error": err.Error()})
		return C.CString(string(errResp))
	}
	return C.CString(`{"success": true}`)
}

//export SentinelRestartCore
func SentinelRestartCore(core *C.char, bin *C.char, config *C.char) *C.char {
	goCore := safeGoString(core)
	goBin := safeGoString(bin)
	goConfig := safeGoString(config)
	pm := supervisor.GetProcessManager()
	if err := pm.RestartCore(goCore, goBin, goConfig); err != nil {
		errResp, _ := json.Marshal(map[string]any{"success": false, "error": err.Error()})
		return C.CString(string(errResp))
	}
	return C.CString(`{"success": true}`)
}

//export SentinelValidateCore
func SentinelValidateCore(core *C.char, bin *C.char, config *C.char) *C.char {
	goCore := safeGoString(core)
	goBin := safeGoString(bin)
	goConfig := safeGoString(config)
	pm := supervisor.GetProcessManager()
	valid, out, err := pm.ValidateCoreConfig(goCore, goBin, goConfig)
	res := map[string]any{
		"valid":  valid,
		"output": out,
	}
	if err != nil {
		res["error"] = err.Error()
	}
	bytes, _ := json.Marshal(res)
	return C.CString(string(bytes))
}

//export SentinelGetCoreVersion
func SentinelGetCoreVersion(core *C.char, bin *C.char) *C.char {
	goCore := safeGoString(core)
	goBin := safeGoString(bin)
	pm := supervisor.GetProcessManager()
	v := pm.DetectCoreVersion(goCore, goBin)
	return C.CString(v)
}

//export SentinelPopLogLine
func SentinelPopLogLine(core *C.char, timeoutMs C.int) *C.char {
	goCore := safeGoString(core)
	pm := supervisor.GetProcessManager()
	line := pm.PopLogLine(goCore, time.Duration(timeoutMs)*time.Millisecond)
	return C.CString(line)
}

//export SentinelGetInMemoryLogs
func SentinelGetInMemoryLogs(core *C.char, limit C.int) *C.char {
	goCore := safeGoString(core)
	pm := supervisor.GetProcessManager()
	lines := pm.GetInMemoryLogs(goCore, int(limit))
	bytes, _ := json.Marshal(lines)
	return C.CString(string(bytes))
}

//export SentinelClearInMemoryLogs
func SentinelClearInMemoryLogs(core *C.char) *C.char {
	goCore := safeGoString(core)
	pm := supervisor.GetProcessManager()
	pm.ClearInMemoryLogs(goCore)
	return C.CString(`{"success": true}`)
}

//export SentinelGetSecuritySchema
func SentinelGetSecuritySchema(lang *C.char) *C.char {
	goLang := safeGoString(lang)
	if goLang == "" {
		goLang = "ru"
	}
	schema := security.GenerateSecuritySchema(goLang)
	bytes, _ := json.Marshal(schema)
	return C.CString(string(bytes))
}

//export SentinelGetDefaultSecurityConfig
func SentinelGetDefaultSecurityConfig() *C.char {
	cfg := security.DefaultSecurityConfig()
	jsonStr, _ := cfg.ToJSON()
	return C.CString(jsonStr)
}

//export SentinelValidateSecurityConfig
func SentinelValidateSecurityConfig(configJSON *C.char) *C.char {
	goJSON := safeGoString(configJSON)
	_, err := security.FromJSON(goJSON)
	if err != nil {
		errResp, _ := json.Marshal(map[string]any{"valid": false, "error": err.Error()})
		return C.CString(string(errResp))
	}
	return C.CString(`{"valid": true}`)
}

//export SentinelFreeString
func SentinelFreeString(str *C.char) {
	if str != nil {
		C.free(unsafe.Pointer(str))
	}
}

func main() {}

var _ = adapter.IngestDBNode
