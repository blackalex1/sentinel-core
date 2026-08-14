package main

/*
#include <stdlib.h>
*/
import "C"
import (
	"encoding/json"
	"unsafe"
	"github.com/blackalex1/sentinel-core/pkg/adapter"
	"github.com/blackalex1/sentinel-core/pkg/ast"
	"github.com/blackalex1/sentinel-core/pkg/builder"
	"github.com/blackalex1/sentinel-core/pkg/crypto"
	"github.com/blackalex1/sentinel-core/pkg/diagnostics"
	"github.com/blackalex1/sentinel-core/pkg/matrix"
	"github.com/blackalex1/sentinel-core/pkg/parser"
	"github.com/blackalex1/sentinel-core/pkg/routing"
)

//export SentinelBuildConfig
func SentinelBuildConfig(specJSON *C.char) *C.char {
	goSpecJSON := C.GoString(specJSON)

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
	goSpecJSON := C.GoString(specJSON)

	var spec ast.ConfigSpec
	if err := json.Unmarshal([]byte(goSpecJSON), &spec); err != nil {
		errResp, _ := json.Marshal(map[string]string{"error": err.Error()})
		return C.CString(string(errResp))
	}

	cfg, err := builder.BuildServerConfig(spec.TargetCore, spec.ServerInbounds, spec.Routing, spec.ClashAPIAddress)
	if err != nil {
		errResp, _ := json.Marshal(map[string]string{"error": err.Error()})
		return C.CString(string(errResp))
	}

	respBytes, _ := json.Marshal(map[string]string{"config": cfg})
	return C.CString(string(respBytes))
}

//export SentinelParseURI
func SentinelParseURI(rawURI *C.char) *C.char {
	goURI := C.GoString(rawURI)
	profile, err := parser.ParseURI(goURI)
	if err != nil {
		errResp, _ := json.Marshal(map[string]string{"error": err.Error()})
		return C.CString(string(errResp))
	}

	jsonBytes, _ := json.Marshal(profile)
	return C.CString(string(jsonBytes))
}

//export SentinelListPresets
func SentinelListPresets() *C.char {
	presets := routing.GetAvailablePresets()
	jsonBytes, _ := json.Marshal(presets)
	return C.CString(string(jsonBytes))
}

//export SentinelGetPreset
func SentinelGetPreset(presetID *C.char) *C.char {
	id := C.GoString(presetID)
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
	goLang := ""
	if lang != nil {
		goLang = C.GoString(lang)
	}
	schema := matrix.GetConfigurationSchema(goLang)
	jsonBytes, _ := json.Marshal(schema)
	return C.CString(string(jsonBytes))
}

//export SentinelEncryptPayload
func SentinelEncryptPayload(plaintext *C.char, secret *C.char) *C.char {
	goPlaintext := C.GoString(plaintext)
	goSecret := C.GoString(secret)

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
	goCipher := C.GoString(ciphertext)
	goSecret := C.GoString(secret)

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
	goSecret := C.GoString(secret)
	report := diagnostics.RunHealthCheck(int(socksPort), int(httpPort), "1.1.1.1", goSecret)
	bytes, _ := json.Marshal(report)
	return C.CString(string(bytes))
}

//export SentinelFreeString
func SentinelFreeString(str *C.char) {
	C.free(unsafe.Pointer(str))
}

func main() {}

var _ = adapter.IngestDBNode
