package main

/*
#include <stdlib.h>
*/
import "C"
import (
	"encoding/json"

	"github.com/blackalex1/sentinel-core/pkg/matrix"
	"github.com/blackalex1/sentinel-core/pkg/routing"
)

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

//export SentinelOptimizeRules
func SentinelOptimizeRules(rulesJSON *C.char) *C.char {
	goJSON := safeGoString(rulesJSON)
	var rules []routing.RoutingRuleRow
	if err := json.Unmarshal([]byte(goJSON), &rules); err != nil {
		errResp, _ := json.Marshal(map[string]string{"error": err.Error()})
		return C.CString(string(errResp))
	}
	opt := routing.OptimizeRules(rules)
	respBytes, _ := json.Marshal(opt)
	return C.CString(string(respBytes))
}
