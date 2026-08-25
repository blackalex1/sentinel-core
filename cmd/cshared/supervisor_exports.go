package main

/*
#include <stdlib.h>
*/
import "C"
import (
	"encoding/json"
	"time"

	"github.com/blackalex1/sentinel-core/pkg/supervisor"
)

//export SentinelGetCoresStatus
func SentinelGetCoresStatus() *C.char {
	ctrl := supervisor.GetController()
	status := ctrl.GetStatus()
	jsonBytes, _ := json.Marshal(status)
	return C.CString(string(jsonBytes))
}

//export SentinelRegisterHysteriaPort
func SentinelRegisterHysteriaPort(port C.int) *C.char {
	p := int(port)
	if p > 0 {
		supervisor.GetController().RegisterHysteriaPort(p)
	}
	return C.CString(`{"success": true}`)
}

//export SentinelConfigureSupervisor
func SentinelConfigureSupervisor(configJSON *C.char) *C.char {
	raw := safeGoString(configJSON)
	var cfg struct {
		ClashAddr     string            `json:"clashAddr"`
		HysteriaPorts []int             `json:"hysteriaPorts"`
		LogPaths      map[string]string `json:"logPaths"`
	}
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		errResp, _ := json.Marshal(map[string]string{"error": err.Error()})
		return C.CString(string(errResp))
	}
	supervisor.GetController().Configure(cfg.ClashAddr, cfg.HysteriaPorts, cfg.LogPaths)
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

//export SentinelPushLogLine
func SentinelPushLogLine(core *C.char, line *C.char) *C.char {
	goCore := safeGoString(core)
	l := safeGoString(line)
	supervisor.GetLogBroadcaster().PushLine(goCore, l)
	return C.CString(`{"success": true}`)
}
