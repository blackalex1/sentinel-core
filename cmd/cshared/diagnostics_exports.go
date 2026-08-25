package main

/*
#include <stdlib.h>
*/
import "C"
import (
	"encoding/json"
	"time"

	"github.com/blackalex1/sentinel-core/pkg/diagnostics"
)

//export SentinelPing
func SentinelPing(host *C.char, port C.int, timeoutMs C.int) *C.char {
	address := safeGoString(host)
	res := diagnostics.PingHostPort(address, int(port), time.Duration(timeoutMs)*time.Millisecond)
	jsonBytes, _ := json.Marshal(res)
	return C.CString(string(jsonBytes))
}

//export SentinelRunHealthCheck
func SentinelRunHealthCheck(socksPort C.int, httpPort C.int, secret *C.char) *C.char {
	goSecret := safeGoString(secret)
	report := diagnostics.RunHealthCheck(int(socksPort), int(httpPort), "1.1.1.1", goSecret)
	bytes, _ := json.Marshal(report)
	return C.CString(string(bytes))
}

//export SentinelBatchPing
func SentinelBatchPing(targetsJSON *C.char, timeoutMs C.int) *C.char {
	goJSON := safeGoString(targetsJSON)
	var targets []diagnostics.PingTarget
	if err := json.Unmarshal([]byte(goJSON), &targets); err != nil {
		errResp, _ := json.Marshal(map[string]string{"error": err.Error()})
		return C.CString(string(errResp))
	}
	timeout := time.Duration(timeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = 2500 * time.Millisecond
	}
	res := diagnostics.BatchPing(targets, timeout, 16)
	respBytes, _ := json.Marshal(res)
	return C.CString(string(respBytes))
}

//export SentinelProxyPing
func SentinelProxyPing(socksPort C.int, authUser *C.char, authPass *C.char, targetURL *C.char, timeoutMs C.int) *C.char {
	port := int(socksPort)
	user := safeGoString(authUser)
	pass := safeGoString(authPass)
	urlStr := safeGoString(targetURL)
	timeout := time.Duration(timeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = 3000 * time.Millisecond
	}
	res := diagnostics.PingThroughProxy(port, user, pass, urlStr, timeout)
	respBytes, _ := json.Marshal(res)
	return C.CString(string(respBytes))
}

//export SentinelGetPublicIP
func SentinelGetPublicIP(socksPort C.int, authUser *C.char, authPass *C.char, timeoutMs C.int) *C.char {
	port := int(socksPort)
	user := safeGoString(authUser)
	pass := safeGoString(authPass)
	timeout := time.Duration(timeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = 3500 * time.Millisecond
	}
	info, err := diagnostics.GetPublicIP(port, user, pass, timeout)
	if err != nil {
		errResp, _ := json.Marshal(map[string]string{"error": err.Error()})
		return C.CString(string(errResp))
	}
	respBytes, _ := json.Marshal(info)
	return C.CString(string(respBytes))
}
