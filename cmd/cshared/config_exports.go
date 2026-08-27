package main

/*
#include <stdlib.h>
*/
import "C"
import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/blackalex1/sentinel-core/pkg/ast"
	"github.com/blackalex1/sentinel-core/pkg/builder"
	"github.com/blackalex1/sentinel-core/pkg/diagnostics"
	"github.com/blackalex1/sentinel-core/pkg/i18n"
	"github.com/blackalex1/sentinel-core/pkg/parser"
)

//export SentinelSetLanguage
func SentinelSetLanguage(lang *C.char) *C.char {
	goLang := safeGoString(lang)
	i18n.SetLocale(i18n.Locale(strings.ToLower(strings.TrimSpace(goLang))))
	return C.CString(`{"success": true}`)
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

//export SentinelParseSubscription
func SentinelParseSubscription(subscriptionContent *C.char) *C.char {
	goContent := safeGoString(subscriptionContent)
	profiles, err := parser.ParseSubscription(goContent)
	if err != nil {
		errResp, _ := json.Marshal(map[string]string{"error": err.Error()})
		return C.CString(string(errResp))
	}

	jsonBytes, _ := json.Marshal(profiles)
	return C.CString(string(jsonBytes))
}

//export SentinelBatchCheckProxies
func SentinelBatchCheckProxies(proxiesJSON *C.char, targetHost *C.char, targetPort C.int, useTLS C.int, timeoutMs C.int, concurrency C.int) *C.char {
	goProxiesJSON := safeGoString(proxiesJSON)
	var proxies []string
	if err := json.Unmarshal([]byte(goProxiesJSON), &proxies); err != nil {
		// Fallback: split lines if it's plain text list
		for _, line := range strings.Split(goProxiesJSON, "\n") {
			l := strings.TrimSpace(line)
			if l != "" && !strings.HasPrefix(l, "#") {
				proxies = append(proxies, l)
			}
		}
	}

	host := safeGoString(targetHost)
	tOut := time.Duration(timeoutMs) * time.Millisecond
	if tOut <= 0 {
		tOut = 3500 * time.Millisecond
	}

	results := diagnostics.BatchCheckProxies(proxies, host, int(targetPort), useTLS != 0, tOut, int(concurrency))
	jsonBytes, _ := json.Marshal(results)
	return C.CString(string(jsonBytes))
}

//export SentinelFindFastestProxy
func SentinelFindFastestProxy(proxiesJSON *C.char, targetHost *C.char, targetPort C.int, useTLS C.int, timeoutMs C.int, concurrency C.int) *C.char {
	goProxiesJSON := safeGoString(proxiesJSON)
	var proxies []string
	if err := json.Unmarshal([]byte(goProxiesJSON), &proxies); err != nil {
		for _, line := range strings.Split(goProxiesJSON, "\n") {
			l := strings.TrimSpace(line)
			if l != "" && !strings.HasPrefix(l, "#") {
				proxies = append(proxies, l)
			}
		}
	}

	host := safeGoString(targetHost)
	tOut := time.Duration(timeoutMs) * time.Millisecond
	if tOut <= 0 {
		tOut = 3500 * time.Millisecond
	}

	best := diagnostics.FindFastestWorkingProxy(proxies, host, int(targetPort), useTLS != 0, tOut, int(concurrency))
	if best == nil {
		return C.CString("null")
	}

	jsonBytes, _ := json.Marshal(best)
	return C.CString(string(jsonBytes))
}

//export SentinelBuildFailoverClientConfig
func SentinelBuildFailoverClientConfig(profilesJSON *C.char, targetCoreStr *C.char, socksPort C.int, httpPort C.int, healthCheckURL *C.char) *C.char {
	goProfilesJSON := safeGoString(profilesJSON)
	var profiles []*ast.ServerProfile
	if err := json.Unmarshal([]byte(goProfilesJSON), &profiles); err != nil {
		errResp, _ := json.Marshal(map[string]string{"error": fmt.Sprintf("invalid profiles JSON: %v", err)})
		return C.CString(string(errResp))
	}

	coreName := ast.TargetCore(safeGoString(targetCoreStr))
	if coreName == "" {
		coreName = ast.CoreSingBox
	}
	hURL := safeGoString(healthCheckURL)

	res, err := builder.BuildFailoverClientConfig(profiles, coreName, int(socksPort), int(httpPort), hURL)
	if err != nil {
		errResp, _ := json.Marshal(map[string]string{"error": err.Error()})
		return C.CString(string(errResp))
	}

	respBytes, _ := json.Marshal(res)
	return C.CString(string(respBytes))
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
