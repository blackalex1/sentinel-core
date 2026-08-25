package main

/*
#include <stdlib.h>
*/
import "C"
import (
	"encoding/json"

	"github.com/blackalex1/sentinel-core/pkg/security"
	"github.com/blackalex1/sentinel-core/pkg/security/detector"
	"github.com/blackalex1/sentinel-core/pkg/security/netfilter"
	"github.com/blackalex1/sentinel-core/pkg/security/ssh"
)

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

//export SentinelAuditConnection
func SentinelAuditConnection(reqJSON *C.char) *C.char {
	goJSON := safeGoString(reqJSON)
	var req security.SecurityAuditRequest
	if err := json.Unmarshal([]byte(goJSON), &req); err != nil {
		errResp, _ := json.Marshal(map[string]any{"error": err.Error()})
		return C.CString(string(errResp))
	}

	engine := security.GetDefaultSecurityEngine()
	verdict := engine.AuditConnection(req)
	respBytes, _ := json.Marshal(verdict)
	return C.CString(string(respBytes))
}

//export SentinelGetPortShieldCatalog
func SentinelGetPortShieldCatalog(lang *C.char) *C.char {
	goLang := safeGoString(lang)
	if goLang == "" {
		goLang = "ru"
	}
	catalog := security.GetPortShieldCatalog(goLang)
	respBytes, _ := json.Marshal(catalog)
	return C.CString(string(respBytes))
}

//export SentinelConfigureSecurityPolicy
func SentinelConfigureSecurityPolicy(policyJSON *C.char) *C.char {
	goJSON := safeGoString(policyJSON)
	var policy security.SecurityPolicyConfig
	if err := json.Unmarshal([]byte(goJSON), &policy); err != nil {
		errResp, _ := json.Marshal(map[string]any{"success": false, "error": err.Error()})
		return C.CString(string(errResp))
	}

	engine := security.GetDefaultSecurityEngine()
	engine.ConfigurePolicy(policy)
	return C.CString(`{"success": true}`)
}

//export SentinelGetSecurityPolicy
func SentinelGetSecurityPolicy() *C.char {
	engine := security.GetDefaultSecurityEngine()
	policy := engine.GetPolicy()
	respBytes, _ := json.Marshal(policy)
	return C.CString(string(respBytes))
}

//export SentinelIngestCoreLog
func SentinelIngestCoreLog(logLine *C.char) *C.char {
	goLine := safeGoString(logLine)
	engine := security.GetDefaultSecurityEngine()
	verdict := engine.IngestCoreLog(goLine)
	if verdict == nil {
		return C.CString("")
	}
	respBytes, _ := json.Marshal(verdict)
	return C.CString(string(respBytes))
}

//export SentinelGetBlockedApps
func SentinelGetBlockedApps() *C.char {
	engine := security.GetDefaultSecurityEngine()
	apps := engine.GetBlockedEntities()
	respBytes, _ := json.Marshal(apps)
	return C.CString(string(respBytes))
}

//export SentinelUnblockApp
func SentinelUnblockApp(callerID *C.char) *C.char {
	id := safeGoString(callerID)
	engine := security.GetDefaultSecurityEngine()
	if id != "" {
		engine.UnblockEntity(id)
	}
	return C.CString(`{"success": true}`)
}

//export SentinelUnblockAllApps
func SentinelUnblockAllApps() *C.char {
	engine := security.GetDefaultSecurityEngine()
	engine.UnblockAllEntities()
	return C.CString(`{"success": true}`)
}

//export SentinelGetPcapStatus
func SentinelGetPcapStatus() *C.char {
	engine := security.GetDefaultSecurityEngine()
	status := engine.GetPcapStatus()
	respBytes, _ := json.Marshal(status)
	return C.CString(string(respBytes))
}

//export SentinelStopPcapCapture
func SentinelStopPcapCapture() *C.char {
	engine := security.GetDefaultSecurityEngine()
	engine.StopPcapSession()
	return C.CString(`{"success": true}`)
}

//export SentinelParseIptablesLine
func SentinelParseIptablesLine(line *C.char, vpnVMID C.int) *C.char {
	goLine := safeGoString(line)
	ev := netfilter.ParseIptablesLine(goLine, int(vpnVMID))
	if ev == nil {
		return C.CString("")
	}
	respBytes, _ := json.Marshal(ev)
	return C.CString(string(respBytes))
}

//export SentinelClassifyConnection
func SentinelClassifyConnection(eventJSON *C.char, policyJSON *C.char, lang *C.char) *C.char {
	goEvJSON := safeGoString(eventJSON)
	goPolJSON := safeGoString(policyJSON)
	goLang := safeGoString(lang)

	var ev netfilter.IptablesEvent
	if err := json.Unmarshal([]byte(goEvJSON), &ev); err != nil {
		errResp, _ := json.Marshal(map[string]string{"error": err.Error()})
		return C.CString(string(errResp))
	}

	policy := netfilter.DefaultClassifierPolicy()
	if goPolJSON != "" {
		_ = json.Unmarshal([]byte(goPolJSON), &policy)
	}

	res := netfilter.ClassifyConnection(ev, policy, goLang)
	respBytes, _ := json.Marshal(res)
	return C.CString(string(respBytes))
}

//export SentinelFindRealVPNClientIP
func SentinelFindRealVPNClientIP(proto *C.char, containerIP *C.char, dstIP *C.char, sport C.int, dpt C.int, conntrackDump *C.char) *C.char {
	goProto := safeGoString(proto)
	goContIP := safeGoString(containerIP)
	goDstIP := safeGoString(dstIP)
	goDump := safeGoString(conntrackDump)

	clientIP := netfilter.FindRealVPNClientIP(goProto, goContIP, goDstIP, int(sport), int(dpt), goDump)
	return C.CString(clientIP)
}

//export SentinelFindXrayClientEmail
func SentinelFindXrayClientEmail(linesJSON *C.char, clientIP *C.char, dstIP *C.char, dstPort C.int, maxAgeSec C.int) *C.char {
	goLinesJSON := safeGoString(linesJSON)
	goClientIP := safeGoString(clientIP)
	goDstIP := safeGoString(dstIP)

	var lines []string
	if err := json.Unmarshal([]byte(goLinesJSON), &lines); err != nil {
		errResp, _ := json.Marshal(map[string]string{"error": err.Error()})
		return C.CString(string(errResp))
	}

	email, ip, tag := detector.FindEmailAndIPInXrayLog(lines, goClientIP, goDstIP, int(dstPort), int(maxAgeSec))
	res := map[string]string{
		"email":       email,
		"ip":          ip,
		"inbound_tag": tag,
	}
	respBytes, _ := json.Marshal(res)
	return C.CString(string(respBytes))
}

//export SentinelFindHysteriaClientEmail
func SentinelFindHysteriaClientEmail(linesJSON *C.char, dstIP *C.char, dstPort C.int, maxAgeSec C.int) *C.char {
	goLinesJSON := safeGoString(linesJSON)
	goDstIP := safeGoString(dstIP)

	var lines []string
	if err := json.Unmarshal([]byte(goLinesJSON), &lines); err != nil {
		return C.CString("")
	}

	email := detector.FindEmailInHysteriaLog(lines, goDstIP, int(dstPort), int(maxAgeSec))
	return C.CString(email)
}

//export SentinelFindClientIPForEmail
func SentinelFindClientIPForEmail(linesJSON *C.char, email *C.char, maxAgeSec C.int) *C.char {
	goLinesJSON := safeGoString(linesJSON)
	goEmail := safeGoString(email)

	var lines []string
	if err := json.Unmarshal([]byte(goLinesJSON), &lines); err != nil {
		return C.CString("")
	}

	ip := detector.FindClientIPForEmailInHysteriaLog(lines, goEmail, int(maxAgeSec))
	return C.CString(ip)
}

//export SentinelParseAuthLogLine
func SentinelParseAuthLogLine(line *C.char) *C.char {
	goLine := safeGoString(line)
	ev, ok := ssh.ParseAuthLine(goLine)
	if !ok || ev == nil {
		return C.CString("")
	}
	respBytes, _ := json.Marshal(ev)
	return C.CString(string(respBytes))
}

//export SentinelParseRouterConntrackLine
func SentinelParseRouterConntrackLine(line *C.char) *C.char {
	goLine := safeGoString(line)
	ev := netfilter.ParseRouterConntrackLine(goLine)
	if ev == nil {
		return C.CString("")
	}
	respBytes, _ := json.Marshal(ev)
	return C.CString(string(respBytes))
}

//export SentinelParseRouterIptablesLine
func SentinelParseRouterIptablesLine(line *C.char) *C.char {
	goLine := safeGoString(line)
	ev := netfilter.ParseRouterIptablesLine(goLine)
	if ev == nil {
		return C.CString("")
	}
	respBytes, _ := json.Marshal(ev)
	return C.CString(string(respBytes))
}
