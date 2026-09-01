package main

/*
#include <stdlib.h>
*/
import "C"
import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/blackalex1/sentinel-core/pkg/security"
	"github.com/blackalex1/sentinel-core/pkg/security/detector"
	"github.com/blackalex1/sentinel-core/pkg/security/ingest"
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

//export SentinelStartSecurityPipeline
func SentinelStartSecurityPipeline(configJSON *C.char) *C.char {
	goCfgJSON := safeGoString(configJSON)
	cfg := ingest.DefaultPipelineConfig()
	if goCfgJSON != "" {
		_ = json.Unmarshal([]byte(goCfgJSON), &cfg)
	}

	pipeline := ingest.GetDefaultSecurityPipeline()
	pipeline.Configure(cfg)
	_ = pipeline.Start(context.Background())
	return C.CString(`{"success": true}`)
}

//export SentinelPollSecurityEvent
func SentinelPollSecurityEvent(timeoutMs C.int) *C.char {
	timeout := time.Duration(int(timeoutMs)) * time.Millisecond
	dispatcher := ingest.GetDefaultEventDispatcher()
	jsonStr := dispatcher.PopEventJSON(timeout)
	return C.CString(jsonStr)
}

//export SentinelStopSecurityPipeline
func SentinelStopSecurityPipeline() *C.char {
	pipeline := ingest.GetDefaultSecurityPipeline()
	pipeline.Stop()
	return C.CString(`{"success": true}`)
}

//export SentinelProcessTrafficLine
func SentinelProcessTrafficLine(source *C.char, line *C.char) *C.char {
	goSource := safeGoString(source)
	goLine := safeGoString(line)
	pipeline := ingest.GetDefaultSecurityPipeline()

	var ev *ingest.SecurityEvent
	switch goSource {
	case "proxmox_iptables":
		ev = pipeline.ProcessProxmoxIptablesLine(goLine)
	case "router_conntrack":
		ev = pipeline.ProcessRouterConntrackLine(goLine)
	case "router_syslog":
		ev = pipeline.ProcessRouterIptablesLine(goLine)
	case "auth_ssh":
		ev = pipeline.ProcessAuthLogLine(goLine)
	default:
		if strings.HasPrefix(goSource, "core:") {
			coreName := strings.TrimPrefix(goSource, "core:")
			pipeline.ProcessProxyCoreLine(coreName, goLine)
			return C.CString(`{"processed": true}`)
		}
	}

	if ev == nil {
		return C.CString("")
	}
	respBytes, _ := json.Marshal(ev)
	return C.CString(string(respBytes))
}

//export SentinelConfigureRouterThreatDetector
func SentinelConfigureRouterThreatDetector(configJSON *C.char) *C.char {
	goJSON := safeGoString(configJSON)
	if strings.TrimSpace(goJSON) == "" {
		return C.CString(`{"success": true}`)
	}

	type routerDetectorConfig struct {
		ScanLimit        int   `json:"scan_limit"`
		BurstLimit1m     int   `json:"burst_limit_1m"`
		BurstLimit3m     int   `json:"burst_limit_3m"`
		TargetBruteLimit int   `json:"target_brute_limit"`
		WindowMinutes    int   `json:"window_minutes"`
		SensitivePorts   []int `json:"sensitive_ports"`
	}

	var cfg routerDetectorConfig
	if err := json.Unmarshal([]byte(goJSON), &cfg); err != nil {
		errResp, _ := json.Marshal(map[string]any{"success": false, "error": err.Error()})
		return C.CString(string(errResp))
	}

	var win time.Duration
	if cfg.WindowMinutes > 0 {
		win = time.Duration(cfg.WindowMinutes) * time.Minute
	}

	detector := netfilter.GetDefaultRouterThreatDetector()
	detector.Configure(cfg.ScanLimit, cfg.BurstLimit1m, cfg.BurstLimit3m, cfg.TargetBruteLimit, win, cfg.SensitivePorts)
	if len(cfg.SensitivePorts) > 0 {
		detector.SetSensitivePorts(cfg.SensitivePorts)
	}

	return C.CString(`{"success": true}`)
}


