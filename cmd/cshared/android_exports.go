package main

/*
#include <stdlib.h>
*/
import "C"
import (
	"encoding/json"

	androidSec "github.com/blackalex1/sentinel-core/pkg/platform/android/security"
	"github.com/blackalex1/sentinel-core/pkg/security"
)

//export SentinelAndroidWritePcap
func SentinelAndroidWritePcap(filePath *C.char, rawHex *C.char, timestampMs C.longlong) *C.char {
	goPath := safeGoString(filePath)
	goHex := safeGoString(rawHex)

	var pktBytes []byte
	if goHex != "" {
		var err error
		pktBytes, err = hexDecode(goHex)
		if err != nil {
			errResp, _ := json.Marshal(map[string]any{"success": false, "error": err.Error()})
			return C.CString(string(errResp))
		}
	}

	if err := androidSec.WritePacketToPcap(goPath, pktBytes, int64(timestampMs)); err != nil {
		errResp, _ := json.Marshal(map[string]any{"success": false, "error": err.Error()})
		return C.CString(string(errResp))
	}

	return C.CString(`{"success": true}`)
}

//export SentinelAndroidSynthesizeAndWritePcap
func SentinelAndroidSynthesizeAndWritePcap(
	filePath *C.char,
	proto *C.char,
	srcIP *C.char,
	srcPort C.int,
	dstIP *C.char,
	dstPort C.int,
	tcpFlags C.int,
	seq C.uint,
	ack C.uint,
	window C.int,
	payloadHex *C.char,
	timestampMs C.longlong,
) *C.char {
	goPath := safeGoString(filePath)
	goProto := safeGoString(proto)
	goSrcIP := safeGoString(srcIP)
	goDstIP := safeGoString(dstIP)
	goPayloadHex := safeGoString(payloadHex)

	var payload []byte
	if goPayloadHex != "" {
		payload, _ = hexDecode(goPayloadHex)
	}

	pkt := androidSec.SynthesizeRawIPv4Packet(
		goProto,
		goSrcIP,
		int(srcPort),
		goDstIP,
		int(dstPort),
		byte(tcpFlags),
		uint32(seq),
		uint32(ack),
		uint16(window),
		payload,
	)

	if err := androidSec.WritePacketToPcap(goPath, pkt, int64(timestampMs)); err != nil {
		errResp, _ := json.Marshal(map[string]any{"success": false, "error": err.Error()})
		return C.CString(string(errResp))
	}

	return C.CString(`{"success": true}`)
}

//export SentinelAndroidDissectPacket
func SentinelAndroidDissectPacket(rawHex *C.char) *C.char {
	goHex := safeGoString(rawHex)
	pktBytes, err := hexDecode(goHex)
	if err != nil {
		errResp, _ := json.Marshal(map[string]any{"error": err.Error()})
		return C.CString(string(errResp))
	}

	dissected, err := androidSec.DissectPacket(pktBytes)
	if err != nil {
		errResp, _ := json.Marshal(map[string]any{"error": err.Error()})
		return C.CString(string(errResp))
	}

	respBytes, _ := json.Marshal(dissected)
	return C.CString(string(respBytes))
}

//export SentinelAndroidBlockApp
func SentinelAndroidBlockApp(pkgName *C.char) *C.char {
	goPkg := safeGoString(pkgName)
	if goPkg != "" {
		androidSec.GetDefaultEngine().BlockApp(goPkg)
		security.GetDefaultSecurityEngine().BanEntity(goPkg, security.ThreatCoreBlocked, "Quarantined by Android manager")
	}
	return C.CString(`{"success": true}`)
}

//export SentinelAndroidUnblockApp
func SentinelAndroidUnblockApp(pkgName *C.char) *C.char {
	goPkg := safeGoString(pkgName)
	if goPkg != "" {
		androidSec.GetDefaultEngine().UnblockApp(goPkg)
		security.GetDefaultSecurityEngine().UnblockEntity(goPkg)
	}
	return C.CString(`{"success": true}`)
}

//export SentinelAndroidIsAppBlocked
func SentinelAndroidIsAppBlocked(pkgName *C.char) *C.char {
	goPkg := safeGoString(pkgName)
	blocked := false
	if goPkg != "" {
		blocked = androidSec.GetDefaultEngine().IsAppBlocked(goPkg) || security.GetDefaultSecurityEngine().IsEntityBlocked(goPkg)
	}
	resp, _ := json.Marshal(map[string]bool{"blocked": blocked})
	return C.CString(string(resp))
}

//export SentinelAndroidGetBlockedApps
func SentinelAndroidGetBlockedApps() *C.char {
	apps := androidSec.GetDefaultEngine().GetBlockedApps()
	resp, _ := json.Marshal(map[string]any{
		"blocked_apps":         apps,
		"blocked_destinations": androidSec.GetDefaultEngine().GetBlockedDestinations(),
		"blocked_ports":        androidSec.GetDefaultEngine().GetBlockedPorts(),
	})
	return C.CString(string(resp))
}

//export SentinelAndroidClearThreats
func SentinelAndroidClearThreats() *C.char {
	androidSec.GetDefaultEngine().ClearAll()
	security.GetDefaultSecurityEngine().UnblockAllEntities()
	return C.CString(`{"success": true}`)
}

//export SentinelAndroidPushLog
func SentinelAndroidPushLog(logJSON *C.char) *C.char {
	goJSON := safeGoString(logJSON)
	var entry androidSec.AndroidLogEntry
	if err := json.Unmarshal([]byte(goJSON), &entry); err != nil {
		errResp, _ := json.Marshal(map[string]string{"error": err.Error()})
		return C.CString(string(errResp))
	}
	androidSec.GetGlobalLogBuffer().Push(entry)
	return C.CString(`{"success": true}`)
}

//export SentinelAndroidGetLogs
func SentinelAndroidGetLogs(limit C.int, offset C.int, portFilter C.int, query *C.char) *C.char {
	q := safeGoString(query)
	logs := androidSec.GetGlobalLogBuffer().GetLogs(int(limit), int(offset), int(portFilter), q)
	respBytes, _ := json.Marshal(logs)
	return C.CString(string(respBytes))
}

//export SentinelAndroidGetLogStats
func SentinelAndroidGetLogStats() *C.char {
	stats := androidSec.GetGlobalLogBuffer().GetStats()
	respBytes, _ := json.Marshal(stats)
	return C.CString(string(respBytes))
}

//export SentinelAndroidClearLogs
func SentinelAndroidClearLogs() *C.char {
	androidSec.GetGlobalLogBuffer().Clear()
	return C.CString(`{"success": true}`)
}
