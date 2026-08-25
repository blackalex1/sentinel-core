package main

/*
#include <stdlib.h>
*/
import "C"
import (
	"encoding/json"

	"github.com/blackalex1/sentinel-core/pkg/supervisor"
)

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

//export SentinelGetRealtimeTraffic
func SentinelGetRealtimeTraffic(clashAddr *C.char) *C.char {
	addr := safeGoString(clashAddr)
	ctrl := supervisor.GetController()
	stats := ctrl.GetRealtimeTraffic(addr)
	jsonBytes, _ := json.Marshal(stats)
	return C.CString(string(jsonBytes))
}

//export SentinelResetRealtimeTraffic
func SentinelResetRealtimeTraffic() *C.char {
	supervisor.ResetRealtimeTraffic()
	return C.CString(`{"success": true}`)
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
