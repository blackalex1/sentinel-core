package main

/*
#include <stdlib.h>
*/
import "C"
import (
	"encoding/json"

	"github.com/blackalex1/sentinel-core/pkg/supervisor"
)

//export SentinelGetActiveSessions
func SentinelGetActiveSessions() *C.char {
	jsonStr := supervisor.GetSessionTracker().GetActiveSessionsJSON()
	return C.CString(jsonStr)
}

//export SentinelGetOnlineEmails
func SentinelGetOnlineEmails() *C.char {
	emails := supervisor.GetSessionTracker().GetOnlineEmails()
	bytes, _ := json.Marshal(emails)
	return C.CString(string(bytes))
}

//export SentinelGetRecentSessionEvents
func SentinelGetRecentSessionEvents(sinceTimestamp C.longlong, limit C.int) *C.char {
	jsonStr := supervisor.GetSessionTracker().GetRecentEventsJSON(int64(sinceTimestamp), int(limit))
	return C.CString(jsonStr)
}

//export SentinelRegisterExternalConnect
func SentinelRegisterExternalConnect(core *C.char, email *C.char, ip *C.char) *C.char {
	goCore := safeGoString(core)
	goEmail := safeGoString(email)
	goIP := safeGoString(ip)
	supervisor.GetSessionTracker().RegisterExternalConnect(goCore, goEmail, goIP)
	return C.CString(`{"success": true}`)
}
