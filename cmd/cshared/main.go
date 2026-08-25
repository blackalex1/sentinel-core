package main

/*
#include <stdlib.h>
*/
import "C"
import (
	"encoding/hex"
	"strings"
	"unsafe"

	"github.com/blackalex1/sentinel-core/pkg/adapter"
)

var Version = "dev"

func safeGoString(s *C.char) string {
	if s == nil {
		return ""
	}
	return C.GoString(s)
}

func hexDecode(s string) ([]byte, error) {
	s = strings.TrimPrefix(s, "0x")
	s = strings.ReplaceAll(s, " ", "")
	return hex.DecodeString(s)
}

//export SentinelGetEngineVersion
func SentinelGetEngineVersion() *C.char {
	return C.CString(Version)
}

//export SentinelFreeString
func SentinelFreeString(str *C.char) {
	if str != nil {
		C.free(unsafe.Pointer(str))
	}
}

func main() {}

var _ = adapter.IngestDBNode
