package integrity

import (
	"reflect"
	"runtime"
	"unsafe"
)

// ZeroizeBytes securely overwrites a byte slice with zeros to prevent secret leakage in heap/dumps.
func ZeroizeBytes(b []byte) {
	if len(b) == 0 {
		return
	}
	for i := range b {
		b[i] = 0
	}
	// Memory barrier / prevent compiler optimization elimination
	runtime.KeepAlive(b)
}

// ZeroizeString securely wipes the underlying memory buffer of an ASCII/UTF-8 string.
func ZeroizeString(s *string) {
	if s == nil || len(*s) == 0 {
		return
	}

	// Use unsafe pointer to overwrite the string's backing memory
	strHeader := (*reflect.StringHeader)(unsafe.Pointer(s))
	ptr := (*byte)(unsafe.Pointer(strHeader.Data))
	length := strHeader.Len

	for i := 0; i < length; i++ {
		*(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(ptr)) + uintptr(i))) = 0
	}

	*s = ""
	runtime.KeepAlive(s)
}

// ZeroizeSliceOfBytes zeroes each byte slice in the provided list.
func ZeroizeSliceOfBytes(slices ...[]byte) {
	for _, s := range slices {
		ZeroizeBytes(s)
	}
}
