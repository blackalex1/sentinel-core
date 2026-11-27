package integrity

import (
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

// ZeroizeString securely resets a string pointer and safely attempts to zeroize writable heap-allocated bytes.
// If the string backing data is located in read-only memory (.rodata), it bypasses in-place wiping and resets the pointer safely.
func ZeroizeString(s *string) {
	if s == nil || len(*s) == 0 {
		return
	}

	defer func() {
		_ = recover()
		*s = ""
		runtime.KeepAlive(s)
	}()

	length := len(*s)
	// nosemgrep: go.lang.security.audit.unsafe.use-of-unsafe-block
	// SAFETY: len(*s) > 0 is checked at entry, so bytePtr points to the valid backing array of *s for length bytes.
	bytePtr := unsafe.StringData(*s)

	// nosemgrep: go.lang.security.audit.unsafe.use-of-unsafe-block
	// SAFETY: bytePtr != nil and length > 0; isWritableMemory probes the address via a kernel pipe read without faulting on .rodata.
	if bytePtr != nil && length > 0 && isWritableMemory(unsafe.Pointer(bytePtr)) {
		for i := 0; i < length; i++ {
			// nosemgrep: go.lang.security.audit.unsafe.use-of-unsafe-block
			// SAFETY: i is bounded by [0, length), within the verified writable backing buffer of *s kept alive by runtime.KeepAlive(s).
			*(*byte)(unsafe.Add(unsafe.Pointer(bytePtr), i)) = 0
		}
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
