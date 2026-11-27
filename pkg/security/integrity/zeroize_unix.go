//go:build !windows

package integrity

import (
	"syscall"
	"unsafe"
)

func isWritableMemory(ptr unsafe.Pointer) bool {
	if ptr == nil {
		return false
	}
	var p [2]int
	if err := syscall.Pipe(p[:]); err != nil {
		return false
	}
	defer func() {
		_ = syscall.Close(p[0])
		_ = syscall.Close(p[1])
	}()

	if _, err := syscall.Write(p[1], []byte{0}); err != nil {
		return false
	}

	// nosemgrep: go.lang.security.audit.unsafe.use-of-unsafe-block
	// SAFETY: ptr is non-nil (checked at entry) and points to at least 1 byte of the target string; syscall.Read probes kernel writability safely via EFAULT.
	b := unsafe.Slice((*byte)(ptr), 1)
	_, err := syscall.Read(p[0], b)
	return err == nil
}
