//go:build !windows

package integrity

import (
	"syscall"
	"unsafe"
)

func isWritableMemory(ptr uintptr) bool {
	if ptr == 0 {
		return false
	}
	var p [2]int
	if err := syscall.Pipe(p[:]); err != nil {
		return false
	}
	defer syscall.Close(p[0])
	defer syscall.Close(p[1])

	if _, err := syscall.Write(p[1], []byte{0}); err != nil {
		return false
	}

	b := unsafe.Slice((*byte)(unsafe.Pointer(ptr)), 1)
	_, err := syscall.Read(p[0], b)
	return err == nil
}
