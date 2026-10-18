//go:build windows

package integrity

import (
	"syscall"
	"unsafe"
)

var (
	kernel32         = syscall.NewLazyDLL("kernel32.dll")
	procVirtualQuery = kernel32.NewProc("VirtualQuery")
)

type memoryBasicInformation struct {
	BaseAddress       uintptr
	AllocationBase    uintptr
	AllocationProtect uint32
	PartitionId       uint16
	RegionSize        uintptr
	State             uint32
	Protect           uint32
	Type              uint32
}

const (
	pageReadWrite        = 0x04
	pageWriteCopy        = 0x08
	pageExecuteReadWrite = 0x40
	pageExecuteWriteCopy = 0x80
)

func isWritableMemory(ptr uintptr) bool {
	if ptr == 0 {
		return false
	}
	var mbi memoryBasicInformation
	ret, _, _ := procVirtualQuery.Call(
		ptr,
		uintptr(unsafe.Pointer(&mbi)),
		unsafe.Sizeof(mbi),
	)
	if ret == 0 {
		return false
	}
	writableFlags := uint32(pageReadWrite | pageWriteCopy | pageExecuteReadWrite | pageExecuteWriteCopy)
	return (mbi.Protect & writableFlags) != 0
}
