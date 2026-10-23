//go:build windows

package main

import (
	"syscall"
	"unsafe"
)

// PROCESS_MEMORY_COUNTERS_EX uses pointer-sized SIZE_T counters. The peak
// working set is the resident process high-water mark, not Go heap allocation.
type memoryCounters struct {
	Size                       uint32
	PageFaultCount             uint32
	PeakWorkingSetSize         uintptr
	WorkingSetSize             uintptr
	QuotaPeakPagedPoolUsage    uintptr
	QuotaPagedPoolUsage        uintptr
	QuotaPeakNonPagedPoolUsage uintptr
	QuotaNonPagedPoolUsage     uintptr
	PagefileUsage              uintptr
	PeakPagefileUsage          uintptr
	PrivateUsage               uintptr
}

func peakRSS() (*uint64, string) {
	counters := memoryCounters{}
	counters.Size = uint32(unsafe.Sizeof(counters))
	procedure := syscall.NewLazyDLL("psapi.dll").NewProc("GetProcessMemoryInfo")
	if procedure.Find() != nil {
		return nil, "unavailable: Windows GetProcessMemoryInfo"
	}
	success, _, _ := procedure.Call(^uintptr(0), uintptr(unsafe.Pointer(&counters)), uintptr(counters.Size))
	if success == 0 {
		return nil, "unavailable: Windows GetProcessMemoryInfo"
	}
	peak := uint64(counters.PeakWorkingSetSize)
	return &peak, "Windows GetProcessMemoryInfo PeakWorkingSetSize"
}
