//go:build windows

package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

func newMeasurementClock() (*measurementClock, error) {
	kernel := syscall.NewLazyDLL("kernel32.dll")
	counter := kernel.NewProc("QueryPerformanceCounter")
	frequency := kernel.NewProc("QueryPerformanceFrequency")
	if err := counter.Find(); err != nil {
		return nil, fmt.Errorf("QueryPerformanceCounter unavailable: %w", err)
	}
	if err := frequency.Find(); err != nil {
		return nil, fmt.Errorf("QueryPerformanceFrequency unavailable: %w", err)
	}
	var hz int64
	ok, _, _ := frequency.Call(uintptr(unsafe.Pointer(&hz)))
	if ok == 0 || hz <= 0 {
		return nil, fmt.Errorf("QueryPerformanceFrequency failed")
	}
	c := &measurementClock{frequency: hz, metadata: map[string]any{"name": "Windows QueryPerformanceCounter", "monotonic": true, "fallback": false, "resolution": "1 / QueryPerformanceFrequency seconds per counter tick; read-spacing calibration retained; no duration floor"}}
	c.now = func() (int64, error) {
		var ticks int64
		ok, _, _ := counter.Call(uintptr(unsafe.Pointer(&ticks)))
		if ok == 0 || ticks < 0 {
			return 0, fmt.Errorf("QueryPerformanceCounter failed")
		}
		return ticks, nil
	}
	if err := c.calibrate(); err != nil {
		return nil, err
	}
	return c, nil
}
