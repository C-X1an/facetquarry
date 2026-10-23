//go:build !linux && !windows

package main

func peakRSS() (*uint64, string) {
	return nil, "unavailable on this platform"
}
