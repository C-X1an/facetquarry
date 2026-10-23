//go:build linux

package main

import (
	"os"
	"strconv"
	"strings"
)

func peakRSS() (*uint64, string) {
	if raw, err := os.ReadFile("/proc/self/status"); err == nil {
		for _, line := range strings.Split(string(raw), "\n") {
			if strings.HasPrefix(line, "VmHWM:") {
				fields := strings.Fields(line)
				if len(fields) == 3 && fields[2] == "kB" {
					if value, err := strconv.ParseUint(fields[1], 10, 64); err == nil {
						peak := value * 1024
						return &peak, "Linux /proc/self/status VmHWM"
					}
				}
			}
		}
	}
	return nil, "unavailable: Linux VmHWM"
}
