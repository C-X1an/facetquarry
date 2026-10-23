//go:build !windows

package main

import "time"

func newMeasurementClock() (*measurementClock, error) {
	origin := time.Now()
	c := &measurementClock{frequency: 1_000_000_000, metadata: map[string]any{"name": "Go time.Since monotonic clock", "monotonic": true, "fallback": false, "resolution": "platform dependent; nanosecond representation does not imply nanosecond hardware resolution"}}
	c.now = func() (int64, error) { return time.Since(origin).Nanoseconds(), nil }
	if err := c.calibrate(); err != nil {
		return nil, err
	}
	return c, nil
}
