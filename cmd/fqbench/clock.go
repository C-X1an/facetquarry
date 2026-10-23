package main

import (
	"fmt"
	"math"
	"math/bits"
)

// A clock is initialized once; concurrent reads use the same cached counter.
// No minimum duration is imposed on observations, including genuine zeros.
type measurementClock struct {
	now       func() (int64, error)
	frequency int64
	metadata  map[string]any
}

func (c *measurementClock) elapsed(start, end int64) (int64, error) {
	if end < start || start < 0 || c.frequency <= 0 {
		return 0, fmt.Errorf("invalid monotonic clock interval")
	}
	hi, lo := bits.Mul64(uint64(end-start), 1_000_000_000)
	if hi >= uint64(c.frequency) {
		return 0, fmt.Errorf("clock interval overflows nanoseconds")
	}
	ns, _ := bits.Div64(hi, lo, uint64(c.frequency))
	if ns > math.MaxInt64 {
		return 0, fmt.Errorf("clock interval overflows nanoseconds")
	}
	return int64(ns), nil
}

func (c *measurementClock) calibrate() error {
	previous, err := c.now()
	if err != nil {
		return err
	}
	var minimum int64
	zeros := 0
	for i := 0; i < 1000; i++ {
		current, err := c.now()
		if err != nil {
			return err
		}
		_, err = c.elapsed(previous, current)
		if err != nil {
			return err
		}
		if current == previous {
			zeros++
		} else if minimum == 0 || current-previous < minimum {
			minimum = current - previous
		}
		previous = current
	}
	var minimumNS any
	if minimum > 0 {
		value, err := c.elapsed(0, minimum)
		if err != nil {
			return err
		}
		minimumNS = value
	}
	c.metadata["frequency_hz"] = c.frequency
	c.metadata["nominal_tick_ns"] = 1e9 / float64(c.frequency)
	c.metadata["calibration"] = map[string]any{"successive_read_pairs": 1000, "zero_tick_pairs": zeros, "minimum_positive_ticks": minimum, "minimum_positive_ns": minimumNS, "scope": "observed counter-read spacing, not search latency or a guaranteed clock resolution"}
	return nil
}
