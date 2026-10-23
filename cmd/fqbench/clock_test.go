package main

import "testing"

func TestTickConversionAndInvalidIntervals(t *testing.T) {
	c := measurementClock{frequency: 10_000_000}
	for _, pair := range [][3]int64{{100, 100, 0}, {100, 101, 100}, {123, 10_000_123, 1_000_000_000}} {
		ns, err := c.elapsed(pair[0], pair[1])
		if err != nil || ns != pair[2] {
			t.Fatalf("elapsed %v = %d, %v", pair, ns, err)
		}
	}
	if _, err := c.elapsed(2, 1); err == nil {
		t.Fatal("backward counter accepted")
	}
	c.frequency = 1
	if _, err := c.elapsed(0, 1<<62); err == nil {
		t.Fatal("overflow accepted")
	}
}

func TestNativeClockMonotonicAndCalibrated(t *testing.T) {
	c, err := newMeasurementClock()
	if err != nil {
		t.Fatal(err)
	}
	if c.frequency <= 0 || c.metadata["calibration"] == nil || c.metadata["fallback"] != false {
		t.Fatal("missing native clock metadata")
	}
	a, err := c.now()
	if err != nil {
		t.Fatal(err)
	}
	b, err := c.now()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.elapsed(a, b); err != nil {
		t.Fatal(err)
	}
}
