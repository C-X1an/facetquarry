// fqbench measures actual in-process Search calls, excluding input loading/parsing.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"facetquarry/internal/engine"
	"flag"
	"fmt"
	"os"
	"runtime"
	"sync"
)

type sample struct {
	Query       int              `json:"query"`
	Repetition  int              `json:"repetition"`
	Nanoseconds int64            `json:"nanoseconds"`
	Response    *engine.Response `json:"response,omitempty"`
	Error       string           `json:"error,omitempty"`
}

var sourceID = "development-unbound"

func execute() error {
	if len(os.Args) == 2 && os.Args[1] == "version" {
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"schema_version": 1, "source": sourceID, "go": runtime.Version()})
	}
	index := flag.String("index", "", "snapshot")
	tenant := flag.String("tenant", "alpha", "host scope")
	file := flag.String("queries", "", "query JSONL")
	reps := flag.Int("repetitions", 5, "timing repetitions")
	warm := flag.Int("warmup", 20, "warmup calls")
	concurrency := flag.Int("concurrency", 1, "query workers")
	flag.Parse()
	if *index == "" || *file == "" || *reps < 1 || *reps > 10 || *warm < 0 || *warm > 100 || *concurrency < 1 || *concurrency > 16 {
		return fmt.Errorf("invalid benchmark controls")
	}
	c, e := engine.Load(*index)
	if e != nil {
		return e
	}
	scope, e := c.Scope(*tenant)
	if e != nil {
		return e
	}
	f, e := os.Open(*file)
	if e != nil {
		return e
	}
	defer f.Close()
	scan := bufio.NewScanner(f)
	scan.Buffer(make([]byte, 4096), engine.MaxQuery+1)
	queries := []engine.Query{}
	for scan.Scan() {
		q, e := engine.DecodeQuery(scan.Bytes())
		if e != nil {
			return e
		}
		queries = append(queries, q)
		if len(queries) > 1000 {
			return fmt.Errorf("query count limit")
		}
	}
	if scan.Err() != nil {
		return scan.Err()
	}
	if len(queries) == 0 {
		return fmt.Errorf("empty queries")
	}
	ctx := context.Background()
	clock, e := newMeasurementClock()
	if e != nil {
		return e
	}
	for i := 0; i < *warm; i++ {
		if _, e = scope.Search(ctx, queries[i%len(queries)]); e != nil {
			return e
		}
	}
	jobs := make(chan int)
	results := make(chan sample, *concurrency)
	var wg sync.WaitGroup
	for w := 0; w < *concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for id := range jobs {
				q := id % len(queries)
				rep := id / len(queries)
				s := sample{Query: q, Repetition: rep}
				start, clockError := clock.now()
				if clockError != nil {
					s.Error = clockError.Error()
					results <- s
					continue
				}
				r, e := scope.Search(ctx, queries[q])
				end, clockError := clock.now()
				if clockError == nil {
					s.Nanoseconds, clockError = clock.elapsed(start, end)
				}
				if clockError != nil {
					s.Error = clockError.Error()
				} else if e != nil {
					s.Error = e.Error()
				} else {
					s.Response = &r
				}
				results <- s
			}
		}()
	}
	intervalStart, e := clock.now()
	if e != nil {
		close(jobs)
		wg.Wait()
		return e
	}
	var intervalEnd int64
	var intervalError error
	go func() {
		for i := 0; i < *reps*len(queries); i++ {
			jobs <- i
		}
		close(jobs)
		wg.Wait()
		intervalEnd, intervalError = clock.now()
		close(results)
	}()
	enc := json.NewEncoder(os.Stdout)
	failed := false
	successful := 0
	zeros := 0
	for s := range results {
		if s.Error != "" {
			failed = true
		} else {
			successful++
		}
		if s.Nanoseconds == 0 {
			zeros++
		}
		if e = enc.Encode(s); e != nil {
			return e
		}
	}
	if intervalError != nil {
		return intervalError
	}
	intervalNS, e := clock.elapsed(intervalStart, intervalEnd)
	if e != nil || intervalNS <= 0 {
		return fmt.Errorf("invalid full-run measurement interval: %d ns, %v", intervalNS, e)
	}
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	rss, rssMeasurement := peakRSS()
	if e = enc.Encode(map[string]any{"summary": true, "source": sourceID, "peak_rss_bytes": rss, "rss_measurement": rssMeasurement, "goos": runtime.GOOS, "goarch": runtime.GOARCH, "gomaxprocs": runtime.GOMAXPROCS(0), "go_runtime_sys_bytes": mem.Sys, "go": runtime.Version(), "workers": *concurrency, "samples": len(queries) * *reps, "successful_queries": successful, "zero_duration_count": zeros, "clock": clock.metadata, "measured_interval_ns": intervalNS, "completed_queries_per_second": float64(successful) * 1e9 / float64(intervalNS), "throughput_measurement": "successful measured queries / dispatch-to-worker-completion interval; includes queueing and streaming JSON backpressure; excludes load, parse, calibration and warmup", "measurement": "per-query search wall time excludes load/parse and worker queue wait; counter-read overhead remains; RSS includes loaded index and harness"}); e != nil {
		return e
	}
	if failed {
		return fmt.Errorf("one or more measured queries failed")
	}
	return nil
}
func main() {
	if e := execute(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
