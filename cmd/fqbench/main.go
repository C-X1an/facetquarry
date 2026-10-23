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
	"strconv"
	"strings"
	"sync"
	"time"
)

type sample struct {
	Query       int              `json:"query"`
	Repetition  int              `json:"repetition"`
	Nanoseconds int64            `json:"nanoseconds"`
	Response    *engine.Response `json:"response,omitempty"`
	Error       string           `json:"error,omitempty"`
}

func execute() error {
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
				start := time.Now()
				r, e := scope.Search(ctx, queries[q])
				s := sample{Query: q, Repetition: rep, Nanoseconds: time.Since(start).Nanoseconds()}
				if e != nil {
					s.Error = e.Error()
				} else {
					s.Response = &r
				}
				results <- s
			}
		}()
	}
	go func() {
		for i := 0; i < *reps*len(queries); i++ {
			jobs <- i
		}
		close(jobs)
		wg.Wait()
		close(results)
	}()
	enc := json.NewEncoder(os.Stdout)
	failed := false
	for s := range results {
		if s.Error != "" {
			failed = true
		}
		if e = enc.Encode(s); e != nil {
			return e
		}
	}
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	rss := int64(0)
	if raw, e := os.ReadFile("/proc/self/status"); e == nil {
		for _, line := range strings.Split(string(raw), "\n") {
			if strings.HasPrefix(line, "VmHWM:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					rss, _ = strconv.ParseInt(fields[1], 10, 64)
					rss *= 1024
				}
			}
		}
	}
	if e = enc.Encode(map[string]any{"summary": true, "peak_rss_bytes_linux": rss, "go_runtime_sys_bytes": mem.Sys, "go": runtime.Version(), "workers": *concurrency, "samples": len(queries) * *reps, "measurement": "Search wall time only; excludes load/parse and worker queue wait; RSS includes loaded index and harness"}); e != nil {
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
