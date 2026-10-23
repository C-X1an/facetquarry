package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"facetquarry/internal/engine"
	"flag"
	"io"
	"os"
	"os/signal"
	"runtime"
	"syscall"
)

var sourceID = "development-unbound"

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r contextReader) Read(b []byte) (int, error) {
	if r.ctx.Err() != nil {
		return 0, &engine.Error{Code: "E_CANCELLED", Message: "operation cancelled"}
	}
	return r.reader.Read(b)
}
func input(ctx context.Context, path string, limit int) ([]byte, error) {
	var r io.Reader = os.Stdin
	if path != "-" {
		f, e := os.Open(path)
		if e != nil {
			return nil, &engine.Error{Code: "E_IO", Message: "cannot open input"}
		}
		defer f.Close()
		r = f
	}
	b, e := io.ReadAll(io.LimitReader(contextReader{ctx, r}, int64(limit)+1))
	if e != nil {
		if ctx.Err() != nil {
			return nil, &engine.Error{Code: "E_CANCELLED", Message: "operation cancelled"}
		}
		return nil, &engine.Error{Code: "E_IO", Message: "cannot read input"}
	}
	if len(b) > limit {
		return nil, &engine.Error{Code: "E_INPUT", Message: "input byte limit"}
	}
	return b, nil
}
func output(v any) error { return json.NewEncoder(os.Stdout).Encode(v) }
func errorValue(err error) any {
	var e *engine.Error
	if !errors.As(err, &e) {
		e = &engine.Error{Code: "E_IO", Message: "I/O operation failed"}
	}
	return struct {
		Error *engine.Error `json:"error"`
	}{e}
}
func run(ctx context.Context, args []string) error {
	emit := func(v any) error {
		if ctx.Err() != nil {
			return &engine.Error{Code: "E_CANCELLED", Message: "operation cancelled"}
		}
		return output(v)
	}
	if ctx.Err() != nil {
		return &engine.Error{Code: "E_CANCELLED", Message: "operation cancelled"}
	}
	bad := func(msg string) error { return &engine.Error{Code: "E_INPUT", Message: msg} }
	if len(args) == 0 {
		return bad("expected build, search, batch, inspect or version")
	}
	if args[0] == "version" {
		if len(args) != 1 {
			return bad("unexpected version arguments")
		}
		return emit(map[string]any{"schema_version": 1, "version": "0.1.0-dev", "source": sourceID, "go": runtime.Version()})
	}
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	index, tenant, query, corpus, out, queries := "", "", "", "", "", ""
	switch args[0] {
	case "build":
		fs.StringVar(&corpus, "input", "", "corpus")
		fs.StringVar(&out, "output", "", "new snapshot")
	case "search", "batch":
		fs.StringVar(&index, "index", "", "snapshot")
		fs.StringVar(&tenant, "tenant", "", "host-selected tenant")
		if args[0] == "search" {
			fs.StringVar(&query, "query", "", "query file or -")
		} else {
			fs.StringVar(&queries, "queries", "", "JSONL file")
		}
	case "inspect":
		fs.StringVar(&index, "index", "", "snapshot")
	default:
		return bad("unknown command")
	}
	if fs.Parse(args[1:]) != nil || fs.NArg() != 0 {
		return bad("invalid command flags")
	}
	if args[0] == "build" {
		if corpus == "" || out == "" {
			return bad("input and output required")
		}
		b, e := input(ctx, corpus, engine.MaxSnapshot)
		if e != nil {
			return e
		}
		c, e := engine.DecodeCorpusContext(ctx, b)
		if e != nil {
			return e
		}
		collection, e := engine.Build(ctx, c)
		if e != nil {
			return e
		}
		if e = collection.SaveContext(ctx, out); e != nil {
			return e
		}
		return emit(collection.Inspect())
	}
	if index == "" {
		return bad("index required")
	}
	collection, e := engine.LoadContext(ctx, index)
	if e != nil {
		return e
	}
	if args[0] == "inspect" {
		return emit(collection.Inspect())
	}
	if tenant == "" {
		return bad("host tenant required")
	}
	scope, e := collection.Scope(tenant)
	if e != nil {
		return e
	}
	execute := func(b []byte) (engine.Response, error) {
		q, e := engine.DecodeQueryContext(ctx, b)
		if e != nil {
			return engine.Response{}, e
		}
		return scope.Search(ctx, q)
	}
	if args[0] == "search" {
		if query == "" {
			return bad("query required")
		}
		b, e := input(ctx, query, engine.MaxQuery)
		if e != nil {
			return e
		}
		r, e := execute(b)
		if e != nil {
			return e
		}
		return emit(r)
	}
	if queries == "" {
		return bad("queries required")
	}
	f, e := os.Open(queries)
	if e != nil {
		return &engine.Error{Code: "E_IO", Message: "cannot open queries"}
	}
	defer f.Close()
	scan := bufio.NewScanner(f)
	scan.Buffer(make([]byte, 4096), engine.MaxQuery+1)
	failed := false
	for scan.Scan() {
		r, e := execute(scan.Bytes())
		if e != nil {
			if engine.Code(e) == "E_CANCELLED" {
				return e
			}
			failed = true
			if e = emit(errorValue(e)); e != nil {
				return e
			}
		} else if e = emit(r); e != nil {
			return e
		}
	}
	if scan.Err() != nil {
		return bad("invalid or oversized query line")
	}
	if failed {
		return bad("one or more batch queries failed")
	}
	return nil
}
func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := run(ctx, os.Args[1:]); err != nil {
		_ = json.NewEncoder(os.Stderr).Encode(errorValue(err))
		code := 1
		switch engine.Code(err) {
		case "E_INPUT", "E_SCOPE", "E_FORMAT":
			code = 2
		case "E_CANCELLED":
			code = 3
		case "E_BUDGET":
			code = 4
		}
		os.Exit(code)
	}
}
