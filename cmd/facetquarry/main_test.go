package main

import (
	"context"
	"facetquarry/internal/engine"
	"path/filepath"
	"testing"
)

func TestCancelledCLINeverSucceeds(t *testing.T) {
	col, err := engine.Build(context.Background(), engine.Corpus{SchemaVersion: 1, Dimension: 1,
		Records: []engine.Record{{Tenant: "alpha", ID: "a", Vector: []float32{0}, Metadata: map[string]string{}}}})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "index.fq")
	if err := col.Save(path); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, args := range [][]string{{"inspect", "--index", path}, {"version"}} {
		if err := run(ctx, args); engine.Code(err) != "E_CANCELLED" {
			t.Fatalf("cancelled command succeeded: %v: %v", args, err)
		}
	}
}
