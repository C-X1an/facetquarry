package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
)

func TestPruneKeepsBridgesAmongDuplicates(t *testing.T) {
	g := &graph{Records: []Record{
		{ID: "base", Vector: []float32{0}},
		{ID: "a", Vector: []float32{0}},
		{ID: "b", Vector: []float32{0}},
		{ID: "c", Vector: []float32{0}},
		{ID: "d", Vector: []float32{0}},
		{ID: "right", Vector: []float32{1}},
		{ID: "left", Vector: []float32{-1}},
	}}
	b := builder{ctx: context.Background(), limit: 100}
	kept, err := b.prune(g, 0, []int{1, 2, 3, 4, 5, 6, 5, 0}, 4)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[int]bool{}
	for _, i := range kept {
		if i == 0 || seen[i] {
			t.Fatalf("self or duplicate edge: %v", kept)
		}
		seen[i] = true
	}
	if len(kept) != 4 || !seen[5] || !seen[6] {
		t.Fatalf("zero-distance duplicates displaced distinct bridges: %v", kept)
	}
}

func TestPrunePreservesNonzeroEqualDistanceDiversity(t *testing.T) {
	g := &graph{Records: []Record{
		{ID: "base", Vector: []float32{0, 0, 0}},
		{ID: "a", Vector: []float32{1, 1, 0}},
		{ID: "b", Vector: []float32{1, 0, 1}},
		{ID: "c", Vector: []float32{-1, -1, 0}},
	}}
	b := builder{ctx: context.Background(), limit: 100}
	kept, err := b.prune(g, 0, []int{3, 2, 1}, 2)
	if err != nil || !reflect.DeepEqual(kept, []int{1, 2}) {
		t.Fatalf("equal nonzero distances lost diversity: %v, %v", kept, err)
	}
}

// This regression mirrors the frozen duplicate-vector construction, not its
// benchmark timing protocol. Exact truth follows from the explicit input IDs.
func TestDuplicateVectorsReachLowestIDs(t *testing.T) {
	for _, seed := range []int64{11, 23, 47, 83, 131} {
		t.Run(fmt.Sprint(seed), func(t *testing.T) {
			c := Corpus{SchemaVersion: 1, Dimension: 64, M: 12, EFConstruction: 96,
				Seed: seed, BuildBudget: 200000000, Records: make([]Record, 10000)}
			for i := range c.Records {
				v := make([]float32, c.Dimension)
				for j := range v {
					v[j] = float32(i % 5)
				}
				c.Records[i] = Record{Tenant: "alpha", ID: fmt.Sprintf("r%06d", i), Vector: v, Metadata: map[string]string{}}
			}
			col := mustBuild(t, c)
			g := col.data.Graphs[0]
			truth := make([]string, 10)
			for i := range truth {
				truth[i] = fmt.Sprintf("r%06d", 5*i)
			}
			// Reproduce the actual upper-layer descent separately from the
			// global entry's bottom component; those entries can differ.
			w := workspace{ctx: context.Background(), g: g, query: make([]float32, 64), budget: 10000, cache: map[int]float64{}}
			lowerEntry := g.Entry
			for level := g.MaxLevel; level > 0; level-- {
				found, err := searchLayer(context.Background(), g, lowerEntry, level, 1, nil, w.get)
				if err != nil {
					t.Fatal(err)
				}
				lowerEntry = found[0].index
			}
			lowerSeen := map[int]bool{lowerEntry: true}
			lowerQueue := []int{lowerEntry}
			for at := 0; at < len(lowerQueue); at++ {
				for _, j := range g.Nodes[lowerQueue[at]].Edges[0] {
					if !lowerSeen[j] {
						lowerSeen[j] = true
						lowerQueue = append(lowerQueue, j)
					}
				}
			}
			unreachable := []string{}
			for _, id := range truth {
				for i, rec := range g.Records {
					_, upperVisited := w.cache[i]
					if rec.ID == id && !lowerSeen[i] && !upperVisited {
						unreachable = append(unreachable, id)
					}
				}
			}
			layers := []map[string]any{}
			for level := 0; level <= g.MaxLevel; level++ {
				seen := map[int]bool{g.Entry: true}
				queue := []int{g.Entry}
				cross, nodes := 0, 0
				for i, n := range g.Nodes {
					if n.Level < level {
						continue
					}
					nodes++
					for _, j := range n.Edges[level] {
						if g.Records[i].Vector[0] != g.Records[j].Vector[0] {
							cross++
						}
					}
				}
				for at := 0; at < len(queue); at++ {
					for _, j := range g.Nodes[queue[at]].Edges[level] {
						if !seen[j] {
							seen[j] = true
							queue = append(queue, j)
						}
					}
				}
				missing := []string{}
				if level == 0 {
					for _, id := range truth {
						for i, r := range g.Records {
							if r.ID == id && !seen[i] {
								missing = append(missing, id)
							}
						}
					}
				}
				layers = append(layers, map[string]any{"level": level, "nodes": nodes, "reachable_from_entry": len(seen), "cross_vector_edges": cross, "unreachable_top10_ids": missing})
			}
			r, err := mustScope(t, col, "alpha").Search(context.Background(), Query{Vector: make([]float32, 64), K: 10, EF: 128, Budget: 10000, Mode: "graph", Filter: map[string]string{}})
			if err != nil {
				t.Fatal(err)
			}
			ids := make([]string, len(r.Hits))
			for i, hit := range r.Hits {
				ids[i] = hit.ID
			}
			data, err := json.Marshal(map[string]any{"seed": seed, "layers": layers, "build_distances": col.buildDistances, "query": r, "expected_ids": truth,
				"actual_lower_entry": g.Records[lowerEntry].ID, "reachable_from_lower_entry": len(lowerSeen), "unreachable_from_query_path_top10": unreachable})
			if err != nil {
				t.Fatal(err)
			}
			t.Log(string(data))
			if r.Plan != "graph" || r.Status != "complete" || r.Exact || r.DistanceEvaluations > 10000 || !reflect.DeepEqual(ids, truth) {
				t.Errorf("duplicate-vector graph missed lowest tied IDs: got %v, want %v", ids, truth)
			}
		})
	}
}
