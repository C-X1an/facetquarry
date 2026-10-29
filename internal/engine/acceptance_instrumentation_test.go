package engine

// Additional scope isolation, foreign-read sensitivity and loaded-index ownership controls.
import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"sync"
	"testing"
)

const harnessControlEnv = "FACETQUARRY_HARNESS_CONTROL"

func harnessControl(t *testing.T) string {
	t.Helper()
	v := os.Getenv(harnessControlEnv)
	switch v {
	case "", "normal":
		return "normal"
	case "race-read-discard":
		return v
	default:
		t.Fatalf("unknown %s=%q", harnessControlEnv, v)
		return "invalid"
	}
}

// Exactly 600 input records: 300 per tenant, identical tenant-local IDs.
func harnessCorpus() Corpus {
	c := Corpus{SchemaVersion: 1, Dimension: 2, M: 4, EFConstruction: 24, Seed: 719, BuildBudget: 5000000}
	for _, tenant := range []string{"alpha", "beta"} {
		for i := 0; i < 300; i++ {
			v := []float32{float32(i), float32(i % 7)}
			if tenant == "beta" {
				v = []float32{float32(10000 + 299 - i), float32(-10000 - i%11)}
			}
			kind := "ordinary"
			if i%97 == 0 {
				kind = "sparse"
			}
			c.Records = append(c.Records, Record{Tenant: tenant, ID: fmt.Sprintf("r%03d", i), Vector: v, Metadata: map[string]string{"group": "all", "kind": kind}})
		}
	}
	return c
}

type harnessCase struct {
	name string
	q    Query
}

func harnessCases() []harnessCase {
	var out []harnessCase
	filters := []struct {
		name string
		data map[string]string
	}{
		{"all", map[string]string{}},
		{"broad", map[string]string{"group": "all"}},
		{"sparse", map[string]string{"group": "all", "kind": "sparse"}},
		{"empty", map[string]string{"kind": "absent"}},
	}
	for _, mode := range []string{"exact", "graph", "postfilter", "auto"} {
		for _, f := range filters {
			for _, budget := range []int{0, 1, 7, 600} {
				out = append(out, harnessCase{fmt.Sprintf("%s/%s/b%d", mode, f.name, budget), Query{Vector: []float32{17, 2}, K: 3, EF: 32, Budget: budget, Mode: mode, Filter: f.data}})
			}
		}
	}
	return out
}

// Deliberately independent of engine distance, postings, less, and exact search.
func harnessOracle(c Corpus, tenant string, q Query) ([]Hit, int) {
	hits := []Hit{}
	for _, rec := range c.Records {
		if rec.Tenant != tenant {
			continue
		}
		matches := true
		for key, value := range q.Filter {
			got, present := rec.Metadata[key]
			if !present || got != value {
				matches = false
				break
			}
		}
		if !matches {
			continue
		}
		d := 0.0
		for j := 0; j < c.Dimension; j++ {
			delta := float64(q.Vector[j]) - float64(rec.Vector[j])
			d += delta * delta
		}
		hits = append(hits, Hit{ID: rec.ID, Distance: d})
	}
	eligible := len(hits)
	sort.Slice(hits, func(i, j int) bool {
		if hits[i].Distance == hits[j].Distance {
			return hits[i].ID < hits[j].ID
		}
		return hits[i].Distance < hits[j].Distance
	})
	if len(hits) > q.K {
		hits = hits[:q.K]
	}
	return hits, eligible
}

func harnessCheckResponse(t *testing.T, c Corpus, tenant, generation string, tc harnessCase, r Response) {
	t.Helper()
	truth, eligible := harnessOracle(c, tenant, tc.q)
	plan := tc.q.Mode
	if plan == "auto" {
		plan = "exact"
		if eligible > 256 {
			plan = "graph"
		}
	}
	if eligible == 0 {
		plan = "exact"
	}
	if r.SchemaVersion != 1 || r.Generation != generation || r.Plan != plan || r.Eligible != eligible || r.DistanceEvaluations < 0 || r.DistanceEvaluations > tc.q.Budget {
		t.Fatalf("%s tenant=%s header/work mismatch: %+v", tc.name, tenant, r)
	}
	if r.Status != "complete" && r.Status != "budget_exhausted" {
		t.Fatalf("%s unknown status: %+v", tc.name, r)
	}
	if eligible == 0 || plan == "exact" && tc.q.Budget >= eligible {
		if r.Status != "complete" || !r.Exact || r.DistanceEvaluations != eligible || !reflect.DeepEqual(r.Hits, truth) {
			t.Fatalf("%s independently checked exact mismatch: %+v truth=%+v", tc.name, r, truth)
		}
	} else {
		if r.Exact {
			t.Fatalf("%s approximate/partial result claims exactness: %+v", tc.name, r)
		}
		if tc.q.Budget == 0 && (r.Status != "budget_exhausted" || r.DistanceEvaluations != 0 || len(r.Hits) != 0) {
			t.Fatalf("%s zero-budget mismatch: %+v", tc.name, r)
		}
		if tc.q.Budget >= 300 && r.Status != "complete" {
			t.Fatalf("%s full fixture budget not complete: %+v", tc.name, r)
		}
	}
	if len(r.Hits) > tc.q.K {
		t.Fatalf("%s too many hits", tc.name)
	}
	for i, hit := range r.Hits {
		if i > 0 && (r.Hits[i-1].Distance > hit.Distance || r.Hits[i-1].Distance == hit.Distance && r.Hits[i-1].ID >= hit.ID) {
			t.Fatalf("%s unordered or duplicate hits: %+v", tc.name, r.Hits)
		}
		found := false
		for _, rec := range c.Records {
			if rec.Tenant != tenant || rec.ID != hit.ID {
				continue
			}
			matches := true
			for k, v := range tc.q.Filter {
				if got, ok := rec.Metadata[k]; !ok || got != v {
					matches = false
				}
			}
			d0 := float64(tc.q.Vector[0]) - float64(rec.Vector[0])
			d1 := float64(tc.q.Vector[1]) - float64(rec.Vector[1])
			found = matches && hit.Distance == d0*d0+d1*d1
			break
		}
		if !found {
			t.Fatalf("%s foreign, ineligible, or wrong-distance hit: %+v", tc.name, hit)
		}
	}
}

func harnessBaseline(t *testing.T, c Corpus, s *Scope, tenant string, cases []harnessCase) []Response {
	t.Helper()
	out := make([]Response, len(cases))
	for i, tc := range cases {
		r, err := s.Search(context.Background(), tc.q)
		if err != nil {
			t.Fatalf("%s baseline: %v", tc.name, err)
		}
		harnessCheckResponse(t, c, tenant, s.generation, tc, r)
		// Expected responses must never alias a buffer returned by Search.
		if r.Hits != nil {
			hits := make([]Hit, len(r.Hits))
			copy(hits, r.Hits)
			r.Hits = hits
		}
		out[i] = r
	}
	return out
}

func harnessBinding(t *testing.T, c Corpus) (*Collection, *Scope, *graph) {
	t.Helper()
	col := mustBuild(t, c)
	if len(col.data.Graphs) != 2 {
		t.Fatal("fixture must have exactly two graphs")
	}
	var alpha, beta *graph
	for _, g := range col.data.Graphs {
		switch g.Tenant {
		case "alpha":
			alpha = g
		case "beta":
			beta = g
		}
	}
	if alpha == nil || beta == nil || alpha == beta {
		t.Fatal("fixture tenant graphs missing or aliased")
	}
	// Reorder before binding: an if-true tenant predicate must bind beta and fail.
	col.data.Graphs = []*graph{beta, alpha}
	s := mustScope(t, col, "alpha")
	if s.g != alpha || s.g == beta || s.dimension != c.Dimension || s.generation != col.generation {
		t.Fatal("beta-first collection did not bind the actual alpha graph")
	}
	return col, s, beta
}

func harnessObserve(s *Scope, q Query) (r Response, err error, panicValue any) {
	defer func() { panicValue = recover() }()
	r, err = s.Search(context.Background(), q)
	return
}

func TestAcceptanceScopePoisonedForeignPayloads(t *testing.T) {
	harnessControl(t)
	for _, poison := range []string{"vector", "node", "posting"} {
		t.Run(poison, func(t *testing.T) {
			c := harnessCorpus()
			_, alpha, beta := harnessBinding(t, c)
			cases := harnessCases()
			before := harnessBaseline(t, c, alpha, "alpha", cases)
			control := Query{Vector: []float32{17, 2}, K: 3, EF: 32, Budget: 600, Mode: "exact", Filter: map[string]string{}}
			if poison == "node" {
				control.Mode = "graph"
			}
			if poison == "posting" {
				control.Filter = map[string]string{"group": "all"}
			}
			calibration := *alpha
			calibration.g = beta
			healthy, err, controlPanic := harnessObserve(&calibration, control)
			if err != nil || controlPanic != nil {
				t.Fatalf("healthy redirected beta failed before %s poison: err=%v panic=%v", poison, err, controlPanic)
			}
			harnessCheckResponse(t, c, "beta", calibration.generation, harnessCase{"healthy beta calibration", control}, healthy)
			switch poison {
			case "vector":
				for i := range beta.Records {
					beta.Records[i].Vector = nil
				}
			case "node":
				for i := range beta.Nodes {
					beta.Nodes[i].Edges = nil
				}
				control.Mode = "graph"
			case "posting":
				beta.postings["group"]["all"] = []int{len(beta.Records) + 17}
				control.Filter = map[string]string{"group": "all"}
			}
			for i, tc := range cases {
				r, err, p := harnessObserve(alpha, tc.q)
				if p != nil || err != nil || !reflect.DeepEqual(before[i], r) {
					t.Fatalf("%s alpha touched poisoned beta or changed complete response: %+v err=%v panic=%v", tc.name, r, err, p)
				}
			}
			// Controlled wrong graph on a local scope copy, through actual Search.
			redirected := *alpha
			redirected.g = beta
			_, _, p := harnessObserve(&redirected, control)
			if p == nil {
				t.Fatalf("%s poison control was not exercised by redirected Scope.Search", poison)
			}
			t.Logf("%s poison sensitivity observed: redirected Scope.Search panicked (%T)", poison, p)
		})
	}
}

type harnessIntSlot struct {
	ptr   *int
	value int
}

// All map traversal happens before either goroutine starts. Only captured posting
// backing elements are assigned during the sentinel; no map is mutated then.
func harnessPostingSlots(g *graph) []harnessIntSlot {
	var slots []harnessIntSlot
	for _, values := range g.postings {
		for _, list := range values {
			for i := range list {
				slots = append(slots, harnessIntSlot{&list[i], list[i]})
			}
		}
	}
	return slots
}

//go:noinline
func harnessReadAndDiscard(g *graph, slots []harnessIntSlot) float64 {
	// Returning a consumed checksum keeps the deliberate foreign loads observable
	// to compilation. Search results never depend on this negative-control value.
	sum := float64(len(g.Tenant) + len(g.Records) + len(g.Nodes) + g.Entry + g.MaxLevel)
	for _, rec := range g.Records {
		sum += float64(len(rec.Tenant) + len(rec.ID) + len(rec.Vector))
		for _, v := range rec.Vector {
			sum += float64(v)
		}
	}
	for _, n := range g.Nodes {
		sum += float64(n.Level + len(n.Edges))
		for _, edges := range n.Edges {
			for _, edge := range edges {
				sum += float64(edge)
			}
		}
	}
	for _, slot := range slots {
		sum += float64(*slot.ptr)
	}
	return sum
}

func TestAcceptanceScopeForeignReadSentinel(t *testing.T) {
	control := harnessControl(t)
	c := harnessCorpus()
	_, alpha, beta := harnessBinding(t, c)
	cases := harnessCases()
	before := harnessBaseline(t, c, alpha, "alpha", cases)
	// Copy every value that the writer will use before concurrency begins.
	fields := *beta
	records := append([]Record(nil), beta.Records...)
	vectors := make([][]float32, len(records))
	for i, rec := range records {
		vectors[i] = append([]float32(nil), rec.Vector...)
	}
	nodes := append([]node(nil), beta.Nodes...)
	edgeValues := make([][][]int, len(nodes))
	for i, n := range nodes {
		edgeValues[i] = make([][]int, len(n.Edges))
		for level, edges := range n.Edges {
			edgeValues[i][level] = append([]int(nil), edges...)
		}
	}
	slots := harnessPostingSlots(beta)
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		for round := 0; round < 512; round++ {
			beta.Tenant = fields.Tenant
			beta.Records = fields.Records
			beta.Nodes = fields.Nodes
			beta.Entry = fields.Entry
			beta.MaxLevel = fields.MaxLevel
			for i, rec := range records {
				fields.Records[i].Tenant = rec.Tenant
				fields.Records[i].ID = rec.ID
				fields.Records[i].Vector = rec.Vector
				for j, v := range vectors[i] {
					rec.Vector[j] = v
				}
			}
			for i, n := range nodes {
				fields.Nodes[i].Level = n.Level
				fields.Nodes[i].Edges = n.Edges
				for level, edges := range n.Edges {
					fields.Nodes[i].Edges[level] = edges
					for j, v := range edgeValues[i][level] {
						edges[j] = v
					}
				}
			}
			for _, slot := range slots {
				*slot.ptr = slot.value
			}
			runtime.Gosched()
		}
	}()
	close(start)
	// No Scope lookup, beta search, inspection, serialization, or map traversal
	// occurs until the writer has joined. Alpha was bound before the writer.
	discarded := 0.0
	for round := 0; round < 4; round++ {
		for i, tc := range cases {
			if control == "race-read-discard" {
				discarded += harnessReadAndDiscard(beta, slots)
			}
			r, err := alpha.Search(context.Background(), tc.q)
			if err != nil || !reflect.DeepEqual(before[i], r) {
				t.Errorf("%s alpha response changed with beta writer: %+v %v", tc.name, r, err)
			}
		}
	}
	wg.Wait()
	runtime.KeepAlive(discarded)
	if control == "race-read-discard" {
		t.Log("intentional read-and-discard control executed; invocation qualifies only if -race reports DATA RACE and exits nonzero")
	}
}

func TestAcceptanceLoadedOwnershipAnd16Readers(t *testing.T) {
	harnessControl(t)
	c := harnessCorpus()
	built := mustBuild(t, c)
	original, err := built.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	cases := harnessCases()
	builtBaselines := map[string][]Response{}
	for _, tenant := range []string{"alpha", "beta"} {
		builtBaselines[tenant] = harnessBaseline(t, c, mustScope(t, built, tenant), tenant, cases)
	}
	for _, loader := range []string{"LoadBytes", "LoadPath"} {
		t.Run(loader, func(t *testing.T) {
			input := append([]byte(nil), original...)
			var loaded *Collection
			var path string
			var loadErr error
			if loader == "LoadBytes" {
				loaded, loadErr = LoadBytes(input)
			} else {
				path = filepath.Join(t.TempDir(), "index.fq")
				if err := os.WriteFile(path, input, 0600); err != nil {
					t.Fatal(err)
				}
				loaded, loadErr = Load(path)
			}
			if loadErr != nil {
				t.Fatal(loadErr)
			}
			if loaded == built || loaded.generation != built.generation {
				t.Fatal("load did not produce a distinct collection with identical generation")
			}
			baseline := map[string][]Response{}
			for _, tenant := range []string{"alpha", "beta"} {
				s := mustScope(t, loaded, tenant)
				baseline[tenant] = harnessBaseline(t, c, s, tenant, cases)
				if !reflect.DeepEqual(baseline[tenant], builtBaselines[tenant]) {
					t.Fatalf("%s complete sequential responses changed after load", tenant)
				}
			}
			pre, err := loaded.Marshal()
			if err != nil || !bytes.Equal(pre, original) {
				t.Fatalf("loaded pre-reader snapshot identity changed: %v", err)
			}
			// Mutate caller-owned bytes only after load. For Load(path), also
			// replace the backing file before any readers run.
			for i := range input {
				input[i] ^= 0xff
			}
			if path != "" {
				if err := os.WriteFile(path, input, 0600); err != nil {
					t.Fatal(err)
				}
			}
			sharedAlpha := mustScope(t, loaded, "alpha")
			var handles [16]*Scope
			var tenants [16]string
			for reader := range handles {
				tenants[reader] = "alpha"
				if reader%3 == 0 {
					handles[reader] = sharedAlpha
				} else {
					if reader%3 == 2 {
						tenants[reader] = "beta"
					}
					handles[reader] = mustScope(t, loaded, tenants[reader])
					if handles[reader] == sharedAlpha {
						t.Fatal("distinct handle allocation aliased shared handle")
					}
				}
			}
			start := make(chan struct{})
			var wg sync.WaitGroup
			for reader := range handles {
				wg.Add(1)
				go func(reader int) {
					defer wg.Done()
					<-start
					for round := 0; round < 2; round++ {
						for offset := range cases {
							i := (offset + reader) % len(cases)
							r, err := handles[reader].Search(context.Background(), cases[i].q)
							if err != nil || !reflect.DeepEqual(r, baseline[tenants[reader]][i]) {
								t.Errorf("reader=%d tenant=%s case=%s complete response changed: %+v err=%v", reader, tenants[reader], cases[i].name, r, err)
								return
							}
						}
					}
				}(reader)
			}
			close(start)
			wg.Wait()
			post, err := loaded.Marshal()
			if err != nil || !bytes.Equal(post, original) || loaded.generation != built.generation {
				t.Fatalf("loaded post-reader snapshot/generation changed: %v", err)
			}
			builtAfter, err := built.Marshal()
			if err != nil || !bytes.Equal(builtAfter, original) {
				t.Fatalf("original built snapshot changed: %v", err)
			}
		})
	}
}
