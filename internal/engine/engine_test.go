package engine

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
)

func TestNestedNullRejected(t *testing.T) {
	queries := []string{
		`{"vector":[null,0],"k":1,"ef":8,"budget":1,"mode":"exact","filter":{}}`,
		`{"vector":[0,0],"k":1,"ef":8,"budget":1,"mode":"exact","filter":{"kind":null}}`,
	}
	for _, input := range queries {
		if _, err := DecodeQuery([]byte(input)); Code(err) != "E_INPUT" {
			t.Fatalf("nested null query accepted: %v", err)
		}
	}
	raw, err := json.Marshal(fixture(1))
	if err != nil {
		t.Fatal(err)
	}
	for _, malformed := range [][]byte{
		bytes.Replace(raw, []byte(`"vector":[0,0]`), []byte(`"vector":[null,0]`), 1),
		bytes.Replace(raw, []byte(`"kind":"even"`), []byte(`"kind":null`), 1),
	} {
		if _, err := DecodeCorpus(malformed); Code(err) != "E_INPUT" {
			t.Fatalf("nested null corpus accepted: %v", err)
		}
	}
	col := mustBuild(t, fixture(1))
	snapshot, err := col.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	malformed := bytes.Replace(snapshot[48:], []byte(`"vector":[0,0]`), []byte(`"vector":[null,0]`), 1)
	if _, err := LoadBytes(reframe(malformed)); Code(err) != "E_FORMAT" {
		t.Fatalf("nested null snapshot accepted: %v", err)
	}
	if _, err := DecodeQuery([]byte(`{"vector":[0,0],"k":1,"ef":8,"budget":1,"mode":"exact","filter":{"kind":""}}`)); err != nil {
		t.Fatalf("legal zero or empty string refused: %v", err)
	}
}

func TestNoncanonicalSnapshotRejected(t *testing.T) {
	col := mustBuild(t, fixture(4))
	raw, err := col.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, raw[48:], "", "  "); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadBytes(reframe(pretty.Bytes())); Code(err) != "E_FORMAT" {
		t.Fatalf("noncanonical snapshot accepted with unstable identity: %v", err)
	}
}

// Cancel only after a full snapshot has been staged, before its atomic publication.
type stagedContext struct {
	context.Context
	directory string
	observed  bool
}

func (s *stagedContext) Err() error {
	paths, _ := filepath.Glob(filepath.Join(s.directory, ".fq-*"))
	for _, p := range paths {
		if st, err := os.Stat(p); err == nil && st.Size() > 0 {
			s.observed = true
			return context.Canceled
		}
	}
	return nil
}
func TestSnapshotCancellationBoundaries(t *testing.T) {
	col := mustBuild(t, fixture(30))
	raw, err := col.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if loaded, err := LoadBytesContext(ctx, raw); loaded != nil || Code(err) != "E_CANCELLED" {
		t.Fatalf("pre-cancelled load: %v", err)
	}
	if data, err := col.MarshalContext(ctx); data != nil || Code(err) != "E_CANCELLED" {
		t.Fatalf("pre-cancelled marshal: %v", err)
	}
	steps := &stepContext{Context: context.Background(), remaining: 8}
	if err := validateSnapshotContext(steps, col.data); Code(err) != "E_CANCELLED" {
		t.Fatalf("validation loop ignored cancellation: %v", err)
	}
	dir := t.TempDir()
	old := filepath.Join(dir, "prior.fq")
	if err := col.Save(old); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(old)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{filepath.Join(dir, "new.fq"), old} {
		staged := &stagedContext{Context: context.Background(), directory: dir}
		if err := col.SaveContext(staged, path); Code(err) != "E_CANCELLED" || !staged.observed {
			t.Fatalf("staged save ignored cancellation: %v, observed=%v", err, staged.observed)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "new.fq")); !os.IsNotExist(err) {
		t.Fatalf("cancelled generation was published: %v", err)
	}
	after, err := os.ReadFile(old)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("prior generation changed")
	}
	paths, err := filepath.Glob(filepath.Join(dir, ".fq-*"))
	if err != nil || len(paths) != 0 {
		t.Fatal("cancelled save left staging files")
	}
}

func fixture(n int) Corpus {
	c := Corpus{SchemaVersion: 1, Dimension: 2, M: 4, EFConstruction: 24, Seed: 17, BuildBudget: 20000000}
	for i := 0; i < n; i++ {
		id := string(rune('a'+i%26)) + string(rune('a'+i/26%26)) + string(rune('a'+i/676))
		kind := "even"
		if i%2 == 1 {
			kind = "odd"
		}
		c.Records = append(c.Records, Record{"alpha", id, []float32{float32(i), float32(i % 7)}, map[string]string{"kind": kind, "group": "all"}})
	}
	return c
}
func query() Query {
	return Query{Vector: []float32{0, 0}, K: 3, EF: 32, Budget: 10000, Mode: "exact", Filter: map[string]string{}}
}
func mustBuild(t *testing.T, c Corpus) *Collection {
	t.Helper()
	v, e := Build(context.Background(), c)
	if e != nil {
		t.Fatal(e)
	}
	return v
}
func mustScope(t *testing.T, c *Collection, tenant string) *Scope {
	t.Helper()
	s, e := c.Scope(tenant)
	if e != nil {
		t.Fatal(e)
	}
	return s
}
func TestExactAndTies(t *testing.T) {
	c := fixture(3)
	c.Records[0].Vector = []float32{1, 0}
	c.Records[1].Vector = []float32{-1, 0}
	c.Records[2].Vector = []float32{4, 0}
	s := mustScope(t, mustBuild(t, c), "alpha")
	r, e := s.Search(context.Background(), query())
	if e != nil {
		t.Fatal(e)
	}
	expected := []Hit{{"aaa", 1}, {"baa", 1}, {"caa", 16}}
	if !reflect.DeepEqual(r.Hits, expected) || !r.Exact || r.Eligible != 3 || r.DistanceEvaluations != 3 {
		t.Fatalf("exact mismatch: %+v", r)
	}
	q := query()
	q.Filter = map[string]string{"kind": "odd", "group": "all"}
	r, e = s.Search(context.Background(), q)
	if e != nil || len(r.Hits) != 1 || r.Hits[0].ID != "baa" {
		t.Fatalf("filter mismatch: %+v %v", r, e)
	}
	q.Filter = map[string]string{"absent": "x"}
	r, e = s.Search(context.Background(), q)
	if e != nil || len(r.Hits) != 0 || r.DistanceEvaluations != 0 || !r.Exact {
		t.Fatalf("empty mismatch %+v %v", r, e)
	}
}
func TestTenantScope(t *testing.T) {
	c := fixture(4)
	c.Records = append(c.Records, Record{"beta", "aaa", []float32{999, 999}, map[string]string{}})
	col := mustBuild(t, c)
	a, e := mustScope(t, col, "alpha").Search(context.Background(), query())
	if e != nil || a.Hits[0].Distance != 0 || a.Eligible != 4 {
		t.Fatalf("alpha boundary %+v %v", a, e)
	}
	b, e := mustScope(t, col, "beta").Search(context.Background(), query())
	if e != nil || b.Hits[0].Distance != 1996002 || b.Eligible != 1 {
		t.Fatalf("beta boundary %+v %v", b, e)
	}
	if _, e = col.Scope("missing"); Code(e) != "E_SCOPE" {
		t.Fatal("missing tenant accepted")
	}
}
func TestBudget(t *testing.T) {
	s := mustScope(t, mustBuild(t, fixture(30)), "alpha")
	for _, mode := range []string{"exact", "graph", "postfilter", "auto"} {
		for _, b := range []int{0, 1, 2, 10, 29, 30, 1000} {
			q := query()
			q.Mode = mode
			q.Budget = b
			r, e := s.Search(context.Background(), q)
			if e != nil {
				t.Fatal(e)
			}
			if r.DistanceEvaluations > b {
				t.Fatalf("overspent: %d > %d", r.DistanceEvaluations, b)
			}
			if b == 0 && (r.Status != "budget_exhausted" || len(r.Hits) != 0) {
				t.Fatalf("zero budget %+v", r)
			}
			if (r.Status == "budget_exhausted" || r.Plan == "graph" || r.Plan == "postfilter") && r.Exact {
				t.Fatalf("false exact: %+v", r)
			}
			if r.Plan == "exact" && b >= 30 && !r.Exact {
				t.Fatalf("complete exact not labeled: %+v", r)
			}
		}
	}
}
func TestGraphDeterminismAndBounds(t *testing.T) {
	c := fixture(300)
	a := mustBuild(t, c)
	b := mustBuild(t, c)
	x, e := a.Marshal()
	if e != nil {
		t.Fatal(e)
	}
	y, e := b.Marshal()
	if e != nil {
		t.Fatal(e)
	}
	if string(x) != string(y) {
		t.Fatal("same seed non-deterministic")
	}
	if a.Inspect().Edges == 0 || a.Inspect().MaxLevel == 0 {
		t.Fatal("fixture must exercise layered edges")
	}
	if e = validateSnapshot(a.data); e != nil {
		t.Fatal(e)
	}
	s := mustScope(t, a, "alpha")
	for _, mode := range []string{"graph", "postfilter"} {
		q := query()
		q.Mode = mode
		q.K = 1
		q.EF = 32
		r, e := s.Search(context.Background(), q)
		if e != nil || len(r.Hits) != 1 || r.Hits[0].Distance != 0 || r.Exact {
			t.Fatalf("graph fixture %+v %v", r, e)
		}
	}
}
func TestPlannerBoundary(t *testing.T) {
	for _, n := range []int{256, 257} {
		s := mustScope(t, mustBuild(t, fixture(n)), "alpha")
		q := query()
		q.Mode = "auto"
		r, e := s.Search(context.Background(), q)
		if e != nil {
			t.Fatal(e)
		}
		want := "exact"
		if n == 257 {
			want = "graph"
		}
		if r.Plan != want {
			t.Fatalf("n=%d plan=%s", n, r.Plan)
		}
	}
}
func TestPostfilterShortfall(t *testing.T) {
	s := mustScope(t, mustBuild(t, fixture(10)), "alpha")
	q := query()
	q.K = 1
	q.Mode = "postfilter"
	q.Filter = map[string]string{"kind": "odd"}
	r, e := s.Search(context.Background(), q)
	if e != nil || len(r.Hits) != 0 {
		t.Fatalf("postfilter must expose shortfall %+v %v", r, e)
	}
	q.Mode = "exact"
	r, e = s.Search(context.Background(), q)
	if e != nil || len(r.Hits) != 1 || r.Hits[0].ID != "baa" {
		t.Fatalf("eligible nearest %+v %v", r, e)
	}
}
func TestInputOwnershipAndConcurrentReaders(t *testing.T) {
	c := fixture(80)
	col := mustBuild(t, c)
	s := mustScope(t, col, "alpha")
	q := query()
	before, e := s.Search(context.Background(), q)
	if e != nil {
		t.Fatal(e)
	}
	c.Records[0].Vector[0] = 9999
	c.Records[0].Metadata["kind"] = "changed"
	var wg sync.WaitGroup
	for j := 0; j < 16; j++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for k := 0; k < 30; k++ {
				r, e := s.Search(context.Background(), q)
				if e != nil || !reflect.DeepEqual(before, r) {
					t.Errorf("ownership/read race %+v %v", r, e)
					return
				}
			}
		}()
	}
	wg.Wait()
}
func TestCancellationAndBuildBudget(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := Build(ctx, fixture(10)); Code(e) != "E_CANCELLED" {
		t.Fatal("cancelled build accepted")
	}
	c := fixture(20)
	c.BuildBudget = 1
	if v, e := Build(context.Background(), c); Code(e) != "E_BUDGET" || v != nil {
		t.Fatal("partial build returned")
	}
	s := mustScope(t, mustBuild(t, fixture(4)), "alpha")
	q := query()
	q.Filter = map[string]string{"absent": "x"}
	if _, e := s.Search(ctx, q); Code(e) != "E_CANCELLED" {
		t.Fatal("cancelled empty query accepted")
	}
}
func TestMalformedCorpus(t *testing.T) {
	cases := []Corpus{fixture(2), fixture(2), fixture(2), fixture(2), fixture(2)}
	cases[0].Records[1].ID = cases[0].Records[0].ID
	cases[1].Records[0].Vector[0] = float32(math.NaN())
	cases[2].Records[0].Vector = []float32{1}
	cases[3].Records[0].Tenant = "../secret"
	cases[4].Dimension = 257
	for i, c := range cases {
		if _, e := Build(context.Background(), c); Code(e) != "E_INPUT" {
			t.Fatalf("malformed corpus %d accepted: %v", i, e)
		}
	}
}
func TestStrictQuery(t *testing.T) {
	good := `{"vector":[0,0],"k":1,"ef":8,"budget":0,"mode":"exact","filter":{}}`
	if _, e := DecodeQuery([]byte(good)); e != nil {
		t.Fatal(e)
	}
	cases := []string{
		`{"vector":[0,0],"k":1,"ef":8,"mode":"exact","filter":{}}`,
		`{"vector":[0,0],"k":1,"ef":8,"budget":1,"budget":2,"mode":"exact","filter":{}}`,
		`{"Vector":[0,0],"k":1,"ef":8,"budget":1,"mode":"exact","filter":{}}`,
		`{"vector":[0,0],"k":1,"ef":8,"budget":1,"mode":"exact","filter":{},"tenant":"beta"}`,
		`{"vector":[0,0],"k":1,"ef":8,"budget":1,"mode":"exact","filter":null}`,
		`{"vector":[1e99,0],"k":1,"ef":8,"budget":1,"mode":"exact","filter":{}}`, good + ` {}`, `null`,
	}
	for i, s := range cases {
		if _, e := DecodeQuery([]byte(s)); Code(e) != "E_INPUT" {
			t.Fatalf("invalid JSON %d accepted", i)
		}
	}
}
func reframe(payload []byte) []byte {
	h := sha256.Sum256(payload)
	b := make([]byte, 48+len(payload))
	copy(b, "FQIDX001")
	binary.LittleEndian.PutUint64(b[8:16], uint64(len(payload)))
	copy(b[16:48], h[:])
	copy(b[48:], payload)
	return b
}
func TestSnapshotValidation(t *testing.T) {
	c := mustBuild(t, fixture(30))
	b, e := c.Marshal()
	if e != nil {
		t.Fatal(e)
	}
	loaded, e := LoadBytes(b)
	if e != nil {
		t.Fatal(e)
	}
	q := query()
	a, _ := mustScope(t, c, "alpha").Search(context.Background(), q)
	d, _ := mustScope(t, loaded, "alpha").Search(context.Background(), q)
	if !reflect.DeepEqual(a, d) {
		t.Fatal("roundtrip changed results")
	}
	damaged := append([]byte(nil), b...)
	damaged[len(damaged)-1] ^= 1
	if _, e := LoadBytes(damaged); Code(e) != "E_FORMAT" {
		t.Fatal("corruption accepted")
	}
	// The digest is not authenticity: a malicious editor can recompute it.
	var state snapshot
	if e = json.Unmarshal(b[48:], &state); e != nil {
		t.Fatal(e)
	}
	state.Graphs[0].Nodes[0].Edges[0] = []int{0}
	p, e := json.Marshal(state)
	if e != nil {
		t.Fatal(e)
	}
	if _, e := LoadBytes(reframe(p)); Code(e) != "E_FORMAT" {
		t.Fatal("valid-digest malformed graph accepted")
	}
	state.Graphs[0].Nodes[0].Edges[0] = []int{}
	state.Graphs[0].Records[0].Tenant = "beta"
	p, _ = json.Marshal(state)
	if _, e := LoadBytes(reframe(p)); Code(e) != "E_FORMAT" {
		t.Fatal("mixed-tenant graph accepted")
	}
}
func TestSaveNeverClobbers(t *testing.T) {
	c := mustBuild(t, fixture(4))
	path := filepath.Join(t.TempDir(), "index.fq")
	if e := c.Save(path); e != nil {
		t.Fatal(e)
	}
	before, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	if e = c.Save(path); Code(e) != "E_IO" {
		t.Fatal("existing destination overwritten")
	}
	after, e := os.ReadFile(path)
	if e != nil || string(before) != string(after) {
		t.Fatal("existing file changed")
	}
}

// A deterministic cancellation source tests mid-loop checks without a timing race.
type stepContext struct {
	context.Context
	remaining int
}

func (s *stepContext) Err() error {
	s.remaining--
	if s.remaining <= 0 {
		return context.Canceled
	}
	return nil
}
func TestMidWorkCancellation(t *testing.T) {
	ctx := &stepContext{Context: context.Background(), remaining: 150}
	if c, e := Build(ctx, fixture(100)); c != nil || Code(e) != "E_CANCELLED" {
		t.Fatalf("mid-build cancellation: %v", e)
	}
	s := mustScope(t, mustBuild(t, fixture(20)), "alpha")
	ctx = &stepContext{Context: context.Background(), remaining: 5}
	if _, e := s.Search(ctx, query()); Code(e) != "E_CANCELLED" {
		t.Fatalf("mid-search cancellation: %v", e)
	}
}
func TestSnapshotHeaderAndSemanticBoundaries(t *testing.T) {
	col := mustBuild(t, fixture(4))
	b, e := col.Marshal()
	if e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 48; i++ {
		if _, e := LoadBytes(b[:i]); Code(e) != "E_FORMAT" {
			t.Fatalf("truncated header %d accepted", i)
		}
	}
	for _, edit := range []func(*snapshot){
		func(s *snapshot) { s.Version = 99 }, func(s *snapshot) { s.Dimension = 0 },
		func(s *snapshot) { s.Graphs[0].Nodes[0].Level = 17 }, func(s *snapshot) { s.Graphs[0].Entry = 999 },
		func(s *snapshot) { s.Graphs[0].Nodes = s.Graphs[0].Nodes[:1] },
		func(s *snapshot) { s.Graphs[0].Nodes[0].Edges[0] = []int{999} },
	} {
		var state snapshot
		if e = json.Unmarshal(b[48:], &state); e != nil {
			t.Fatal(e)
		}
		edit(&state)
		raw, e := json.Marshal(state)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = LoadBytes(reframe(raw)); Code(e) != "E_FORMAT" {
			t.Fatal("malformed valid-digest snapshot accepted")
		}
	}
}
