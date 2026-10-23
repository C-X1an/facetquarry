// Package engine implements a bounded, immutable, tenant-partitioned ANN experiment.
package engine

import (
	"context"
	"errors"
	"facetquarry/internal/strictjson"
	"math"
	"sort"
	"unicode/utf8"
)

const MaxSnapshot = 128 << 20
const MaxQuery = 1 << 20
const MaxRecords = 50000

type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *Error) Error() string    { return e.Code + ": " + e.Message }
func fail(code, msg string) error { return &Error{code, msg} }
func Code(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return "E_IO"
}
func cancelled(ctx context.Context) error {
	if ctx.Err() != nil {
		return fail("E_CANCELLED", "operation cancelled")
	}
	return nil
}

type Record struct {
	Tenant   string            `json:"tenant"`
	ID       string            `json:"id"`
	Vector   []float32         `json:"vector"`
	Metadata map[string]string `json:"metadata"`
}
type Corpus struct {
	SchemaVersion  int      `json:"schema_version"`
	Dimension      int      `json:"dimension"`
	M              int      `json:"m"`
	EFConstruction int      `json:"ef_construction"`
	Seed           int64    `json:"seed"`
	BuildBudget    int      `json:"build_budget"`
	Records        []Record `json:"records"`
}
type Query struct {
	Vector []float32         `json:"vector"`
	K      int               `json:"k"`
	EF     int               `json:"ef"`
	Budget int               `json:"budget"`
	Mode   string            `json:"mode"`
	Filter map[string]string `json:"filter"`
}
type Hit struct {
	ID       string  `json:"id"`
	Distance float64 `json:"distance"`
}
type Response struct {
	SchemaVersion       int    `json:"schema_version"`
	Generation          string `json:"generation"`
	Plan                string `json:"plan"`
	Status              string `json:"status"`
	Exact               bool   `json:"exact"`
	Eligible            int    `json:"eligible"`
	DistanceEvaluations int    `json:"distance_evaluations"`
	Hits                []Hit  `json:"hits"`
}
type node struct {
	Level int     `json:"level"`
	Edges [][]int `json:"edges"`
}
type graph struct {
	Tenant   string   `json:"tenant"`
	Records  []Record `json:"records"`
	Nodes    []node   `json:"nodes"`
	Entry    int      `json:"entry"`
	MaxLevel int      `json:"max_level"`
	postings map[string]map[string][]int
}
type snapshot struct {
	Version        int      `json:"version"`
	Dimension      int      `json:"dimension"`
	M              int      `json:"m"`
	EFConstruction int      `json:"ef_construction"`
	Seed           int64    `json:"seed"`
	BuildBudget    int      `json:"build_budget"`
	Graphs         []*graph `json:"graphs"`
}
type Collection struct {
	data       snapshot
	generation string
}
type Scope struct {
	g          *graph
	dimension  int
	generation string
}

func (c *Collection) Scope(tenant string) (*Scope, error) {
	for _, g := range c.data.Graphs {
		if g.Tenant == tenant {
			return &Scope{g, c.data.Dimension, c.generation}, nil
		}
	}
	return nil, fail("E_SCOPE", "unknown tenant")
}
func validID(s string) bool {
	if len(s) < 1 || len(s) > 64 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.') {
			return false
		}
	}
	return true
}
func validMeta(m map[string]string) bool {
	if m == nil || len(m) > 8 {
		return false
	}
	for k, v := range m {
		if !validID(k) || len(v) > 128 || !utf8.ValidString(v) {
			return false
		}
	}
	return true
}
func validVector(v []float32, dim int) bool {
	if len(v) != dim {
		return false
	}
	for _, x := range v {
		f := float64(x)
		if math.IsNaN(f) || math.IsInf(f, 0) || math.Abs(f) > 1e15 {
			return false
		}
	}
	return true
}
func normalize(c Corpus) (Corpus, error) { return normalizeContext(context.Background(), c) }
func normalizeContext(ctx context.Context, c Corpus) (Corpus, error) {
	if c.M == 0 {
		c.M = 12
	}
	if c.EFConstruction == 0 {
		c.EFConstruction = 96
	}
	if c.Seed == 0 {
		c.Seed = 20261023
	}
	if c.BuildBudget == 0 {
		c.BuildBudget = 20000000
	}
	if c.SchemaVersion != 1 || c.Dimension < 1 || c.Dimension > 256 || c.M < 2 || c.M > 32 || c.EFConstruction < c.M || c.EFConstruction > 4096 || c.BuildBudget < 1 || c.BuildBudget > 200000000 || len(c.Records) < 1 || len(c.Records) > MaxRecords {
		return c, fail("E_INPUT", "corpus bounds")
	}
	ids := map[string]map[string]bool{}
	for _, r := range c.Records {
		if err := cancelled(ctx); err != nil {
			return c, err
		}
		if !validID(r.Tenant) || !validID(r.ID) || !validVector(r.Vector, c.Dimension) || !validMeta(r.Metadata) {
			return c, fail("E_INPUT", "record bounds")
		}
		if ids[r.Tenant] == nil {
			ids[r.Tenant] = map[string]bool{}
		}
		if ids[r.Tenant][r.ID] {
			return c, fail("E_INPUT", "duplicate tenant-local ID")
		}
		ids[r.Tenant][r.ID] = true
	}
	if len(ids) > 64 {
		return c, fail("E_INPUT", "tenant limit")
	}
	return c, nil
}
func DecodeCorpus(b []byte) (Corpus, error) {
	var c Corpus
	if strictjson.Decode(b, MaxSnapshot, &c) != nil || strictjson.Required(b, "schema_version", "dimension", "records") != nil {
		return c, fail("E_INPUT", "invalid corpus JSON")
	}
	return normalize(c)
}
func DecodeQuery(b []byte) (Query, error) {
	var q Query
	if strictjson.Decode(b, MaxQuery, &q) != nil || strictjson.Required(b, "vector", "k", "ef", "budget", "mode", "filter") != nil {
		return q, fail("E_INPUT", "invalid query JSON")
	}
	if err := validateQuery(q, len(q.Vector)); err != nil {
		return q, err
	}
	return q, nil
}
func validateQuery(q Query, dim int) error {
	if dim < 1 || dim > 256 || !validVector(q.Vector, dim) || q.K < 1 || q.K > 100 || q.EF < q.K || q.EF > 4096 || q.Budget < 0 || q.Budget > 1000000 || !validMeta(q.Filter) {
		return fail("E_INPUT", "query bounds")
	}
	switch q.Mode {
	case "exact", "graph", "postfilter", "auto":
	default:
		return fail("E_INPUT", "unsupported search mode")
	}
	return nil
}
func distance(a, b []float32) float64 {
	var s float64
	for i, x := range a {
		d := float64(x) - float64(b[i])
		s += d * d
	}
	return s
}
func (g *graph) indexMetadata() {
	g.postings = map[string]map[string][]int{}
	for i, r := range g.Records {
		for k, v := range r.Metadata {
			if g.postings[k] == nil {
				g.postings[k] = map[string][]int{}
			}
			g.postings[k][v] = append(g.postings[k][v], i)
		}
	}
}
func (g *graph) eligible(f map[string]string) []bool {
	out := make([]bool, len(g.Records))
	if len(f) == 0 {
		for i := range out {
			out[i] = true
		}
		return out
	}
	lists := make([][]int, 0, len(f))
	for k, v := range f {
		p := g.postings[k][v]
		if len(p) == 0 {
			return out
		}
		lists = append(lists, p)
	}
	sort.Slice(lists, func(i, j int) bool { return len(lists[i]) < len(lists[j]) })
	current := append([]int(nil), lists[0]...)
	for _, list := range lists[1:] {
		next := make([]int, 0, len(current))
		i, j := 0, 0
		for i < len(current) && j < len(list) {
			if current[i] == list[j] {
				next = append(next, current[i])
				i++
				j++
			} else if current[i] < list[j] {
				i++
			} else {
				j++
			}
		}
		current = next
	}
	for _, i := range current {
		out[i] = true
	}
	return out
}
