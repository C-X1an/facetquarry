package engine

import (
	"container/heap"
	"context"
	"math"
	"math/rand"
	"sort"
)

type neighbor struct {
	index int
	d     float64
	id    string
}

func less(a, b neighbor) bool {
	if a.d == b.d {
		return a.id < b.id
	}
	return a.d < b.d
}

type frontier struct {
	items []neighbor
	max   bool
}

func (h frontier) Len() int { return len(h.items) }
func (h frontier) Less(i, j int) bool {
	if h.max {
		return less(h.items[j], h.items[i])
	}
	return less(h.items[i], h.items[j])
}
func (h frontier) Swap(i, j int) { h.items[i], h.items[j] = h.items[j], h.items[i] }
func (h *frontier) Push(x any)   { h.items = append(h.items, x.(neighbor)) }
func (h *frontier) Pop() any     { n := len(h.items); v := h.items[n-1]; h.items = h.items[:n-1]; return v }
func sortedNeighbors(h *frontier) []neighbor {
	out := append([]neighbor(nil), h.items...)
	sort.Slice(out, func(i, j int) bool { return less(out[i], out[j]) })
	return out
}

type distanceFn func(int) (float64, error)

// searchLayer permits navigation through ineligible within-tenant bridges.
// Only eligible neighbors enter the bounded result heap. It is still approximate.
func searchLayer(ctx context.Context, g *graph, entry, level, ef int, eligible []bool, get distanceFn) ([]neighbor, error) {
	candidates := &frontier{}
	best := &frontier{max: true}
	seen := make([]bool, len(g.Nodes))
	add := func(i int) error {
		d, err := get(i)
		if err != nil {
			return err
		}
		v := neighbor{i, d, g.Records[i].ID}
		heap.Push(candidates, v)
		seen[i] = true
		if eligible == nil || eligible[i] {
			heap.Push(best, v)
			if best.Len() > ef {
				heap.Pop(best)
			}
		}
		return nil
	}
	if err := add(entry); err != nil {
		return nil, err
	}
	for candidates.Len() > 0 {
		if err := cancelled(ctx); err != nil {
			return nil, err
		}
		cur := heap.Pop(candidates).(neighbor)
		if best.Len() >= ef && less(best.items[0], cur) {
			break
		}
		for _, next := range g.Nodes[cur.index].Edges[level] {
			if seen[next] {
				continue
			}
			seen[next] = true
			d, err := get(next)
			if err != nil {
				return nil, err
			}
			v := neighbor{next, d, g.Records[next].ID}
			if best.Len() < ef || less(v, best.items[0]) || eligible != nil && !eligible[next] {
				heap.Push(candidates, v)
				if eligible == nil || eligible[next] {
					heap.Push(best, v)
					if best.Len() > ef {
						heap.Pop(best)
					}
				}
			}
		}
	}
	return sortedNeighbors(best), nil
}

type builder struct {
	ctx         context.Context
	used, limit int
}

func (b *builder) distance(a, c []float32) (float64, error) {
	if err := cancelled(b.ctx); err != nil {
		return 0, err
	}
	if b.used >= b.limit {
		return 0, fail("E_BUDGET", "build distance budget exhausted")
	}
	b.used++
	return distance(a, c), nil
}
func (b *builder) prune(g *graph, base int, candidates []int, cap int) ([]int, error) {
	list := make([]neighbor, 0, len(candidates))
	seen := map[int]bool{}
	for _, i := range candidates {
		if i == base || seen[i] {
			continue
		}
		seen[i] = true
		d, e := b.distance(g.Records[base].Vector, g.Records[i].Vector)
		if e != nil {
			return nil, e
		}
		list = append(list, neighbor{i, d, g.Records[i].ID})
	}
	sort.Slice(list, func(i, j int) bool { return less(list[i], list[j]) })
	kept := make([]int, 0, cap)
	discard := make([]int, 0, len(list))
	for _, cand := range list {
		if len(kept) == cap {
			break
		}
		diverse := true
		for _, other := range kept {
			d, e := b.distance(g.Records[cand.index].Vector, g.Records[other].Vector)
			if e != nil {
				return nil, e
			}
			if d < cand.d {
				diverse = false
				break
			}
		}
		if diverse {
			kept = append(kept, cand.index)
		} else {
			discard = append(discard, cand.index)
		}
	}
	for _, i := range discard {
		if len(kept) == cap {
			break
		}
		kept = append(kept, i)
	}
	return kept, nil
}
func cloneRecord(r Record) Record {
	out := r
	out.Vector = append([]float32(nil), r.Vector...)
	out.Metadata = make(map[string]string, len(r.Metadata))
	for k, v := range r.Metadata {
		out.Metadata[k] = v
	}
	return out
}

// Build validates and copies caller-owned input, then constructs original HNSW graphs.
// It performs no filesystem I/O and never returns a partial collection.
func Build(ctx context.Context, input Corpus) (*Collection, error) {
	if err := cancelled(ctx); err != nil {
		return nil, err
	}
	c, err := normalizeContext(ctx, input)
	if err != nil {
		return nil, err
	}
	groups := map[string][]Record{}
	for _, r := range c.Records {
		if err := cancelled(ctx); err != nil {
			return nil, err
		}
		groups[r.Tenant] = append(groups[r.Tenant], cloneRecord(r))
	}
	tenants := make([]string, 0, len(groups))
	for t := range groups {
		tenants = append(tenants, t)
	}
	sort.Strings(tenants)
	col := &Collection{data: snapshot{Version: 1, Dimension: c.Dimension, M: c.M, EFConstruction: c.EFConstruction, Seed: c.Seed, BuildBudget: c.BuildBudget, Graphs: []*graph{}}}
	rng := rand.New(rand.NewSource(c.Seed))
	b := builder{ctx: ctx, limit: c.BuildBudget}
	for _, tenant := range tenants {
		records := groups[tenant]
		sort.Slice(records, func(i, j int) bool { return records[i].ID < records[j].ID })
		rng.Shuffle(len(records), func(i, j int) { records[i], records[j] = records[j], records[i] })
		g := &graph{Tenant: tenant, Records: records, Nodes: make([]node, 0, len(records)), Entry: 0, MaxLevel: 0}
		for i, r := range records {
			if err := cancelled(ctx); err != nil {
				return nil, err
			}
			u := rng.Float64()
			for u == 0 {
				u = rng.Float64()
			}
			level := int(math.Floor(-math.Log(u) / math.Log(float64(c.M))))
			if level > 16 {
				level = 16
			}
			edges := make([][]int, level+1)
			for j := range edges {
				edges[j] = []int{}
			}
			g.Nodes = append(g.Nodes, node{level, edges})
			if i == 0 {
				g.MaxLevel = level
				continue
			}
			entry := g.Entry
			get := func(j int) (float64, error) { return b.distance(r.Vector, g.Records[j].Vector) }
			for l := g.MaxLevel; l > level; l-- {
				found, e := searchLayer(ctx, g, entry, l, 1, nil, get)
				if e != nil {
					return nil, e
				}
				entry = found[0].index
			}
			start := level
			if start > g.MaxLevel {
				start = g.MaxLevel
			}
			for l := start; l >= 0; l-- {
				found, e := searchLayer(ctx, g, entry, l, c.EFConstruction, nil, get)
				if e != nil {
					return nil, e
				}
				ids := make([]int, 0, len(found))
				for _, v := range found {
					ids = append(ids, v.index)
				}
				degree := c.M
				if l == 0 {
					degree *= 2
				}
				chosen, e := b.prune(g, i, ids, degree)
				if e != nil {
					return nil, e
				}
				g.Nodes[i].Edges[l] = chosen
				for _, j := range chosen {
					links := append(append([]int(nil), g.Nodes[j].Edges[l]...), i)
					if len(links) > degree {
						links, e = b.prune(g, j, links, degree)
						if e != nil {
							return nil, e
						}
					}
					g.Nodes[j].Edges[l] = links
				}
				if len(found) > 0 {
					entry = found[0].index
				}
			}
			if level > g.MaxLevel {
				g.Entry = i
				g.MaxLevel = level
			}
		}
		if err := g.indexMetadataContext(ctx); err != nil {
			return nil, err
		}
		col.data.Graphs = append(col.data.Graphs, g)
	}
	if err := validateSnapshotContext(ctx, col.data); err != nil {
		return nil, err
	}
	if err := col.identifyContext(ctx); err != nil {
		return nil, err
	}
	if err := cancelled(ctx); err != nil {
		return nil, err
	}
	col.buildDistances = b.used
	col.buildMeasured = true
	return col, nil
}
