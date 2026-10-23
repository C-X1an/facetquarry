package engine

import (
	"context"
	"sort"
)

type workspace struct {
	ctx          context.Context
	g            *graph
	query        []float32
	budget, used int
	cache        map[int]float64
}

func (w *workspace) get(i int) (float64, error) {
	if err := cancelled(w.ctx); err != nil {
		return 0, err
	}
	if d, ok := w.cache[i]; ok {
		return d, nil
	}
	if w.used >= w.budget {
		return 0, fail("E_BUDGET", "query distance budget exhausted")
	}
	w.used++
	d := distance(w.query, w.g.Records[i].Vector)
	w.cache[i] = d
	return d, nil
}

// Search reads one immutable tenant generation. Callers must not mutate query slices
// concurrently with a call. No index-owned mutable memory is exposed in the result.
func (s *Scope) Search(ctx context.Context, q Query) (Response, error) {
	r := Response{SchemaVersion: 1, Generation: s.generation, Status: "complete", Hits: []Hit{}}
	if err := cancelled(ctx); err != nil {
		return r, err
	}
	if err := validateQuery(q, s.dimension); err != nil {
		return r, err
	}
	eligible, err := s.g.eligibleContext(ctx, q.Filter)
	if err != nil {
		return Response{}, err
	}
	for _, yes := range eligible {
		if err := cancelled(ctx); err != nil {
			return Response{}, err
		}
		if yes {
			r.Eligible++
		}
	}
	r.Plan = q.Mode
	if r.Plan == "auto" {
		if r.Eligible <= 256 {
			r.Plan = "exact"
		} else {
			r.Plan = "graph"
		}
	}
	// Empty eligibility is itself an exhaustive exact result, disclosed as exact plan.
	if r.Eligible == 0 {
		r.Plan = "exact"
		r.Exact = true
		return r, cancelled(ctx)
	}
	w := workspace{ctx: ctx, g: s.g, query: q.Vector, budget: q.Budget, cache: map[int]float64{}}
	if r.Plan == "exact" {
		for i, yes := range eligible {
			if err := cancelled(ctx); err != nil {
				return Response{}, err
			}
			if yes {
				_, err = w.get(i)
				if err != nil {
					break
				}
			}
		}
		r.Exact = err == nil
	} else {
		entry := s.g.Entry
		for l := s.g.MaxLevel; l > 0; l-- {
			var found []neighbor
			found, err = searchLayer(ctx, s.g, entry, l, 1, nil, w.get)
			if err != nil {
				break
			}
			entry = found[0].index
		}
		if err == nil {
			mask := eligible
			if r.Plan == "postfilter" {
				mask = nil
			}
			_, err = searchLayer(ctx, s.g, entry, 0, q.EF, mask, w.get)
		}
	}
	if err != nil {
		if Code(err) != "E_BUDGET" {
			return Response{}, err
		}
		r.Status = "budget_exhausted"
		r.Exact = false
	}
	if err := cancelled(ctx); err != nil {
		return Response{}, err
	}
	results := make([]neighbor, 0, len(w.cache))
	for i, d := range w.cache {
		if err := cancelled(ctx); err != nil {
			return Response{}, err
		}
		if eligible[i] || r.Plan == "postfilter" {
			results = append(results, neighbor{i, d, s.g.Records[i].ID})
		}
	}
	sort.Slice(results, func(i, j int) bool { return less(results[i], results[j]) })
	if len(results) > q.K {
		results = results[:q.K]
	}
	for _, v := range results {
		if eligible[v.index] {
			r.Hits = append(r.Hits, Hit{v.id, v.d})
		}
	}
	r.DistanceEvaluations = w.used
	if err := cancelled(ctx); err != nil {
		return Response{}, err
	}
	return r, nil
}
