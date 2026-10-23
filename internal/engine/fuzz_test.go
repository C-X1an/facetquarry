package engine

import (
	"context"
	"testing"
)

func FuzzQuery(f *testing.F) {
	f.Add([]byte(`{"vector":[0,0],"k":1,"ef":8,"budget":3,"mode":"graph","filter":{}}`))
	f.Add([]byte(`{"tenant":"beta"}`))
	col, e := Build(context.Background(), fixture(12))
	if e != nil {
		f.Fatal(e)
	}
	s, e := col.Scope("alpha")
	if e != nil {
		f.Fatal(e)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > MaxQuery+1 {
			return
		}
		q, e := DecodeQuery(b)
		if e != nil {
			return
		}
		r, e := s.Search(context.Background(), q)
		if e == nil {
			if r.DistanceEvaluations > q.Budget {
				t.Fatal("budget bypass")
			}
			if r.Exact && r.Status != "complete" {
				t.Fatal("false exact")
			}
		}
	})
}
func FuzzSnapshot(f *testing.F) {
	c, e := Build(context.Background(), fixture(4))
	if e != nil {
		f.Fatal(e)
	}
	b, e := c.Marshal()
	if e != nil {
		f.Fatal(e)
	}
	f.Add(b)
	f.Add([]byte("FQIDX001"))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1<<20 {
			return
		}
		c, e := LoadBytes(b)
		if e != nil {
			return
		}
		if e = validateSnapshot(c.data); e != nil {
			t.Fatal(e)
		}
		for _, g := range c.data.Graphs {
			s, e := c.Scope(g.Tenant)
			if e != nil {
				t.Fatal(e)
			}
			q := query()
			q.Vector = make([]float32, c.data.Dimension)
			q.Mode = "graph"
			q.Budget = 10
			if _, e = s.Search(context.Background(), q); e != nil {
				t.Fatal(e)
			}
		}
	})
}
