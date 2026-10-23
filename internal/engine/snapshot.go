package engine

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"facetquarry/internal/strictjson"
	"io"
	"os"
	"path/filepath"
	"runtime"
)

func validateSnapshot(s snapshot) error {
	bad := func() error { return fail("E_FORMAT", "invalid snapshot structure") }
	if s.Version != 1 || s.Dimension < 1 || s.Dimension > 256 || s.M < 2 || s.M > 32 || s.EFConstruction < s.M || s.EFConstruction > 4096 || s.BuildBudget < 1 || s.BuildBudget > 200000000 || len(s.Graphs) < 1 || len(s.Graphs) > 64 {
		return bad()
	}
	total := 0
	tenants := map[string]bool{}
	for _, g := range s.Graphs {
		if g == nil || !validID(g.Tenant) || tenants[g.Tenant] || len(g.Records) < 1 || len(g.Nodes) != len(g.Records) || g.Entry < 0 || g.Entry >= len(g.Nodes) || g.MaxLevel < 0 || g.MaxLevel > 16 {
			return bad()
		}
		tenants[g.Tenant] = true
		total += len(g.Records)
		if total > MaxRecords {
			return bad()
		}
		ids := map[string]bool{}
		maxLevel := 0
		for i, n := range g.Nodes {
			r := g.Records[i]
			if r.Tenant != g.Tenant || !validID(r.ID) || ids[r.ID] || !validVector(r.Vector, s.Dimension) || !validMeta(r.Metadata) || n.Level < 0 || n.Level > 16 || len(n.Edges) != n.Level+1 {
				return bad()
			}
			ids[r.ID] = true
			if n.Level > maxLevel {
				maxLevel = n.Level
			}
			for l, edges := range n.Edges {
				cap := s.M
				if l == 0 {
					cap *= 2
				}
				if len(edges) > cap {
					return bad()
				}
				seen := map[int]bool{}
				for _, j := range edges {
					if j < 0 || j >= len(g.Nodes) || j == i || seen[j] || g.Nodes[j].Level < l {
						return bad()
					}
					seen[j] = true
				}
			}
		}
		if maxLevel != g.MaxLevel || g.Nodes[g.Entry].Level != maxLevel {
			return bad()
		}
	}
	return nil
}
func (c *Collection) payload() ([]byte, error) {
	b, e := json.Marshal(c.data)
	if e != nil {
		return nil, fail("E_FORMAT", "cannot encode snapshot")
	}
	if len(b) > MaxSnapshot-48 {
		return nil, fail("E_FORMAT", "snapshot byte limit")
	}
	return b, nil
}
func (c *Collection) identify() error {
	b, e := c.payload()
	if e != nil {
		return e
	}
	h := sha256.Sum256(b)
	c.generation = hex.EncodeToString(h[:])
	return nil
}
func (c *Collection) Marshal() ([]byte, error) {
	payload, e := c.payload()
	if e != nil {
		return nil, e
	}
	h := sha256.Sum256(payload)
	out := make([]byte, 48+len(payload))
	copy(out, []byte("FQIDX001"))
	binary.LittleEndian.PutUint64(out[8:16], uint64(len(payload)))
	copy(out[16:48], h[:])
	copy(out[48:], payload)
	return out, nil
}
func LoadBytes(b []byte) (*Collection, error) {
	if len(b) < 48 || len(b) > MaxSnapshot || string(b[:8]) != "FQIDX001" || binary.LittleEndian.Uint64(b[8:16]) != uint64(len(b)-48) {
		return nil, fail("E_FORMAT", "invalid snapshot header")
	}
	hash := sha256.Sum256(b[48:])
	if string(hash[:]) != string(b[16:48]) {
		return nil, fail("E_FORMAT", "snapshot digest mismatch")
	}
	var s snapshot
	if strictjson.Decode(b[48:], MaxSnapshot-48, &s) != nil {
		return nil, fail("E_FORMAT", "invalid snapshot JSON")
	}
	if e := validateSnapshot(s); e != nil {
		return nil, e
	}
	for _, g := range s.Graphs {
		g.indexMetadata()
	}
	return &Collection{s, hex.EncodeToString(hash[:])}, nil
}
func Load(path string) (*Collection, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, fail("E_IO", "cannot open snapshot")
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, MaxSnapshot+1))
	if e != nil {
		return nil, fail("E_IO", "cannot read snapshot")
	}
	return LoadBytes(b)
}

// Save publishes a new file without overwriting an existing destination. Hard-link
// support is required. File data is synced; Linux also syncs the directory.
func (c *Collection) Save(path string) error {
	b, e := c.Marshal()
	if e != nil {
		return e
	}
	dir := filepath.Dir(path)
	f, e := os.CreateTemp(dir, ".fq-*")
	if e != nil {
		return fail("E_IO", "cannot create snapshot temporary")
	}
	temp := f.Name()
	defer os.Remove(temp)
	if _, e = f.Write(b); e != nil {
		f.Close()
		return fail("E_IO", "cannot write snapshot")
	}
	if e = f.Sync(); e != nil {
		f.Close()
		return fail("E_IO", "cannot sync snapshot")
	}
	if e = f.Close(); e != nil {
		return fail("E_IO", "cannot close snapshot")
	}
	if e = os.Link(temp, path); e != nil {
		return fail("E_IO", "cannot publish snapshot; destination must be new and filesystem must support hard links")
	}
	if runtime.GOOS == "linux" {
		d, e := os.Open(dir)
		if e != nil {
			return fail("E_IO", "cannot open output directory after publication")
		}
		e = d.Sync()
		ce := d.Close()
		if e != nil || ce != nil {
			return fail("E_IO", "directory sync failed after publication")
		}
	}
	return nil
}

type Info struct {
	SchemaVersion int    `json:"schema_version"`
	Generation    string `json:"generation"`
	Dimension     int    `json:"dimension"`
	Tenants       int    `json:"tenants"`
	Records       int    `json:"records"`
	Edges         int    `json:"edges"`
	MaxLevel      int    `json:"max_level"`
}

func (c *Collection) Inspect() Info {
	v := Info{SchemaVersion: 1, Generation: c.generation, Dimension: c.data.Dimension, Tenants: len(c.data.Graphs)}
	for _, g := range c.data.Graphs {
		v.Records += len(g.Records)
		if g.MaxLevel > v.MaxLevel {
			v.MaxLevel = g.MaxLevel
		}
		for _, n := range g.Nodes {
			for _, e := range n.Edges {
				v.Edges += len(e)
			}
		}
	}
	return v
}
