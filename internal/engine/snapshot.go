package engine

import (
	"bytes"
	"context"
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
	return validateSnapshotContext(context.Background(), s)
}
func validateSnapshotContext(ctx context.Context, s snapshot) error {
	if err := cancelled(ctx); err != nil {
		return err
	}
	bad := func() error { return fail("E_FORMAT", "invalid snapshot structure") }
	if s.Version != 1 || s.Dimension < 1 || s.Dimension > 256 || s.M < 2 || s.M > 32 || s.EFConstruction < s.M || s.EFConstruction > 4096 || s.BuildBudget < 1 || s.BuildBudget > 200000000 || len(s.Graphs) < 1 || len(s.Graphs) > 64 {
		return bad()
	}
	total := 0
	tenants := map[string]bool{}
	for _, g := range s.Graphs {
		if err := cancelled(ctx); err != nil {
			return err
		}
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
			if err := cancelled(ctx); err != nil {
				return err
			}
			r := g.Records[i]
			if r.Tenant != g.Tenant || !validID(r.ID) || ids[r.ID] || !validVector(r.Vector, s.Dimension) || !validMeta(r.Metadata) || n.Level < 0 || n.Level > 16 || len(n.Edges) != n.Level+1 {
				return bad()
			}
			ids[r.ID] = true
			if n.Level > maxLevel {
				maxLevel = n.Level
			}
			for l, edges := range n.Edges {
				if err := cancelled(ctx); err != nil {
					return err
				}
				cap := s.M
				if l == 0 {
					cap *= 2
				}
				if len(edges) > cap {
					return bad()
				}
				seen := map[int]bool{}
				for _, j := range edges {
					if err := cancelled(ctx); err != nil {
						return err
					}
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
	return cancelled(ctx)
}
func (c *Collection) payload() ([]byte, error) {
	return c.payloadContext(context.Background())
}
func (c *Collection) payloadContext(ctx context.Context) ([]byte, error) {
	if err := cancelled(ctx); err != nil {
		return nil, err
	}
	b, e := json.Marshal(c.data)
	if err := cancelled(ctx); err != nil {
		return nil, err
	}
	if e != nil {
		return nil, fail("E_FORMAT", "cannot encode snapshot")
	}
	if len(b) > MaxSnapshot-48 {
		return nil, fail("E_FORMAT", "snapshot byte limit")
	}
	return b, nil
}
func (c *Collection) identify() error {
	return c.identifyContext(context.Background())
}
func (c *Collection) identifyContext(ctx context.Context) error {
	b, e := c.payloadContext(ctx)
	if e != nil {
		return e
	}
	h := sha256.Sum256(b)
	if err := cancelled(ctx); err != nil {
		return err
	}
	c.generation = hex.EncodeToString(h[:])
	return nil
}
func (c *Collection) Marshal() ([]byte, error) {
	return c.MarshalContext(context.Background())
}
func (c *Collection) MarshalContext(ctx context.Context) ([]byte, error) {
	payload, e := c.payloadContext(ctx)
	if e != nil {
		return nil, e
	}
	h := sha256.Sum256(payload)
	out := make([]byte, 48+len(payload))
	copy(out, []byte("FQIDX001"))
	binary.LittleEndian.PutUint64(out[8:16], uint64(len(payload)))
	copy(out[16:48], h[:])
	copy(out[48:], payload)
	if err := cancelled(ctx); err != nil {
		return nil, err
	}
	return out, nil
}
func LoadBytes(b []byte) (*Collection, error) {
	return LoadBytesContext(context.Background(), b)
}
func LoadBytesContext(ctx context.Context, b []byte) (*Collection, error) {
	if err := cancelled(ctx); err != nil {
		return nil, err
	}
	if len(b) < 48 || len(b) > MaxSnapshot || string(b[:8]) != "FQIDX001" || binary.LittleEndian.Uint64(b[8:16]) != uint64(len(b)-48) {
		return nil, fail("E_FORMAT", "invalid snapshot header")
	}
	hash := sha256.Sum256(b[48:])
	if err := cancelled(ctx); err != nil {
		return nil, err
	}
	if string(hash[:]) != string(b[16:48]) {
		return nil, fail("E_FORMAT", "snapshot digest mismatch")
	}
	var s snapshot
	if strictjson.DecodeContext(ctx, b[48:], MaxSnapshot-48, &s) != nil {
		if err := cancelled(ctx); err != nil {
			return nil, err
		}
		return nil, fail("E_FORMAT", "invalid snapshot JSON")
	}
	if e := validateSnapshotContext(ctx, s); e != nil {
		return nil, e
	}
	col := &Collection{data: s, generation: hex.EncodeToString(hash[:])}
	canonical, err := col.payloadContext(ctx)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(canonical, b[48:]) {
		return nil, fail("E_FORMAT", "snapshot payload must use canonical format-1 encoding")
	}
	for _, g := range s.Graphs {
		if err := g.indexMetadataContext(ctx); err != nil {
			return nil, err
		}
	}
	if err := cancelled(ctx); err != nil {
		return nil, err
	}
	return col, nil
}
func Load(path string) (*Collection, error) {
	return LoadContext(context.Background(), path)
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r contextReader) Read(b []byte) (int, error) {
	if err := cancelled(r.ctx); err != nil {
		return 0, err
	}
	return r.reader.Read(b)
}
func LoadContext(ctx context.Context, path string) (*Collection, error) {
	if err := cancelled(ctx); err != nil {
		return nil, err
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, fail("E_IO", "cannot open snapshot")
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(contextReader{ctx, f}, MaxSnapshot+1))
	if e != nil {
		if err := cancelled(ctx); err != nil {
			return nil, err
		}
		return nil, fail("E_IO", "cannot read snapshot")
	}
	return LoadBytesContext(ctx, b)
}

// Save publishes a new file without overwriting an existing destination. Hard-link
// support is required. File data is synced; Linux also syncs the directory.
func (c *Collection) Save(path string) error {
	return c.SaveContext(context.Background(), path)
}

// SaveContext checks cancellation before the atomic no-clobber link. Successful
// linking is the publication boundary; cancellation after it cannot undo a save.
func (c *Collection) SaveContext(ctx context.Context, path string) error {
	b, e := c.MarshalContext(ctx)
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
	defer f.Close()
	if err := cancelled(ctx); err != nil {
		return err
	}
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
	if err := cancelled(ctx); err != nil {
		return err
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
	SchemaVersion            int    `json:"schema_version"`
	FormatVersion            int    `json:"format_version"`
	Generation               string `json:"generation"`
	Dimension                int    `json:"dimension"`
	M                        int    `json:"m"`
	EFConstruction           int    `json:"ef_construction"`
	Seed                     int64  `json:"seed"`
	BuildBudget              int    `json:"build_budget"`
	BuildDistanceEvaluations *int   `json:"build_distance_evaluations,omitempty"`
	Tenants                  int    `json:"tenants"`
	Records                  int    `json:"records"`
	Edges                    int    `json:"edges"`
	MaxLevel                 int    `json:"max_level"`
}

func (c *Collection) Inspect() Info {
	v := Info{SchemaVersion: 1, FormatVersion: c.data.Version, Generation: c.generation, Dimension: c.data.Dimension, Tenants: len(c.data.Graphs), M: c.data.M, EFConstruction: c.data.EFConstruction, Seed: c.data.Seed, BuildBudget: c.data.BuildBudget}
	if c.buildMeasured {
		used := c.buildDistances
		v.BuildDistanceEvaluations = &used
	}
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
