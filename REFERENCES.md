# Technical references
Accessed 2026-10-23. These sources explain prior art and tooling; they do not validate this implementation.

- Malkov and Yashunin, *Efficient and robust approximate nearest neighbor search using Hierarchical Navigable Small World graphs*, arXiv:1603.09320. https://arxiv.org/abs/1603.09320
- *ACORN: Performant and Predicate-Agnostic Search Over Vector Embeddings and Structured Data*, arXiv:2403.04871. https://arxiv.org/abs/2403.04871
- Qdrant, filtered vector search / ACORN engineering article, August 7, 2026. https://qdrant.tech/articles/filtered-vector-search-acorn/
- hnswlib release history and comparator implementation. https://github.com/nmslib/hnswlib/releases
- Go release policy and release history; Go 1.27.3 published October 19, 2026. https://go.dev/doc/devel/release
- Go fuzzing documentation. https://go.dev/doc/security/fuzz/

FacetQuarry does not claim a novel ANN algorithm, ACORN conformance, a faithful reproduction of upstream benchmarks or superiority over mature libraries. Within-tenant metadata filtering is a relevance feature, not arbitrary record authorization.
