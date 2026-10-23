# FacetQuarry product requirements
Version 1.0 | Design contract | Research as of 2026-10-23

## Thesis and user
A retrieval engineer needs to understand when a metadata filter makes approximate nearest-neighbor search inaccurate or expensive. FacetQuarry is a bounded, original implementation that exposes that tradeoff. It is not a hosted vector database and does not generate embeddings or language.

Primary users are engineers testing filtered retrieval, maintainers examining algorithmic behavior, and reviewers reproducing claims. The owner must be able to trace a query and explain a missed neighbor, not merely present a dashboard.

## Jobs and user stories
US-001: As a retrieval engineer, build a deterministic index from a small local vector corpus and compare exact and approximate answers on identical eligible data.
US-002: As an application integrator, fix a tenant in trusted host code, accept only query/filter controls from the client, and never let query text expand authority.
US-003: As an evaluator, vary selectivity and correlation independently, see each experiment's configuration and failures, and reproduce the raw measurements.
US-004: As a reviewer, run a small demo without keys, inspect a denial, exact fallback and budget exhaustion, then find the implementation and tests responsible.

## Functional and non-functional requirements
| ID | Requirement |
|---|---|
| FR-001 | Validate bounded finite float32 vectors, IDs, dimensions, metadata and strictly decoded requests before use. |
| FR-002 | Return deterministic exact filtered top-k under squared L2, ties by bytewise ASCII ID. |
| FR-003 | Own an original HNSW implementation: layered construction, best-first search, diversified pruning and bounded degree. |
| FR-004 | Intersect tenant-local equality posting lists and select exact or graph search using a disclosed rule. |
| FR-005 | Report plan, candidate cardinality, distance evaluations, generation, completeness and exactness independently. |
| FR-006 | Build and load immutable versioned snapshots; reject malformed or corrupt snapshots without partial publication. |
| FR-007 | Provide a real CLI and host-fixed scope adapter; client requests cannot select a tenant or filesystem path. |
| FR-008 | Provide an offline escaped inspector generated from real execution and a reproducible demonstration. |
| SEC-001 | Each scope can access only one tenant graph; no global-graph traversal or cross-tenant result. |
| SEC-002 | Reject unknown/duplicate JSON keys, trailing values, excessive nesting/bytes, invalid numbers and unsupported fields. |
| SEC-003 | No network listener, model calls, secrets, external HTML assets or execution of input content in the core. |
| SEC-004 | Publish only allowlisted product source, tests, contracts, synthetic fixtures and reviewed evidence summaries. |
| REL-001 | Concurrent read-only queries do not mutate an index; retain one generation throughout a query. |
| REL-002 | Cancellation aborts with a typed error; compute exhaustion is explicit, never disguised as a complete exact result. |
| REL-003 | A failed build/load leaves prior operator-selected artifacts intact; no automatic in-place migration. |
| PERF-001 | Enforce caller-requested distance budget within a host maximum; count each actual query-vector calculation. |
| PERF-002 | Measure recall, latency, build time, memory and distance work across the frozen workload matrix; retain failures. |
| PERF-003 | Target recall@10 >= 0.95 on the defined unfiltered reference cells; do not promise that target on every filter or budget. |
| NFR-001 | Core installs without third-party runtime modules, GPU, paid API, database or mandatory container. |
| NFR-002 | Keep attributable development storage below 15,000,000,000 bytes using owned paths, admission and hard quota where available. |
| NFR-003 | Provide source-bound machine receipts, independent oracle, negative controls, clean reproduction and honest release gating. |
| NFR-004 | Keep the interface explainable, keyboard-readable, text-first and portable; distinguish supported from merely compiled platforms. |

## Invariants
I-01: A query's tenant graph is chosen before parsing client data and cannot change during execution.
I-02: Every returned ID belongs to that graph and satisfies all requested metadata equalities.
I-03: `exact=true` is emitted only for a completed exhaustive scan of the eligible set (including the empty set).
I-04: `distance_evaluations <= budget`; zero is a real budget, not an alias for unlimited.
I-05: Returned hits have distinct IDs and are ordered by (squared L2 distance, ID).
I-06: Index publication is all-or-nothing; input and returned slices cannot mutate stored vectors/edges.
I-07: Build/query/format identities are retained in evidence; historical receipts never automatically qualify a newer source.

## Core boundaries and defaults
Offline immutable build, one process, CPU, squared Euclidean distance only. Vectors are float32; subtraction and accumulation use float64. Coordinates must be finite and |x| <= 1e15. Dimension 1..256, total records 1..50,000, tenants 1..64, ID/tenant ASCII [A-Za-z0-9_.-] length 1..64, metadata at most 8 pairs (key <=64 ASCII identifier bytes, value <=128 UTF-8 bytes). A query has k 1..100, ef k..4096, budget 0..1,000,000; input JSON <=1 MiB and depth <=32. Dataset/snapshot cap is 128 MiB. Duplicate IDs within a tenant are rejected; identical IDs across tenants are legal.

Build defaults M=12, efConstruction=96, seed=20261023, level cap=16, total build-distance budget=20,000,000 (maximum 200,000,000). Degrees at most 2*M at level zero and M elsewhere; M range 2..32. Sorted IDs followed by a seeded shuffle fix insertion order. The pinned Go toolchain and format identify deterministic output; cross-version bitwise identity is not promised.

Auto planner: exact if eligible count <=256, graph otherwise. This is a disclosed baseline rule, not a learned optimizer. Operator may use exact/graph/postfilter explicitly. Metadata equalities are ANDed. Unknown metadata values yield an empty set. Metadata filters refine relevance within an already authorized tenant; they are NOT arbitrary record ACLs.

## Reliability, performance and scale
TARGET: On a declared 4-vCPU/8-GB CPU reference host, a 10,000 x 64 synthetic corpus, k=10, M=12, efConstruction=96, ef=128 and sufficient budget should achieve mean unfiltered recall@10 >=0.95 over 200 fixed queries and five graph seeds. TARGET p95 query latency <=50 ms is a diagnostic goal, not a universal release promise; report missed targets and hardware differences. All exact finite oracle comparisons must agree under the numeric tolerance in acceptance.

DESIGN CAPACITY is the validated input limits above, not throughput. TESTED CAPACITY is populated only by executed runs. OBSERVED CAPACITY refers to the actual environment. REAL USER/PRODUCTION SCALE is none unless evidence later exists. A 50,000-record input limit does not establish adequate latency at that size.

Linux x86_64 is the reference release platform. Linux arm64, macOS and Windows may compile; runtime support requires their own tests. WSL2 is an option, but its existing VM disk and new allocations must be counted under the user's storage rule.

## Privacy, retention and usability
No telemetry. Synthetic examples only. Delete local datasets through operator-owned paths; no promise of secure erasure from filesystems/backups. Evidence raw output stays private/ignored by default, is capped and scanned before any publication. Keep aggregate public receipts sufficient for reproducibility without copying the resume, tokens or private logs. Demo HTML has meaningful headings, a table caption, visible focus and no color-only verdicts, scripts or external network resources.

## Failure and edge behavior
Empty eligible set: exact empty answer, no distances. Fewer than k eligible: return all found, never invent neighbors. Unknown tenant: typed E_SCOPE. Invalid JSON/limits: E_INPUT. Build budget exhausted: no index published. Query budget exhausted: a possibly partial, ordered eligible answer with `status=budget_exhausted`, `exact=false`. Cancelled query: E_CANCELLED, no successful response. Damaged format/digest: E_FORMAT. Unsupported format: explicit refusal, not best-effort decode. No automatic retry loops.

## Non-goals and optional work
No online insert/delete, WAL, replication, consensus, GPU, SIMD/PQ kernel claim, full SQL, arbitrary ACL predicates, public HTTP service, cryptographic authentication, model API, embeddings service, secure enclave or timing privacy. Optional real-data evaluation and hnswlib comparison do not supply product functionality. Optional two-hop traversal is a separately named experiment, not silently called ACORN conformance. Add components only through an ADR/removal test.
