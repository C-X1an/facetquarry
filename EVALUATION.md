# Evaluation and benchmark plan
TARGETS ARE NOT RESULTS. Initial results are NOT YET MEASURED until machine receipts and raw outputs exist. A development smoke run cannot qualify the full matrix.

## Claims and methods
| Claim | Experiment | Baseline | Failure interpretation |
|---|---|---|---|
| Exact filtered semantics | 1000 small seeded datasets, independent Python float32 conversion then exhaustive float64 L2 | Direct filter+sort, not shared engine code | Any wrong ID/order invalidates correctness |
| Graph quality | Identical fixed queries/eligible sets over five build seeds | Exact eligible top-k | Low recall is an observed limitation, not a test to hide |
| Filtering planner value | Vary correlation/selectivity; separate exact, graph, postfilter, auto | Same corpus and query; hnswlib optional extra | Auto speedup cannot be attributed solely to HNSW |
| Bounded work | Budget sweep including zero and tiny values | Expected arithmetic limit | Counter overshoot or false exact label invalidates control |
| Concurrent safety | 1/4/16 readers and Go race detector | Single-reader answer identity | Any race/result drift blocks concurrency claim |
| Parser resilience | Fixed malformed corpus plus bounded fuzz | Typed error contract | Panic, unbounded allocation or invalid acceptance is a defect |

## Frozen full matrix (schema 1)
Core corpus sizes: 2,000 and 10,000; dimension 64; k=10; build seeds 11,23,47,83,131; M=12; efConstruction=96. Three distributions: uniform independent coordinates, clustered mixtures, duplicate/tie-heavy. Metadata relationship: independent, positive/negative rank correlation with squared distance to the origin; queries are sampled near the origin. Selectivity targets: 100%, 20%, 5%, 1%, 0.1%; retain actual eligible counts (rounding/duplicate bins may differ). AND case: a threshold facet AND ID parity with measured intersection (no independence assumption), never multiply marginal selectivities as ground truth. ef grid 32/128/512; plans exact/graph/postfilter/auto; concurrency 1 primary and 4/16 separate throughput profiles. 200 fixed queries per cell; 20 untimed warmup queries per plan; five timing repetitions with randomized method order. Generate a named grid ID for every expected cell and retain terminal outcomes, including timeout/failure.

Do not fully cross dimensions that are semantically irrelevant (ef does not change exact search); the coverage validator must derive expected cells from the declared config, not from whichever output files exist. Full runs may be executed in serial groups below the disk cap; flush compact per-query JSONL, not duplicate entire indexes per query. Retain sufficient raw inputs/seeds and aggregate bootstrap unit at graph-seed/query level; repeated timings of one query are not independent datasets.

## Ground truth and metrics
Convert input numbers to float32 once in both paths. Independently enumerate eligible IDs and order by (float64 squared L2, ASCII ID). `recall@k = |returned IDs intersect exact IDs| / min(k, eligible count)` for nonempty eligible set. Zero-eligible queries are excluded from mean recall and separately report exact-empty correctness, not quietly scored 100%. Report returned-count deficit, invalid/foreign IDs and filter violations independently. Numerical distance tolerance abs1e-9 + rel1e-12; ties follow the contract, and near-ties are identified rather than relabeled equal.

Per-query latency uses a monotonic clock around search only; process startup/build/parsing are separate end-to-end metrics. Report p50/p95/p99 with sample count and quantile convention, arithmetic mean where appropriate, confidence intervals and all per-seed summaries. Throughput is completed queries per measured interval at fixed concurrency, not reciprocal p50. Build wall time, build-distance count, peak process RSS, serialized bytes and query-distance counts are separate. CPU/profile captures explain hotspots; no extrapolation to production traffic.

## Environment and noise
Record CPU model/count, available RAM, OS/kernel/architecture, Go exact version, source/tree digest, build flags, GOMAXPROCS, power mode when known, corpus hash, query hash, algorithm/options, timestamp and competing workload limitations. Local shared-container timings are observational only, not the named reference host. Warm caches and cold-start results must be labeled separately. Keep unsuccessful runs; investigate noise rather than cherry-picking the fastest. Full performance qualification requires an independent methodology review.

## Upstream and real-data tracks
hnswlib is an optional Apache-2.0 comparator with a pinned release/hash and declared thread count. It uses different numeric/SIMD behavior and filter conventions; compare IDs/recall to our independent exact oracle and disclose k-shortfall exceptions. Its Python callback overhead is not evidence our graph algorithm is intrinsically faster. No ANN library is a product dependency.

Real-data evaluation is optional until provenance/license and compact size are verified. Do not download SIFT, GloVe, LAION or model weights by habit. The reproducible core remains synthetic and explicitly labeled. A separate real-data track may use UCI Wine Quality's 11 numeric attributes with a fixed train/query split and scaling fitted only on training data, if its current CC BY 4.0 provenance is verified. This is a low-dimensional real measurement dataset, NOT a semantic embedding benchmark.

## Raw output and plots
`.local/evidence/<run-id>/` stores command streams privately/ignored. `.local/evidence/run_manifest.jsonl` binds command to source and hashes. Reviewed public exports live under `verification/published/`. Benchmark JSONL includes grid_id, seed, plan, ef, distribution, correlation, selectivity_actual, query_id, eligible, recall, latency_ns, distance_evaluations, status and error. Store configuration once per run. A report table and optional plots read these outputs, never hand-enter values. Plot recall versus distance work and latency on separate axes/figures, with each distribution/filter relationship visible. Do not average away pathological cells.

## Negative controls and independence
Targeted defects: scope uses wrong partition; metadata predicate skipped; exactness incorrectly true on exhaustion; budget charge moved after computation. Use isolated temporary copies and record PASS -> intended FAIL -> restored PASS, confirming the failing assertion, not a compile error. The independent verifier starts read-only and asks what broken implementation could still pass. Its report precedes fixes. Self-review and differential oracle testing are useful but not a substitute for a genuinely separate reviewer.

## Implemented measurement boundary
The current runner computes per-cell mean recall, nearest-rank latency quantiles, distance work, build time, snapshot bytes and native memory metadata, retaining compressed raw samples. Confidence intervals, a plotted comparative report, a complete full-grid run, current-toolchain reference-host qualification and independent methodology review are still pending. They are requirements of the intended evaluation, not observed outcomes. Correlation labels in the generator mean rank relative to origin, not arbitrary semantic correlation or a claim that every query has the same realized selectivity/difficulty.
