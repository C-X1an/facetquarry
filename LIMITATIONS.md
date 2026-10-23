# Deliberate limitations
This is an experimental CPU-only local engine, not a production vector database or a newly invented ANN algorithm. The product claims no live users, production scale, universal speedup, security certification or proof of HNSW correctness.

Only squared L2, finite bounded float32 vectors, string-equality AND filters, immutable offline generations and host-fixed tenant partitions are supported. No online updates, deletions, distributed replication, WAL, arbitrary SQL, embeddings API, GPU, compression or native code plugins are included.

Approximate search can miss true nearest eligible neighbors. An apparently full result set is not proof of recall. Auto may choose exact search; do not attribute that answer to approximate graph quality. Distance budgets are logical work caps, not hard operating-system CPU/RAM quotas. Snapshot hashes are not authentication. Per-tenant graphs do not hide data from the process owner and do not implement per-record ACLs or timing privacy.

A disk monitor alone cannot mathematically prevent a short write burst exceeding a threshold. The 15 GB absolute requirement needs an OS-enforced quota/container volume limit or remote execution for growth-heavy tasks. Default local work is designed to remain far below it, but do not assert quota enforcement where it was not configured.

See VERIFICATION_REPORT.md for what actually ran and what remains incomplete. Historical receipts apply only to their source identity. Synthetic observations cannot be described as real embedding or production workloads. Public release qualification requires the outstanding full matrix, reference environment, browser and manual gates, not just a green unit suite.

The engine package is internal to this module and exercised through the real CLI/tests. No separately versioned, externally importable Go SDK has been published. The earlier hosted browser was blocked by administrator navigation policy. Current browser-review status is recorded separately; generated HTML alone is not a graphical review.
