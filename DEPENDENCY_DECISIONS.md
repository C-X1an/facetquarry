# Dependency decisions
Research as of 2026-10-23. Exact local runtime probes override assumptions about what is installed, not the support policy. Recheck releases/security advisories at execution time.

| Component | Selected/support policy | Purpose/license | Alternatives and rationale | Security/operational cost |
|---|---|---|---|---|
| Go | Reference 1.27.3, official announcement 2026-10-19; supported 1.26.10 fallback only by documented deviation | Original engine and standard-library CLI; BSD-3-Clause toolchain | Rust gives explicit ownership but adds fresh compiler/toolchain/cargo storage; C++ adds memory-safety risk. Go keeps algorithm/concurrency work original and setup small | Pin `.go-version`; GOTOOLCHAIN=local; verify official download SHA; never download an unverified binary |
| Python | Reference 3.14.9 maintenance release 2026-10-21; scripts compatible with supported 3.11+ | Independent reference, fixtures and evidence; PSF license | Full NumPy/dataframe stack not needed for bounded oracle/demo | No pip packages required for core; record actual version and patch status |
| hnswlib | Optional comparison v0.9.0, release page inspected; pin source archive hash at fetch | External ANN baseline only; Apache-2.0 | Faiss (MIT) and Qdrant add larger runtime/setup and are unnecessary for first comparison | Python callback/GIL/SIMD differences must be disclosed; not copied into engine; <=1 GB reserved comparator env |
| Go test/race/fuzz/vet | Bundled with supported Go | Native correctness/concurrency/fuzz/static checks | Extra test frameworks add little here | Race needs supported OS/architecture and C toolchain; absence is BLOCKED, not skipped PASS |
| govulncheck | Resolve current official golang.org/x/vuln release; pin resolved version in scanner lock before execution | Reachability-aware Go vulnerability scan; BSD-3-Clause | Standard library only does not eliminate toolchain vulnerabilities | Network advisory data changes; retain scanner/version/date, do not call a local pattern scan an online vulnerability check |
| GitHub Actions | SHA-pinned official checkout/setup actions; resolve actual release commits, no invented hashes | Reproducible Linux CI | No mandatory local Docker/VM; release runs separate from PR smoke | Read-only permissions, no PR secrets, no privileged self-hosted runner |
| Synthetic fixtures | Generated from fixed seeds; original CC0 data declaration | Default reproducible workloads | No licensed embedding downloads or private data | Counts are synthetic, not users/production scale |
| UCI Wine Quality | Optional compact real-data track; 11 numerical features, CC BY 4.0 verified at UCI | Numeric real-data recall test, not semantic embeddings | Large ANN corpora excluded from core for storage/provenance | Download checksum/attribution; train-only scaling and fixed split; no dependence on ucimlrepo package |

## Freshness conflict encountered
The web renderer returned stale main Go/Python index pages while dated official announcements and release-specific pages were newer. The package therefore records the dated Go 1.27.3 announcement/release-history search result and Python 3.14.9 release page, not the stale index's claim of latest. Runtime bootstrap must fetch current official metadata and compare its version/checksum; if it cannot verify the pinned release, stop that installation, record BLOCKED, and continue code work using a clearly labeled available developer toolchain. Never fabricate the newer compiler or label old-toolchain tests as current-toolchain qualification.

## No unnecessary reimplementation
Use standard cryptographic hashes, JSON tokenization primitives, OS file primitives, heaps and context cancellation. Implement the graph construction/search, pruning, posting intersection and plan semantics ourselves because those are the project's engineering subject. Do not implement new cryptography, a package manager, a web framework, an auth server or a database.

## Source references
S-GO: https://go.dev/doc/devel/release#go1.27.3 and official golang-announce release dated 2026-10-19.
S-PY: https://www.python.org/downloads/release/python-3149/
S-HNSWLIB: https://github.com/nmslib/hnswlib/releases and repository license.
S-UCI: https://archive.ics.uci.edu/dataset/186/wine+quality
S-GOVULN: https://go.dev/security/vuln/
