# Independent findings and disposition

This curated record preserves findings received before implementation repairs. Reviewer conduct was read-only; it was not an OS-enforced sandbox.

# Independent read-only first review â€” 2026-10-23

Reviewer: independent_verifier, explicitly selected gpt-6.1-sol, high reasoning, fresh isolated context. Source checkpoint: public commit 4ca0a3015f6153870d898fa6d34bd8ef70b608f5; technical source c7f4926932182520cc1794aaf8ee069d7aa870f9dd285acb27bfd19d7c01e8ab. Findings were delivered before integrator product edits. Review conduct was read-only, not an OS-enforced sandbox claim. All filesystem commands were Get-Content, rg --files, Get-FileHash, and formatting; no edits, tests, builds, installs, network calls, or publication. No findings below are claimed dynamically reproduced by the reviewer.

## Findings

IR-001 HIGH: scripts/release_gate.py:18â€“27 checks evidence status/exit/source only if basename is receipt.json. A digest-correct summary.json can say FAIL or belong to stale source while its criterion is marked PASS. The existing assessment currently fails; the defect is the acceptance path. Regression: otherwise complete fixture with failed, stale, and renamed receipts must be rejected using typed evidence validation.

IR-002 MEDIUM: internal/strictjson/decode.go:86â€“89 accepts null at every type position. Query/corpus numeric null coordinates become zero; null map values become empty strings. Required-root checks do not reject nested null. Regression: E_INPUT for null query/corpus coordinates and filter/metadata values; E_FORMAT for valid-digest malformed snapshots; preserve legal zero and empty strings.

IR-003 MEDIUM: internal/engine/graph.go:279â€“285; snapshot.go:15â€“63,97â€“127,132â€“169; cmd/facetquarry/main.go:106â€“111. Build final validation/identity, Load, Save, and CLI inspect do not observe context. Cancellation can still produce success/publication. Regression: pre-cancelled CLI inspect, deterministic validation cancellation, and pre-publication cancellation with no new destination and unchanged existing destination.

IR-004 MEDIUM: scripts/benchmark.py:63â€“64,106â€“117 skips collecting cached later-group summaries once --limit-cells is reached. Global coverage counts filenames while failed_cells derives only from collected summaries, allowing a later cached failure to disappear. Regression: tiny multi-group resume with last missing early cell plus later cached failure must retain failure and return nonzero.

IR-005 MEDIUM: scripts/benchmark.py:46,66â€“76,85â€“86,103 and cmd/fqbench/main.go. Measurements claim current source without verifying either ignored executable's embedded source; fqbench has none. Regression: build A, change technical source to B, run benchmark directly, refuse before measuring; retain binary hashes and provenance on resume.

IR-006 MEDIUM: snapshot.go:65â€“95,101â€“115 accepts noncanonical JSON and assigns its raw payload hash, while Marshal canonicalizes and changes the generation. Regression: reformat/reorder valid-digest payload, load/marshal/reload, either explicitly reject noncanonical format-1 input or consistently derive canonical generation.

## Coverage and limitations

Reviewed contracts, all internal/engine and internal/strictjson source/tests, both command packages, all Python scripts and tests, Makefile, CI workflow, grid, criteria/locks/phases, verification and claims narratives. Tenant handles statically select one graph, distance work is charged before computation, core dependencies are standard-library only, and the demo escapes output without external assets. These are static observations, not runtime passes.

No dynamic testing, race, fuzz, benchmark, browser, toolchain, history audit, full resource inventory, exhaustive raw-archive review, or independent recalculation was performed. Finite tests do not prove universal graph correctness or release readiness.

Selected reviewed file hashes:
- internal/strictjson/decode.go: 6c63da43a43f23955ec39c0748d54988ac8268434de18d803aad517967a0e954
- internal/engine/snapshot.go: 6ac70e36942d8556484a7758a76c69d2093855801f14ea2a15581ae89e31115d
- scripts/benchmark.py: f25e146752a793f1951c1d525994cffad08513842f236392c9d1eab888154df0
- scripts/release_gate.py: 603527c108b2ae815764ff42e5ce70c375f23ba976b96eaa8b6690fdbd3ee5ae


# Independent release-path review findings before fixes

Reviewer: release_review, fresh read-only gpt-6.1-sol session. Current technical source c52e210c3b3f7c6761630c179930129bb229ea258a6e2f81c5ef2861a2ecdbfa. No source edits, tests, builds, external applications or network requests by reviewer. These findings were received and preserved before integrator repairs.

RR-001 MEDIUM: .github/workflows/release-evidence.yml combines make verify and clean-verify in one `set -e` step, while the scanner uses the default success condition. A failing verify suppresses clean reproduction and the current scanner although those checks can produce useful independent outcomes. Split the steps and use explicit non-cancelled conditions with their own real failures. Benchmark already uses !cancelled().

RR-002 MEDIUM: scripts/benchmark.py obtains disk admission, then unconditionally calls workload/prepare_records and writes active-corpus.json before testing admission status. A refused group still materializes its potentially large corpus. Branch before workload/corpus creation, retain small explicit terminal admission-failure records, and test that refusal never calls the generator or builder.

Review of QPC timing/provenance and remaining paths is in progress. Do not treat this checkpoint as the final independent acceptance disposition.

Final read-only review: no critical/high findings; three P2 findings. RR-003 MEDIUM: job timeout350minutes is below cumulative admitted command time355minutes (1500+600+600+600+18000seconds), before setup/retention. Fit stage budgets within the job deadline with explicit inventory/upload reserve. Reviewed workflow, benchmark/support/common/integrity, native clock/memory/harness and tooling tests. QPC conversion/calibration and labeled throughput were supported in static inspection. Actual remote quota and constraints remain unexecuted. Workflow hash D8C45BB599327BA427E22558CF4AE9345F1CDFCFF6A0B08F5C802B09CA296BE7; benchmark.py hash218D479878E3F142F3DAE1A1E0AE74CE05C35225C0F0B7472DB88646FC112686; fqbench/main.go hash9F8F6EB2BFDE0CF67F5E2685655E1C27A83FE5DECD53A65FEDF95C7C2B3CA89B.


## Reassessment at current source

IR-001 through IR-006 were closed by independent read-only reassessment after typed receipt validation, recursive null rejection, context checks, complete cached-failure collection, executable provenance and canonical snapshot validation were repaired. The reviewer then identified missing native-failure retention, hardware provenance and zero-resolution Windows timing. These were repaired with retained attempts, host records and calibrated QueryPerformanceCounter timing.

RR-001, RR-002 and RR-003 were independently reassessed CLOSED on source `c06d3256afde9bb7141f3b787947b920b88967eeb3a52def5f41dc1e1f40ce09`: independent CI stages survive earlier failure; refused admission does no corpus/oracle/build work; step ceilings total 340 minutes within the 350-minute job. No remaining material issue was found in this reassessment.

Dynamic regression evidence: [supported verification](verify/receipt.json), including 28 Python tests, Go unit/race tests, four expected-assertion defect controls, two byte-exact integrity controls, oracle and bounded fuzzing. Reviewers did not run those checks themselves. Actual remote enforcement, full matrix, browser usability and owner understanding are separate gates.
