# Verification report

**Experimental implementation; release qualification remains incomplete.** Updated2026-10-23. Current technical source `e7d2268d8196e614a8cc3b120d47263748e47cb8cd375dfe2cc8f3f27fb6bc03`; audited source commit `4a6d08f163da12f04b0bde963da381d7196f949c`. Presentation/evidence updates are outside this technical digest's documented domain.

The original Go engine is implemented and independently challenged. Current execution uses pinned **Go1.27.3 windows/amd64**, Python3.13.14 and Git2.52.0. Linux x86_64 is the locked reference platform. Older Linux/Go1.23.2 exports remain historical development evidence.

| Actually executed check | Outcome | Evidence and scope |
|---|---|---|
| `make verify` | PASS, exit0,438.23s | [Receipt](verification/published/candidate-e7/core/receipt.json), [stdout](verification/published/candidate-e7/core/stdout.txt), [stderr](verification/published/candidate-e7/core/stderr.txt). Build, format, vet, compile, Go unit/race,33Python tests, controls, demo, smoke, oracle, fuzz, source/history audit. Source unchanged throughout. |
| Independent exhaustive oracle | PASS,1000seeded cases | [Summary](verification/published/candidate-e7/oracle/summary.json) and cases. Separate Python float32 conversion and exhaustive float64 L2/order; finite semantics, not ANN recall. |
| Engine and locked-file controls |4+2PASS/FAIL/PASS controls | [Engine mutations](verification/published/candidate-e7/mutations/summary.json), [integrity controls](verification/published/candidate-e7/integrity-controls/summary.json). Each defect fails its expected assertion; canonical bytes restore exactly. |
| Supported fuzz | PASS,>=30s each | Query target22329executions; snapshot target1094301executions. Interesting corpus remains in owned cache; bounded campaigns are not universal safety proof. |
| Current vulnerability scan | PASS | [govulncheckv1.9.0](verification/published/candidate-e7/online-security/receipt.json) returned “No vulnerabilities found.” This is current advisory coverage, not security certification. |
| Independent security/release review | Completed within declared static scope | [Findings, repairs and limits](verification/published/candidate-e7/independent-review.md). Two current read-only security reviews produced no substantiated vulnerability; all material earlier findings reassessed closed. |
| Synthetic smoke | PASS,21cells/672timed samples | [Coverage](verification/published/candidate-e7/smoke/coverage.json), all sample archives/summaries. n512,dim8,concurrency1. Zero-duration samples:0. This is not the full/reference matrix. |
| Real offline inspector |6real CLI cases | [HTML](docs/demo/report.html), [trace](docs/demo/trace.json). Escaped outcome table and native details; actual browser visual/keyboard review BLOCKED by URL policy. |
| Current committed Windows reproduction | FAIL, source unchanged | [Outer receipt](verification/published/candidate-e7/clean-failed/receipt.json), [nested command](verification/published/candidate-e7/clone-command/receipt.json), [summary](verification/published/candidate-e7/clean-summary.json). Actual nested paths exceed disabled Windows long-path policy; no passing claim. |

Current smoke p50 search ranges across all21cells from5900.0to195900.0ns; p95 from12700.0to1112800.0ns. [Machine-derived observations](verification/published/candidate-e7/smoke-observations.json) retain recall and RSS ranges. The shared Windows host is observational. QueryPerformanceCounter calibration/read overhead is disclosed; zero values remain if observed. Throughput uses actual successful-query count divided by a measured dispatch-to-completion interval including queue/JSON backpressure, not reciprocal p50.

## Failed and interrupted work

Historical failures remain source-bound and visible: initial Windows symlink privilege; reproduced null/cancellation/snapshot defects; newline restoration; fresh Git checkout newline conversion; a native-failure test stopped by resource admission; external Chrome cache eviction during inventory; and current nested Windows maximum paths. The guard was not bypassed, thresholds were not relaxed, tests were not skipped, and no unavailable output was invented. An obsolete verification was explicitly stopped to repair a remaining exception-retention path; incomplete streams and an interruption record remain private. Earlier below-resolution Windows timings remain preserved and excluded from latency claims.

Current Windows `LongPathsEnabled=0`; an actual nonmutating writable-registry-key probe was denied. Enabling that OS policy requires administrator consent. Linux reference reproduction remains automated work. Available nested failures are retained before clone cleanup and remote uploads include test fixtures; missing artifacts caused by failed Windows path creation are explicitly reported.

The earlier security workbench scan was marked failed as obsolete after authorized source repairs; it was not relabeled current. A fresh scan bound to the current commit completed. Total scan token usage is unavailable; no estimate is substituted.

## Outstanding gates

The frozen primary matrix is **5400cells and5.4million timed query samples**. Full matrix, reference10k64 recall target, confidence intervals and per-seed comparative report are NOT RUN. Separate concurrency4/16 profiles are also unmeasured. All cells and failures must be retained; a missed target is a failure, not a success to relabel.

The reviewed manual Linux workflow installs the verified pinned SDK in an owned5.5GB loop filesystem, requires actual ENOSPC refusal, constrains process resources, retains independent verification/reproduction/scanner outcomes and uploads failure evidence. It has not executed. A shared runner with4CPU/8GiB process constraints is not automatically a dedicated4-vCPU/8-GB physical reference host.

Local/external inventory is approximately2.6GB, below the15,000,000,000-byte ceiling. Local quota query was denied; monitoring is not hard enforcement. Remote enforcement must actually execute. Browser file-URL policy denied the actual inspector; no screenshot or keyboard PASS exists. Owner walkthrough was declined and remains NOT RUN. [All24criteria](verification/criterion_status.json) retain incomplete/failed gates.

The new public [C-X1an/facetquarry repository](https://github.com/C-X1an/facetquarry) was created and verified empty before publication. The [post-curation public export/history audit](verification/published/candidate-e7/export-audit.json) passed; source push and hosted CI were pending at this checkpoint. No deployment, live-user, availability, universal recall, arbitrary ACL, snapshot authenticity, hard local quota or vendor-superiority claim is made.
