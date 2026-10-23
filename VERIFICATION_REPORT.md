# Verification report

**Experimental implementation; release qualification is incomplete.** Updated 2026-10-23. Technical source: `c06d3256afde9bb7141f3b787947b920b88967eeb3a52def5f41dc1e1f40ce09`.

The original Go engine is implemented and has undergone independent challenge and repairs. Current command evidence uses pinned **Go 1.27.3 windows/amd64**, Python 3.13.14 and Git 2.52.0. The locked reference platform is Linux; Windows observations do not establish its performance qualification. Older Linux/Go 1.23.2 exports remain historical development evidence.

| Check actually executed | Outcome | Evidence and limits |
|---|---|---|
| `make verify` | PASS, exit 0, 332.65 seconds | [Derived receipt](verification/published/supported-20261023/verify/receipt.json), [stdout](verification/published/supported-20261023/verify/stdout.txt), [stderr](verification/published/supported-20261023/verify/stderr.txt). Build, format, vet, compilation, Go unit/race checks, 28 Python tests, mutation, demo, smoke, oracle, fuzz and public audit. |
| Independent exhaustive oracle | PASS, 1,000 seeded cases | [Summary and cases](verification/published/supported-20261023/oracle/summary.json). Separate Python float32 conversion and exhaustive float64 L2/order calculation. Finite semantic evidence. |
| Intentional engine defects | Four PASS/FAIL/PASS controls | [Mutation record](verification/published/supported-20261023/mutations/summary.json): tenant, filter, exact-label and distance-budget defects fail their expected assertions. |
| Locked-file tampering | Two PASS/FAIL/PASS controls | [Retained control outputs](verification/published/supported-20261023/integrity-controls/summary.json). Acceptance and phase edits fail integrity checks; original bytes restore exactly. |
| Supported-toolchain fuzz | PASS, at least 30 seconds each | Current verification log: query target 134,974 executions; snapshot target 1,301,312 executions. These bounded campaigns do not prove arbitrary-input safety. Interesting corpus remains in the owned cache. |
| Calibrated synthetic smoke | PASS, 21 cells and 672 timed samples | [Coverage](verification/published/supported-20261023/smoke/coverage.json), all raw sample archives and per-cell summaries in the same directory. Concurrency 1, n=512, dimension 8. This is not the frozen full matrix. |
| Real offline inspector | Six real CLI cases PASS | [Generated report](docs/demo/report.html), [trace](docs/demo/trace.json). Dynamic content is escaped. Actual browser visual/keyboard review is BLOCKED. |
| Independent review | Material findings repaired and reassessed | [Findings before fixes and disposition](verification/published/supported-20261023/independent-review.md). Separate reviewers began read-only; root performed dynamic checks. Review conduct was not an OS sandbox. |

The curated receipts replace only local path prefixes and declare original and exported digests. Successful and failed originals remain unchanged in private storage. They are trusted-host execution records, not third-party attestations.

## Failures preserved

The initial supported Windows run failed because a test attempted a symlink without OS privilege. The replacement test uses an actual Windows directory junction while POSIX still tests symlinks. A deliberately executed regression suite reproduced recursive null acceptance, snapshot-generation drift and cancelled CLI success before repairs. A later verification failed because its integrity control restored text with changed newlines; the control now restores exact bytes. [Those failed receipts and streams remain available](verification/published/supported-20261023/failures/).

An earlier Windows timing run produced zero-duration samples because its clock lacked adequate resolution. That run is retained privately and excluded from latency claims. Current native measurements use calibrated QueryPerformanceCounter, retain zero values if observed, and disclose counter-read overhead. Throughput is successful queries divided by an actual measured interval that includes queue/JSON output backpressure, not reciprocal median latency.

## Outstanding qualification

The complete frozen matrix has **5,400 cells and 5.4 million timed query samples**. It has not yet run on the current source. The 10,000-record, 64-dimensional reference recall target, confidence intervals, per-seed comparative report, and separate concurrency 4/16 throughput profiles remain unmeasured. A target failure must be reported as a failure.

A manual Linux evidence workflow implements a 5.5 GB loop-backed filesystem, a real ENOSPC probe, owned SDK/caches, process resource constraints, independent verification/reproduction/scanner stages and failure-artifact retention. Its source has been reviewed; the workflow has not executed. A constrained shared runner must not be described as a dedicated physical reference machine.

The local quota query returned access denied. Full local/external attributable inventory is below the 15 GB limit, but an admission monitor is not a hard quota. Fresh current-source committed reproduction is pending. The current online govulncheck v1.9.0 scan passed with “No vulnerabilities found”; see [receipt](verification/published/supported-20261023/online-security/receipt.json). A [separate current-source read-only security review](verification/published/supported-20261023/security-review.md) found no substantiated new vulnerabilities within its stated scope. Public repository creation/publication is pending final export audit.

Browser automation refused the local inspector file URL under its URL policy. No screenshot or keyboard result is invented and no bypass was attempted. The owner declined the technical walkthrough. AC-013 is PARTIAL and AC-022 remains NOT RUN; neither is silently waived by this report. [All 24 criterion statuses](verification/criterion_status.json) retain the unresolved gates.

No production availability, arbitrary record ACL enforcement, snapshot authenticity, universal ANN recall, hard device quota or vendor-superiority claim is made.
