# Verification report

**Implemented experimental prototype; NOT release-ready.** Research/handoff date2026-10-23 (Asia/Singapore). Actual receipts use UTC timestamps on2026-10-22, which is the same Singapore calendar day for these runs.

Technical source: `391755f583d10662000e092d181cdce8acc72d6e7ac6e7ca44fbd569dae5da8e`. Local source commit checked: `219000c2277b19c208bb6e8f07e5b044833a2861`. Neither is a hosted-repository publication claim.

## What actually ran
| Check | Actual outcome | Scope |
|---|---|---|
| `make verify` | PASS, exit0 | Build, formatting, Go vet/type compilation, Go unit tests,6 Python integration/tooling tests, race, mutations, demo, smoke,1,000-case oracle, both bounded fuzz campaigns, targeted public audit |
| `make clean-verify` | PASS, exit0 | Fresh committed local clone with separate build caches; build, lint/type checks, tests, integration and demo |
| Independent exhaustive oracle |1,000 seeded cases matched | IDs/order and float64 distances after float32 conversion; finite exact semantics, not ANN recall |
| Targeted defect controls |4 PASS-FAIL-PASS controls | Tenant selection, filter bypass, final exact-label exhaustion and budget overspend; not a whole-program mutation score |
| Locked-spec controls |2 PASS-FAIL-PASS checks | Acceptance and phase-definition edits are detected, then restored |
| Smoke benchmark |21 cells,672 timed samples |512 vectors,8 dimensions,one seed,uniform/independent data; not full/reference workload |
| Smoke metric recalculation |PASS | Rebuilt exact eligible IDs and recomputed recall/work/p95 and query/repetition coverage without benchmark/oracle helper reuse |
| Browser review |BLOCKED | File and ordinary loopback navigation returned ERR_BLOCKED_BY_ADMINISTRATOR; no screenshots or keyboard/layout results claimed |

**All executable Go checks above used Go1.23.2 on Linux x86_64, with Python3.13.5.** The pinned reference is Go1.27.3. A verified-current-toolchain download attempt failed DNS here. Compatible source execution is useful developmental evidence, not supported-toolchain or current-security qualification.

Raw logs/receipts are in [published evidence](verification/published/README.md). The source hash covers technical code/config/fixtures/locked behavior; documentation/export changes do not imply that a new source implementation was exercised. This report does not assert a live CI pass.

## Failures preserved rather than hidden
An early intermediate exactness mutation survived because a later safety check corrected its value. The actual failing run is retained privately. The control was replaced with a final observable boundary defect and the unchanged assertions then detected it; all four controls passed after restoration. An earlier fuzz wrapper was interrupted before a final receipt; its output is not treated as a valid completed receipt. The later final-core run captured both completed campaigns and the real exit code.

The current security-online command requires an installed verified scanner and may fail NOT RUN. The release gate deliberately refuses unsupported runtime and missing criteria. Neither a scanner absence nor a blocked browser is quietly converted to PASS.

## Criterion assessment
| Criterion | Status | Qualification |
|---|---|---|
| AC-001 | PASS | Command-level PASS on Linux/Go1.23.2; current-toolchain release qualification is separate. |
| AC-002 | PASS | Command-level PASS on Linux/Go1.23.2; current-toolchain release qualification is separate. |
| AC-003 | PASS | Command-level PASS on Linux/Go1.23.2; current-toolchain release qualification is separate. |
| AC-004 | PASS | Command-level PASS on Linux/Go1.23.2; current-toolchain release qualification is separate. |
| AC-005 | PASS | Command-level PASS on Linux/Go1.23.2; current-toolchain release qualification is separate. |
| AC-006 | PASS | Command-level PASS on Linux/Go1.23.2; current-toolchain release qualification is separate. |
| AC-007 | PASS | Command-level PASS on Linux/Go1.23.2; current-toolchain release qualification is separate. |
| AC-008 | PASS | Command-level PASS on Linux/Go1.23.2; current-toolchain release qualification is separate. |
| AC-009 | PASS | Command-level PASS on Linux/Go1.23.2; current-toolchain release qualification is separate. |
| AC-010 | PASS | Command-level PASS on Linux/Go1.23.2; current-toolchain release qualification is separate. |
| AC-011 | PASS | Command-level PASS on Linux/Go1.23.2; current-toolchain release qualification is separate. |
| AC-012 | PASS | Command-level PASS on Linux/Go1.23.2; current-toolchain release qualification is separate. |
| AC-013 | PARTIAL | Real CLI/escaped HTML passed; both actual browser navigation attempts were blocked by administrator policy. |
| AC-014 | PASS | Command-level PASS on Linux/Go1.23.2; current-toolchain release qualification is separate. |
| AC-015 | BLOCKED | Both bounded fuzz campaigns passed on Go1.23.2, not the required supported Go1.27.3. |
| AC-016 | PARTIAL | Separate21-cell smoke passed; zero full-grid qualification cells claimed; full5400-cell grid and intended statistical report unrun. |
| AC-017 | NOT_RUN | 10k64-dimensional reference-host recall target not measured. |
| AC-018 | PARTIAL | Explicit public tree/history heuristic scan executed; full independent/current security review remains open. |
| AC-019 | BLOCKED | Fresh committed local checkout passed, but supported-toolchain qualification remains open. |
| AC-020 | PARTIAL | Owned workspace and guard tests checked; actual user-device external allocations and hard quota not verified. |
| AC-021 | NOT_RUN | No genuinely separate read-only reviewer was available; self-checks are not substituted. |
| AC-022 | NOT_RUN | Actual owner technical walkthrough not performed; browser manual usability also incomplete. |
| AC-023 | PASS | Command-level PASS on Linux/Go1.23.2; current-toolchain release qualification is separate. |
| AC-024 | PASS | Command-level PASS on Linux/Go1.23.2; current-toolchain release qualification is separate. |

## Still required
Supported-toolchain re-verification and online security checks; full frozen synthetic grid and predeclared statistical summary; reference-host target; actual browser usability; genuinely independent read-only findings followed by repairs and re-verification; owner understanding; complete attributable-device resource inventory/hard enforcement where needed; final public-source/history audit and authenticated GitHub publication. Optional hnswlib/real-data tracks are not implemented or measured and are not represented as core evidence.

No production users, production traffic, availability SLA, cryptographic snapshot authenticity, arbitrary record ACL enforcement, universal ANN recall or vendor superiority is claimed.

## Final fail-closed checks actually executed
On the final technical source, `make security-online` exited2 because a verified govulncheck was not installed; `make release-verify` exited2 at the supported-toolchain gate; direct `python3 scripts/release_gate.py` exited1 because required criteria/gates are incomplete. Original receipts and command output are retained in verification/published/blocked-gates/. Those are expected unresolved qualification outcomes, not passing security or release results.

## Final fail-closed checks actually executed
On the final technical source, `make security-online` exited2 because a verified govulncheck was not installed; `make release-verify` exited2 at the supported-toolchain gate; direct `python3 scripts/release_gate.py` exited1 because required criteria/gates are incomplete. Original receipts and command output are retained in verification/published/blocked-gates/. Those are expected unresolved qualification outcomes, not passing security or release results.
