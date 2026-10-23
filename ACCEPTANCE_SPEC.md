# Locked acceptance specification

acceptance_spec_locked: true
version: 1.0

These criteria precede product implementation. A receipt establishes a run, not universal correctness. Codex may add stronger checks but cannot weaken/delete these. An objectively mistaken criterion requires a preserved TEST_SPEC_EXCEPTION_<ID>.md, evidence and an independent assessment. A failing performance target is reported as failing rather than converted into a measured success.

## AC-001 - FR-001
Precondition: An empty builder.

Input: Wrong dimensions, duplicate tenant-local IDs, NaN/Inf through library, excessive bounds.

Behavior: Reject before publication.

Expected: Typed error; no usable index.

Tolerance: zero invalid acceptances.

Test level: unit/contract. Evidence: rejection cases and builder state.

## AC-002 - FR-002
Precondition: A fixed authorized tenant.

Input: 1000 generated small datasets and queries including ties/empty filters.

Behavior: Compare to separately implemented exhaustive Python calculation.

Expected: Identical ID order and distances.

Tolerance: abs 1e-9 + rel 1e-12 on float64 accumulation.

Test level: property/differential. Evidence: seeded raw comparisons.

## AC-003 - FR-003
Precondition: A valid corpus and two same-seed builds.

Input: Inspect all graph levels/edges and repeat queries.

Behavior: Original layered graph; no self/duplicate/out-of-range edges; bounded degree; deterministic results.

Expected: Graph validation and same-seed output identity.

Tolerance: zero structural violations.

Test level: unit/property. Evidence: graph validator and source review.

## AC-004 - FR-004
Precondition: Tenant-local metadata postings.

Input: AND filters, absent values, no filters; counts 256 and 257.

Behavior: Eligible set matches direct independent filtering; auto selects disclosed path.

Expected: Exact <=256, graph >256.

Tolerance: zero set/plan mismatches.

Test level: unit/contract. Evidence: posting and planner tests.

## AC-005 - SEC-001
Precondition: Two tenants with same IDs, radically different vectors.

Input: A host-fixed alpha handle; query attempts tenant override.

Behavior: Never access or return beta graph; request field rejected.

Expected: Scoped alpha results or E_INPUT.

Tolerance: zero foreign accesses/results.

Test level: security/integration. Evidence: scope instrumentation and negative control.

## AC-006 - FR-005
Precondition: Any completed method.

Input: exact, graph, postfilter and small budgets.

Behavior: Completeness separate from exactness.

Expected: Graph never claims exact; incomplete exact never claims exact.

Tolerance: zero false exact labels.

Test level: acceptance. Evidence: output receipts.

## AC-007 - PERF-001
Precondition: Query with eligible records.

Input: Budgets 0,1,2,10 and normal value; cached upper/lower distances.

Behavior: Charge before computation; never overspend.

Expected: distance_evaluations <= supplied budget.

Tolerance: zero overspend.

Test level: property/acceptance. Evidence: counter checks and budget mutation.

## AC-008 - REL-001
Precondition: Immutable built/loaded index.

Input: Parallel queries and mutation of original input after Build.

Behavior: Independent query-local state and copied input ownership.

Expected: Stable expected results under Go race detector.

Tolerance: zero races or state changes.

Test level: concurrency/system. Evidence: race log and ownership test.

## AC-009 - FR-006
Precondition: A serialized snapshot.

Input: Roundtrip, truncate every header boundary, corrupt payload, bad edge/level/count/version.

Behavior: Bounded structural/digest validation before acceptance.

Expected: Valid snapshot same answers; invalid returns E_FORMAT.

Tolerance: zero corrupt accepts.

Test level: integration/fuzz. Evidence: loader corpus and roundtrip receipt.

## AC-010 - REL-002
Precondition: A cancelled context or bounded build.

Input: Cancel before/during work, exhaust build budget.

Behavior: Stop computation and refuse success; no partial build publication.

Expected: E_CANCELLED or E_BUDGET; prior file unchanged.

Tolerance: check at each distance and bounded validation loops.

Test level: unit/system. Evidence: cancellation and failed-publication receipts.

## AC-011 - SEC-002
Precondition: CLI boundary.

Input: Duplicate/unknown keys, trailing JSON, wrong case, too deep, >limit, unsupported modes.

Behavior: Strict decode with matching library limits.

Expected: E_INPUT before search.

Tolerance: zero malformed accepts.

Test level: contract/fuzz. Evidence: malformed-input corpus.

## AC-012 - FR-007
Precondition: Fresh built executable.

Input: Actual build/search subprocess with fixed-scope adapter.

Behavior: Read real input and run real Go product, not fixture output.

Expected: Exact and graph outputs from product; tenant override denied.

Tolerance: zero mock substitutions.

Test level: end-to-end. Evidence: subprocess command receipts.

## AC-013 - FR-008
Precondition: Real demo execution.

Input: Allowed query, sparse exact fallback, scope denial, exhausted budget.

Behavior: Generate escaped offline inspector from outputs.

Expected: Report reflects actual outcomes and needs no network.

Tolerance: zero executable payloads or fake screenshots.

Test level: end-to-end/security. Evidence: HTML/source review and actual browser capture.

## AC-014 - NFR-003
Precondition: Clean disposable test copy.

Input: Targeted tenant/filter/exact-label/budget intentional defects.

Behavior: Same critical tests pass, fail for defect, pass after restore.

Expected: Every selected control killed for expected assertion.

Tolerance: zero surviving selected controls.

Test level: mutation. Evidence: PASS/FAIL/PASS commands and source hashes.

## AC-015 - NFR-003
Precondition: Supported toolchain.

Input: Bounded fuzz campaigns against request and snapshot parser.

Behavior: No panic, unbounded accepted allocation or silent corruption.

Expected: Campaign completes and retains discovered corpus.

Tolerance: at least 30 s per target in release workflow.

Test level: fuzz/security. Evidence: real fuzz receipts.

## AC-016 - PERF-002
Precondition: Frozen benchmark matrix and independent exact ground truth.

Input: All defined distributions/selectivities/seeds/methods.

Behavior: Capture raw per-query recall and latency, work/build/RSS; retain failed cells.

Expected: Complete grid or explicit nonqualification.

Tolerance: no missing cell silently omitted.

Test level: performance. Evidence: raw JSONL plus grid coverage validator.

## AC-017 - PERF-003
Precondition: Declared reference environment.

Input: Unfiltered reference cells defined in PRD.

Behavior: Measure recall target separately from implementation correctness.

Expected: Report target PASS/FAIL honestly; no false release performance claim.

Tolerance: mean recall@10 >=0.95 per graph seed.

Test level: performance. Evidence: source-bound reference-host results.

## AC-018 - SEC-004
Precondition: Public export plus proposed history.

Input: Allowlist, secret/PII/license/history scans.

Behavior: Reject private research, credentials, resume, raw private logs or incompatible assets.

Expected: Clean publish candidate.

Tolerance: zero unexplained findings.

Test level: security/release. Evidence: scanner receipts and reviewed export manifest.

## AC-019 - NFR-001
Precondition: Fresh committed checkout on supported toolchain.

Input: Bootstrap, build, format, vet, tests, demo, cleanup.

Behavior: No hidden local packages or services.

Expected: All applicable commands actually execute.

Tolerance: zero undeclared prerequisites.

Test level: clean-environment. Evidence: fresh-checkout receipt.

## AC-020 - NFR-002
Precondition: All project-owned roots and worker reservations.

Input: Threshold unit fixtures plus live workspace scan.

Behavior: Refuse admitted growth beyond conservative cap; inventory external attributable paths.

Expected: Below 15 GB; hard quota status explicitly recorded.

Tolerance: 15,000,000,000 byte total ceiling.

Test level: operations/system. Evidence: disk receipts and OS quota/remote execution record.

## AC-021 - NFR-003
Precondition: Claims, source, tests and machine receipts.

Input: Read-only independent adversarial review before integrator fixes.

Behavior: Classify findings; repair material issues; rerun affected tests.

Expected: No unresolved critical/high findings; limitations visible.

Tolerance: no self-review relabeled independent.

Test level: independent-review. Evidence: separate findings then fixes and rerun.

## AC-022 - NFR-004
Precondition: Release docs and owner walkthrough.

Input: Five-minute trace, numeric/budget/scope explanation, demo keyboard review.

Behavior: Explain structures, missed neighbor and boundaries without unsupported claims.

Expected: Defence checklist and usability review recorded.

Tolerance: no fictitious owner interview.

Test level: manual/review. Evidence: owner or reviewer notes; otherwise NOT RUN.

## AC-023 - SEC-003
Precondition: Core dependency/network inventory.

Input: Run local demo offline; inspect loaded modules and generated HTML.

Behavior: No model calls, service credentials or external assets.

Expected: Local-only product functions.

Tolerance: zero undeclared network paths.

Test level: security/integration. Evidence: dependency list and offline inspection.

## AC-024 - NFR-003
Precondition: Locked canonical files.

Input: Alter immutable manifest/acceptance in disposable copy.

Behavior: Integrity gate detects edits; status/evidence-only updates allowed.

Expected: Unauthorized change fails; no automatic hash rewriting.

Tolerance: zero bypasses in specified controls.

Test level: tooling/negative-control. Evidence: integrity test receipts.
