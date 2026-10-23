# Requirement-to-test matrix

Command-level developmental results are in VERIFICATION_REPORT.md. The table defines verification paths, not automatic release PASS. Mock-only output cannot satisfy real integration criteria.

| Requirement | Criterion | Test/source | Command or method | Negative control / qualification |
|---|---|---|---|---|
| FR-001 | AC-001 | internal/engine/engine_test.go | TestMalformedCorpus and input rejection | bad dimensions/finite values |
| FR-002 | AC-002 | scripts/oracle.py | make property | separate Python exhaustive calculation |
| FR-003 | AC-003 | internal/engine/engine_test.go | graph/deterministic tests | structural edge/degree checks |
| FR-004 | AC-004 | internal/engine/engine_test.go | filter/planner tests | direct eligible-set filtering |
| SEC-001 | AC-005 | internal/engine/engine_test.go; tests/test_cli.py | scope tests and request rejection | tenant-selection mutation |
| FR-005 | AC-006 | internal/engine/engine_test.go | exactness/completion tests | final exact-label mutation |
| PERF-001 | AC-007 | internal/engine/engine_test.go | budget boundary tests | off-by-one budget mutation |
| REL-001 | AC-008 | internal/engine/engine_test.go | make race | input deep-copy and parallel query invariants |
| FR-006 | AC-009 | internal/engine/engine_test.go; fuzz_test.go | snapshot corrupt/semantic/truncation tests | valid-digest invalid graph fixtures |
| REL-002 | AC-010 | internal/engine/engine_test.go | cancel/buildbudget/publication tests | deterministic mid-work cancellation |
| SEC-002 | AC-011 | internal/strictjson/decode_test.go; tests/test_cli.py | strict JSON tests | duplicate, unknown, trailing, invalid UTF8/depth |
| FR-007 | AC-012 | tests/test_cli.py | make integration | real subprocess failures and batch lines |
| FR-008 | AC-013 | scripts/demo.py | make demo; real browser review | HTML escape fixture; actual keyboard/viewport review still NOT RUN |
| NFR-003 | AC-014 | scripts/mutation.py | make mutation | four PASS-FAIL-PASS controls; equivalent historical mutant retained |
| NFR-003 | AC-015 | internal/engine/fuzz_test.go | make fuzz with supported toolchain | bounded campaigns; old toolchain is developmental only |
| PERF-002 | AC-016 | scripts/benchmark.py; benchmarks/grid.json | make benchmark | frozen expected-cell ledger; retain failures/missing cells |
| PERF-003 | AC-017 | scripts/benchmark.py | reference host target subset | per-seed exact oracle and recall threshold; NOT YET MEASURED |
| SEC-004 | AC-018 | scripts/public_audit.py | make security plus current scanner/license review | allowlist, private paths, historical blobs; scanner not installed here |
| NFR-001 | AC-019 | scripts/clean_verify.py | make clean-verify | fresh committed clone; supported toolchain separately required |
| NFR-002 | AC-020 | scripts/disk_guard.py; tests/test_tooling.py | make disk plus external allocation inventory | 10/12/15GB boundaries; OS quota NOT verified |
| NFR-003 | AC-021 | independent reviewer packet in control | read-only findings then integrator repair | separate actor; NOT RUN here |
| NFR-004 | AC-022 | docs/PORTFOLIO_DEFENCE_MAP.md | actual owner/browser walkthrough | human understanding cannot be generated |
| SEC-003 | AC-023 | go.mod; scripts/demo.py | offline core/source inspection | no ANN module/model/network dependency |
| NFR-003 | AC-024 | scripts/check_integrity.py; integrity_negative.py | make integrity mutation | mutate acceptance/phase definitions; detect then restore |
