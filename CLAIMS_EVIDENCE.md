# Claims and evidence

Latest full-size codec control [40355777329](verification/published/codec-control-40355777329.json) failed during archive encoding at the unchanged 400,000,000-byte output cap, after 927.869 seconds. Measured commit `221ac37115184b228ab86602799e3fab2d2408c8`, source `5b4060b211b6671c4da47609ccfa6cf52edc95364d3ad4fec5bb4d0ad996ef75`, used preset 3 with a 1,800-second deadline. This was not a timeout. All 27,738 originals were unchanged, the 399,990,467-byte partial was safely removed, and residual package bytes were zero.

The 103 bounded progress events show inventory 5.146 seconds and manifest encoding 308.980 seconds; archive encoding reached the 32,000-of-33,366 checkpoint before the cap failure. Input recheck and internal verification were not reached. All 114 metadata ZIP files, complete original/recovered inventories and inverse mapping were independently streamed and hashed. Metadata retention PASS does not establish completed codec verification. Actual 2 GB quota enforcement, 2.1 GB ENOSPC and exact-mount closure passed.

The next codec-only candidate, source `e6f92ba8af4b9c9b93c3b4cdc103638c27ef1f9ae8af5e326ac1221cdd777f3f`, coherently selects the already supported preset 6 with a 64 MiB dictionary and requires those exact manifest parameters. Three focused real tiny-child policy tests passed after preserved initial failures; 72 regression tests ran, 71 passed and one explicit platform skip. Independent read-only findings preceded the edits, and postreview found no material regression. Full-size fit, encoder RAM and completion remain NOT RUN. The 400 MB output cap, 2 GB image, 1,800-second child,1,890-second wrapper, 34-minute step and 60-minute job bounds remain unchanged.

Main reference packaging still uses preset 3 and 720 seconds; a codec-only success would not repair or qualify it. The earlier complete native Python suite at source 5b40 remains FAIL: 222 tests, 4 errors and 7 skips, with stale executable identities correctly rejected and two Windows file operations denied. The new candidate needs supported-toolchain verification, current security review, guest/diagnostic execution and all frozen 1/4/16-reader measurements. Actual browser review and the declined owner walkthrough remain unrun.

Earlier [720-second codec control](verification/published/codec-control-40323015414.json) and [420-second codec control](verification/published/codec-control-40293840858.json) remain preserved with their original failures and source identities. No codec control supplies new engine measurements or a passing repaired-source full benchmark matrix.

Earlier runtime/codec candidate source `53371c28d6cfb4bccaeb56e173d6e13442665945ec412bdbccb6e6ced3d0529d` passed144local controls:137passed and7explicit Windows/platform skips. Independent read-only findings preceded the guest runtime, codec proof export and Windows receipt repairs; RED/GREEN and intermediate failures remain in [the candidate evidence](verification/published/runtime-codec-candidate-20261026.json). Native Make is unavailable (actual exit127); canonical integrity and shell/Python parsing passed. Current supported-toolchain execution, full-size codec, guest smoke, current security scan, repaired full1/4/16 measurements and manual gates remain unqualified.

Current qualification-tooling candidate source `ffe6a722d127d3d392c4b3c49fd1c33f9600b0d39c99c5e5043dab9926f671d1`; the engine repair was previously checked at sourcebb95. The [verification report](VERIFICATION_REPORT.md) distinguishes original failed measurements, scoped repair checks and pending current-source qualification. Earlier sources remain historical.

| Claim | Evidence | Limit |
|---|---|---|
| Original Go graph engine | Source, deterministic graph tests and independent review | No ANN novelty or superiority claim |
| Exact filtered semantics |1000separate exhaustive seeded comparisons | Finite inputs, not universal proof or graph recall |
| Scope/budget/ownership controls | Unit, CLI, race and4intentional defect controls | Trusted host selects tenant; no hostile-process isolation or arbitrary record ACLs |
| Validated snapshots | Structural/canonical/digest/cancellation tests and current fuzz | Corruption checks do not authenticate malicious authors |
| Pinned-toolchain verification at sourcebb95 | [Repaired-source evidence](verification/published/repair-bb95/README.md): Go 1.27.3 Windows `make verify` PASS, 34 Python tests, race, oracle, controls and fuzz; subsequent supported Linux CI passed | New candidate verification and fresh committed reproduction pending |
| Scoped advisory/security checks | Sourcebb95 govulncheck PASS and completed immutable repair diff with zero findings; earlier full baseline retained | New helper/workflow scan pending; bounded/static/advisory scope, not certification |
| Reference environment and proof tooling | Actual four-vCPU/8-billion-byte KVM environment smoke passed; [independent proof/retention controls](verification/published/reference-pipeline-c1/preflight/README.md) preserve RED/GREEN | Environment-only smoke and synthetic descriptor controls do not qualify the current full matrix |
| Full original measurements | [Source4949 results](verification/published/reference-4949/README.md): all 5,400 cells and 5.4 million timed calls, 33 of 45 recall targets PASS and 12 FAIL | Named reference host unverified; current repaired matrix and reader4/16 unrun |
| Duplicate-vector pruning repair | Independent findings before fix; real five-seed RED/GREEN and actual query-path reachability | Focused zero queries do not replace the frozen 200-query matrix or guarantee connectivity |
| Offline inspector | Six actual escaped CLI cases | Browser visual/keyboard review blocked |
| Clean reproduction | Historical source4949 committed Linux reproduction PASS; earlier Windows failure preserved | Current repaired committed reproduction pending; Windows long-path policy denied |
| Public repository | [Published repair and curated evidence](https://github.com/C-X1an/facetquarry), with public tree/history audits | Current tooling publication and final audit pending |
| Resource policy | All declared local/external allocations inventoried below 15 GB; actual remote 5.5-GB volume refused 6 GB with ENOSPC | Local hard quota denied; monitor is not enforcement; future growth needs fresh global admission |
| Owner understanding | Walkthrough declined | NOT RUN; agent explanation is not owner evidence |

Trusted-host receipts can be forged by their owner; inspect original/curated digests and scope. Unfavorable results, failed attempts and missing gates remain visible.

Portable identity and owned-volume repairs were qualified on Linux at source4949. The duplicate-pruning change creates sourcebb95; its Windows verification and online scanner passed. No historical benchmark, scan or clean-checkout result is relabeled as current repair qualification.


Actual reference smoke40124290304 (commit3058/sourceffe6): supported full verification, clean committed Linux reproduction, current online scan and lossless655-member preservation/owned-image cleanup PASS. Guest benchmark FAIL before any native query: complete disk admission timed out120seconds; all21cells retained. See verification/published/reference-pipeline-c2/observation.json. Inventory metadata and ZIP admission repairs have bounded controls; actual rerun, full repaired1/4/16 matrices and manual gates remain unqualified.


Preservation candidate03f15ea3:122local Python controls,118passed/4explicit platform skips; actualLinuxnewgeometry/recovery/current-toolchain/fullmatrix gates NOT RUN. Full40132496594 has zero artifacts and unavailable scientific raw; no recall or coverage result is inferred. See [candidate evidence](verification/published/preservation-candidate-20261025.json).

Subsequent [actual control40227147631](verification/published/preservation-control-20261025.json) at a398/source03f passed supported verification, committed Linux reproduction, online scan, actual2.3GB/1.1GB allocation-denial controls, and complete612-member frozen-image recovery. Overall FAIL: trimmed-Go startup omitted GOROOT before guest boot; zero new guest cells. The intentional2s pack timeout and all originals remain preserved. Full-size codec, repaired full1/4/16 measurements and manual gates remain unrun.
