# Claims and evidence

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
