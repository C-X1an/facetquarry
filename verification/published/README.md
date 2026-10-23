# Published execution evidence
Technical source: `391755f583d10662000e092d181cdce8acc72d6e7ac6e7ca44fbd569dae5da8e`.

`final-core/` contains the original machine receipt and raw stdout/stderr for `make verify`; `fresh-checkout/` and `fresh-checkout-details/` record a real fresh committed local rebuild. All used **Go1.23.2**; they are developmental, not current-toolchain release qualification. Go1.27.3 remains pinned and unverified here.

`oracle/` retains1,000 seeded case outcomes. `benchmark-smoke/` retains21 cell summaries and672 raw timed query observations over512 vectors of8 dimensions, not the full/reference grid. `smoke-recalculation.json` recomputes those metrics separately without the benchmark/oracle helpers; it is still implementer-led analysis, not the independent reviewer required by AC-021.

`browser-attempts/` records actual administrative navigation denial. There are no browser screenshots or completed keyboard/layout tests. `docs/demo/report.html` comes from real CLI execution and can be inspected in an authorized browser.

Receipts are unchanged exports. Their original `.local/evidence/...` paths describe the execution layout; in this public export the matching stdout/stderr files are adjacent. Hashes can be checked directly. Commit IDs refer to the local audited source checkpoint, not a claim that those commits exist on a hosted repository. The delivered technical-source hash is reproducible with `python3 scripts/common.py`; presentation-only documents/curated exports are outside that hash's stated domain.
