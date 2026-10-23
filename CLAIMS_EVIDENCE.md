# Claims-to-evidence map
Technical source `391755f583d10662000e092d181cdce8acc72d6e7ac6e7ca44fbd569dae5da8e`. Read VERIFICATION_REPORT.md before using a claim outside this scope.

| Proposed claim | Status | Actual evidence | Forbidden extrapolation |
|---|---|---|---|
| Original Go HNSW builder and search |Implemented; self-inspected |internal/engine/graph.go, search.go; core tests |Novel ANN research or performance superiority |
| Exact filtered answers match separate calculation |Measured developmental |published/oracle + final-core logs:1,000 seeded cases |Proof for every input or graph recall |
| Tenant-scoped selection and budget invariants |Measured finite controls |Unit/integration/race and4 targeted mutation controls |Hostile-code isolation, arbitrary ACLs or audited security |
| Validated immutable snapshots |Implemented and tested |Header/digest/structural/truncation fixtures and roundtrip |Cryptographic authenticity, hardware power-loss certification |
| Concurrent immutable readers |Developmental race check passed |final-core receipt/log |Unlimited concurrency or absence of all races |
| Conditional search quality experiment |Smoke measured |21 cells/672 raw timings, recomputed metrics |Full5400-cell completion,10k64 reference target, production scale |
| Offline demo |Actual executable output |docs/demo/report.html and trace.json |Completed visual/browser accessibility review |
| Fresh reproduction |Developmental local checkout passed |fresh-checkout receipt/details |Supported toolchain or user's untested device |
| Independent review |NOT RUN |No qualified review artifact exists |Calling implementer self-checks independent |
| Public GitHub repo |NOT CREATED HERE |Local source and publication instructions only |Invented live URL, CI badge or deployment |
|15GB hard device cap |Policy + admission tooling; not user-host verified |disk guard fixtures and private resource inventory |Guarantee from a polling monitor alone |

All linked published paths are relative to verification/published/ unless otherwise written. Receipts are trusted-host records, not third-party attestations. Unfavorable recall and failed attempts remain visible. Targets must remain placeholders until actual evidence is available.
