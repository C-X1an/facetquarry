# API, data and error contract
Schema version 1; no REST/RPC server is part of core scope.

## Trusted CLI
```sh
facetquarry build --input examples/corpus.json --output .local/index.fq
facetquarry search --index .local/index.fq --tenant alpha --query examples/query.json
facetquarry batch --index .local/index.fq --tenant alpha --queries .local/queries.jsonl
facetquarry inspect --index .local/index.fq
facetquarry version
```
`--tenant`, input/index/output paths and build configuration are trusted operator arguments. Batch is an optional throughput interface with one bounded query object per line and one result envelope per line; a batch implementation must not silently turn line errors into process success without explicit per-line status. Seed implementation status may omit batch until its contract is tested.

## Corpus schema
```json
{"schema_version":1,"dimension":2,"m":12,"ef_construction":96,"seed":20261023,"build_budget":20000000,"records":[{"tenant":"alpha","id":"a1","vector":[0,1],"metadata":{"kind":"guide"}},{"tenant":"beta","id":"a1","vector":[9,9],"metadata":{"kind":"guide"}}]}
```
All root fields are required except build parameters, whose defaults are in PRD. Unknown/duplicate fields are errors, including case variants of canonical keys. Tenant-local IDs are unique. Metadata key/value equality is exact UTF-8 byte equality with no implicit case folding/normalization. Identifier rules and caps are defined in PRD. Input ordering does not determine query tie order.

## Client query schema
```json
{"vector":[0,0],"k":10,"ef":128,"budget":10000,"mode":"auto","filter":{"kind":"guide"}}
```
All controls are explicit in examples. The Go Query type may support defaults only through a separate trusted constructor; the client decoder requires vector/k/ef/budget/mode/filter so omitted budget never means unlimited. `mode` is exact/graph/postfilter/auto. Zero budget is accepted. Client keys `tenant`, `path`, `index`, `command`, `url`, `token` are not supported. Request limit 1 MiB, depth32, one JSON value, no duplicate object keys, exact case. Host maximums are never increased by client input.

## Response
```json
{"schema_version":1,"generation":"<sha256>","plan":"exact","status":"complete","exact":true,"eligible":1,"distance_evaluations":1,"hits":[{"id":"a1","distance":1}]}
```
The example is a contract illustration, not a measured run. `complete` says the selected method terminated normally; only `exact=true` asserts exhaustive eligible-set search. `budget_exhausted` may return zero or more ordered eligible hits and always has exact=false. Graph and postfilter remain exact=false even if a particular run happens to match ground truth. Generation is the deterministic canonical snapshot payload hash for this build. It is content identity, not a signature.

`inspect` returns format/options/counts and graph structural statistics, not vectors or keys. The CLI process owner already has full access; limiting inspect is about avoiding accidental data output, not hiding data from that owner.

## Errors and exits
stderr envelope: `{"error":{"code":"E_INPUT","message":"bounded human-readable explanation"}}`. Do not echo raw input or secrets. Exit0 for a completed response, including explicitly flagged approximate/budget-limited results; exit2 invalid input/scope/format, exit3 cancellation, exit4 build-budget/resource refusal, exit1 unexpected I/O/internal failure. Tool callers must inspect response status and exact flag; exit0 alone does not establish exactness or release qualification.

Errors: E_INPUT, E_SCOPE, E_FORMAT, E_CANCELLED, E_BUDGET, E_IO. No retries inside engine. A caller may rerun a deterministic query against the same immutable generation. Build publication refuses existing output paths; use a new generation filename rather than overwrite. There are no API credentials, environment secrets, remote identifiers, migrations or database indexes. `FQ_WORKSPACE_ROOT` is tooling-only and must point to an owned parent directory, not arbitrary user files.

## Internal contracts
Collection owns tenant->graph mapping. Scope retains one graph plus generation; Search accepts context and immutable Query value. A graph owns records, level lists, entrypoint and postings. No exported method returns internal mutable slices/maps. Search returns copied hit values; cancellation returns an error without a success envelope. Build has no side effects; Save is a separate operator action. Load validates before making any collection available.

## File layout
Snapshot header and validation are specified in ARCHITECTURE.md. `.local/` holds generated disposable indexes/reports; `.cache/` holds owned build caches. Neither is tracked. Public `examples/` contains tiny synthetic JSON only. Evidence raw logs are ignored; reviewed summaries state source and environment. Format1 changes are breaking and require explicit new version/ADR; no automatic repair of a corrupted snapshot.
