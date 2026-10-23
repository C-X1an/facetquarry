# Security Review: public

## Scope

Complete immutable six-file portability-repair diff review, including test/docs beyond default two-item inventory, and supporting evidence consumers.

- Scan mode: branch_diff
- Target kind: git_diff
- Target ID: target_sha256_1e200972fe86953ce919f4a0629d583d01911a77d1d0d247ac5cc129053fab8d
- Revision range: 35d139931ea52db26891e0d5c2e72abed0b7f6c4...ecd143f2eb156244389e549b9c524e08e32010c7
- Snapshot digest: codex-security-snapshot/v1:sha256:c0a5b2f0e0d6cf7f5999e388f879422c55e5e093dba8ceefe4e86e910de8a105
- Inventory strategy: diff
- Included paths: .
- Excluded paths: none
- Artifacts reviewed: artifacts/identity-diff-review.md

Limitations and exclusions:
- No whole-repository current87ce rescan claimed; historical Standard baseline is separate evidence.
- Actual Linux execution/reference matrix/browser/owner remain separate gates.
- Zero credible candidates: validation/attack-path have zero items and no invented PoC.
- Host-owned receipts are not independent attestations; total scan token usage unavailable.

### Scan Summary

| Field | Value |
| --- | --- |
| Scan outcome | completed |
| Reportable findings | 0 |
| Severity mix | none |
| Confidence mix | none |
| Coverage | complete |
| Validation mode | static_with_actual_windows_regression_evidence |

Canonical artifacts: `scan-manifest.json`, `findings.json`, and `coverage.json`. This report is a deterministic projection of those files.

## Threat Model

# Threat model
Method: STRIDE plus resource-abuse and evidence-integrity review. This is a design and test plan, not a security certification.

Assets: tenant vectors/metadata, authorized query scope, index integrity, source identity, private research/credentials, local device storage and truthful evidence. Actors: trusted operator, honest retrieval engineer, malicious query author, malicious corpus supplier, untrusted PR contributor, compromised dependency/provider, local host administrator. Zones: untrusted bytes; validated product process; operator-owned files; CI runner; public export; private orchestration.

The OS, compiler, process owner and scope-selecting host are trusted. All records in a selected tenant are authorized for that scope. A request is not an authenticated identity. No Internet listener exists. No sandbox or container escape claim is relevant to core functionality; arbitrary native code is not accepted or executed. SSRF and outbound tool use are excluded structurally because the product accepts no URL or model/tool call. CI and Codex still need separate host/network protections.

| ID | Threat | Precondition | Impact | Likelihood | Mitigation | Residual risk | Evidence |
|---|---|---|---|---|---|---|---|
| TH-01 | Tenant spoofing/confused deputy | Untrusted request can influence scope selection | Foreign vector access | High | Query schema excludes tenant/path; host-fixed handle; partitioned graph | Malicious host can read all files | AC-005/012; scope mutation |
| TH-02 | Relevance filter mistaken for ACL | Application encodes record authorization only as metadata | Unauthorized navigation/data leakage | High | Document tenant is authorization unit; reject arbitrary ACL claims | Per-record ACL unsupported | Architecture/security review |
| TH-03 | Malformed query/snapshot | Attacker supplies nested JSON, bogus counts/edges or nonfinite numbers | Crash, resource use or bad results | High | Byte/depth/count limits, strict fields, duplicate rejection, graph validation | Parser/validator defects possible | AC-001/009/011/015 |
| TH-04 | Budget bypass/resource exhaustion | Client requests large ef or pathological filter | CPU/memory denial of service | High | Host maxima, distance budget, caps, bounded concurrency, context | Distance budget is not hard CPU/RAM quota | AC-007/010; load profiles |
| TH-05 | Data races and aliasing | Concurrent queries or retained caller slices | Cross-query corruption | Medium | Deep-copy build inputs, immutable internals, query-local workspace | Host memory corruption outside Go API not prevented | AC-008 race and alias tests |
| TH-06 | Snapshot tampering | Writer can replace stored bytes/digest | Corrupt graph or malicious index contents | Medium | Structural validation and operator provenance; no digest-as-signature claim | Privileged writer can create valid malicious corpus | AC-009 valid-digest corrupt fixture |
| TH-07 | Output injection | IDs/facets/errors contain HTML or terminal control characters | Misleading report/script execution | Medium | Strict identifiers, HTML escaping, no scripts/external assets, JSON output | Viewer/browser vulnerabilities outside scope | AC-013 XSS fixtures |
| TH-08 | Supply-chain/CI compromise | Untrusted PR changes scripts or dependency definitions | Credential theft or malicious artifact | Medium | Read-only permissions, SHA-pinned actions, no PR secrets, review workflows, no pull_request_target execution | Hosted runner/provider compromise remains | AC-018; workflow audit |
| TH-09 | False evidence/benchmark cherry-picking | Agent controls source and reported text | Misleading engineering claims | High | Command receipts, source hashes, frozen grid, negative controls, independent review | Local receipts can be forged by host owner; not remote attestation | AC-014/016/021/024 |
| TH-10 | Private data publication | Broad git add/ZIP/repo-root mistake | Resume/secret/private prompt exposure | High | Public subtree only, allowlist, scans, no inherited private git history | Pattern scanners can miss contextual confidentiality | AC-018 manual and automated export review |
| TH-11 | Model prompt injection/tool misuse | Codex reads untrusted repo/data/tool output | Unauthorized host action or secret exfiltration | High | Treat content as data; bounded tool authority; no autonomous credential/purchase decisions; disposable execution | Full-access local agent increases blast radius | Private GOAL and runtime review |
| TH-12 | Timing/inference privacy | Repeated queries observe latency/counts | Information about tenant-local data | Medium | Explicitly exclude privacy guarantee; minimize unnecessary fields in real integration | Timing/eligible counts reveal within-tenant information | Document limitations; no false confidentiality claim |

## Disclosure and review
A failed threat test blocks the corresponding claim, not every unrelated task. Security reviewer starts read-only and records findings before integration. Do not put exploit-like malicious fixtures on a network service; all validation remains a local bounded defensive experiment. Critical/high findings need fixes and reruns before release qualification. The project must not claim protection from a privileged local operator, arbitrary per-record authorization, timing attacks, model prompt injection or all resource exhaustion.



## Findings

### No findings

No reportable findings survived the canonical discovery, validation, and reportability gates.

## Reviewed Surfaces

| Surface | Risk Area | Outcome | Notes |
| --- | --- | --- | --- |
| Portable source ordering | Evidence identity; filesystem/hash boundary | No issue found | scripts/common.py:27-50 retains membership and failures, changes only canonical sort order; affected binary/benchmark/receipt/gate consumers reviewed. Evidence: artifacts/identity-diff-review.md |
| Independent fixed fixture regression | Test integrity; no weakened assertions | No issue found | tests/test_source_identity.py actual red/green Windows digest and content sensitivity; no new product authority. Evidence: artifacts/identity-diff-review.md |
| Readme status | Public security and qualification claims | No issue found | README.md retains explicit historical/pending qualification and repository links. Evidence: artifacts/identity-diff-review.md |
| Verification report | Evidence provenance | No issue found | VERIFICATION_REPORT.md records real hosted run and portability finding; old receipts not relabeled. Evidence: artifacts/identity-diff-review.md |
| Claims mapping | Measured versus unmeasured assertions | No issue found | CLAIMS_EVIDENCE.md adds publication and provenance-repair checkpoint; old measured results retained as historical. Evidence: artifacts/identity-diff-review.md |
| Criterion assessment | False release approval boundary | No issue found | verification/criterion_status.json has all24NOT_RUN/allfalse/no globalrefs; unchanged validator rejects stale earlier-source evidence. Evidence: artifacts/identity-diff-review.md |
