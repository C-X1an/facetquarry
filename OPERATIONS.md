# Deployment and operations
Research as of 2026-10-23. Commands describe the required implementation interface; consult VERIFICATION_REPORT.md for their actual execution state. No cloud account or model key is needed for the core.

## Environments
Reference: Linux x86_64, supported Go 1.27.3, Python 3.14.9 (supported 3.11+ script compatibility), Make, Git and a C compiler for race detection. Keep all new toolchains, caches and temporary artifacts under the owned workspace. Existing system toolchains may be reused; inventory any new external allocations attributable to this project.

```sh
cd public
make bootstrap       # Inspect versions, create owned cache dirs; never silently modify global settings.
make build           # Native CLI.
make demo            # Real CLI executions and offline report.
make verify          # Local core checks, not full release qualification.
make release-verify  # Evidence-gated full criteria; fails when required evidence is missing.
```

## Exact development interface
| Task | Command | Meaning |
|---|---|---|
| Install/probe | `make bootstrap` | Validate tools and pin support; explicit developer override is nonqualifying |
| Build | `make build` | Go build with trimpath |
| Format apply/check | `make format` / `make fmt` | gofmt apply / fail on differences |
| Lint/static/type | `make lint` / `make check` | go vet and compile; Go compiler provides static typecheck |
| Unit | `make test` | Go package tests; Python tooling tests run through `make integration` |
| Integration | `make integration` | Real CLI/snapshot/adapter subprocess checks |
| Locked acceptance | `make acceptance` | Criteria-linked checks; does not invent missing manual evidence |
| Race | `make race` | Go race tests under supported platform |
| Property | `make property` | Independent Python exact oracle across fixed seeds |
| Fuzz | `make fuzz` | Bounded Go fuzz targets, 30 s each for release profile |
| Negative controls | `make mutation` | Disposable copy PASS/FAIL/PASS targeted defects |
| Security local | `make security` | Local input/scope/public-file checks, not online CVE assurance |
| Security online | `make security-online` | Installed pinned official govulncheck; missing scanner fails. Public secret-pattern checks are a separate local gate. |
| Benchmark smoke/full | `make benchmark-smoke` / `make benchmark` | Smoke observation versus full frozen grid; never interchangeable |
| Demo | `make demo` | Deterministic actual executable outputs and escaped HTML |
| Clean environment | `make clean-verify` | Fresh committed checkout with owned caches; re-run setup/checks/demo |
| Core CI equivalent | `make ci` | Build, formatting, vet, tests, race, mutations, demo and smoke; `make verify` also runs the oracle, fuzz and security checks |
| Teardown | `make clean` | Remove only owned generated binaries/demo/cache paths after preserving relevant evidence |

The first delivery may have incomplete targets that explicitly exit nonzero with NOT RUN and task IDs. Codex must implement them, not change them to success messages. Never use `|| true` or blanket exception suppression on required checks.

## Configuration and secrets
There are no service secrets or API providers. GOCACHE and GOMODCACHE are inside `.cache/`; GOTMPDIR and child-process temporary files use `.cache/tmp`. Generated workloads and evidence use `.local/`. `GOTOOLCHAIN=local` prevents surprise toolchain downloads. Make sets GOMAXPROCS to 2; direct Python helpers use `FQ_CPUS` or 2. Benchmarks record the actual value. Do not run `go env -w` against the user's global profile. Inputs/outputs are operator-owned files; never accept those paths from client query JSON.

## Index lifecycle and recovery
Build to a new destination name, validate before publication, and retain the old immutable generation until the new one has passed smoke queries. Startup loads and validates a snapshot, then returns scoped handles. Reads do not mutate disk. Backup is copying completed snapshot/checksum/config to an approved owned path; restore uses full validation before scope creation. There is no database migration. Unsupported format is E_FORMAT; write a separate converter only after versioned contract and tests.

Failed writes/cancelled builds leave no successful new generation and never overwrite an existing one. Remove stale temporary files only after checking ownership and no running writer. Process termination tests demonstrate process recovery behavior, not physical power-loss guarantees. On unexpected internal error, preserve a small synthetic reproducer and receipt, not confidential full input.

## Observability
CLI emits structured results and bounded errors, not an always-running metrics endpoint. Measure per-query plan/cardinality/distance work/status and separate process/build timings. Optional pprof profiles are local developer artifacts; never expose a diagnostic HTTP listener. No OpenTelemetry collector or Prometheus stack is needed for a local library. Alerts are deterministic nonzero exit codes and release-gate failures.

## CI and supply chain
The source workflow uses `pull_request` and `push`, read-only `contents`, immutable official action commits, disabled persisted checkout credentials and a bounded timeout. It has no deployment secrets or privileged runner. It runs `make verify` and the public audit. The separate manual release-evidence workflow admits a loop-backed 5.5 GB volume only after an actual ENOSPC probe, installs the verified pinned toolchain, constrains process resources, runs independent verification/reproduction/scanner stages and the full matrix, and uploads successful and failed evidence. It has not yet executed. Shared runner constraints do not imply dedicated physical reference hardware. Cache stays disabled to simplify provenance and storage.

SBOM starts from `go list -m -json all` and toolchain/dependency notices; current third-party runtime module list is empty by design, not proof that compiler/OS code has no vulnerabilities. License checks verify original license plus any optional comparator/data terms. No container scan is claimed when no image exists. A GitHub workflow file is not evidence it ran.

## Hosted/static demonstration
Recommended hosted option is a sanitized static HTML report in GitHub Pages. It displays recorded experiments; it is not a live search endpoint. Keep source and synthetic fixtures public; keep private research and raw local logs out. Pages setup may require repository administration; that narrow task becomes HA-002, while local development continues. No custom domain or paid plan is required.

An optional paid reference host is used only after explicit billing authorization. Transfer the public source and synthetic corpus, restrict access to SSH, do not expose a retrieval service, run measurements, preserve sanitized outputs and tear down approved resources. Dedicated/steady CPU is preferable to burstable hardware for strong performance claims; publish CPU-credit/virtualization caveats if using Lightsail. Infrastructure-as-code for a fleet is unnecessary for one optional benchmark machine; record exact provisioning parameters instead.

## Resource and storage policy
Absolute ceiling: 15,000,000,000 bytes attributable to project development. Planning target <=8 GB. Warning 10 GB; no new heavy job beyond 12 GB; retain >=2 GB reserve before any bounded growth. Include source, Git objects/worktrees, downloaded archives, installed toolchains, module/build caches, comparator env, logs, temporary snapshots, browser profiles and any new VM/container allocations. Do not count only the visible repository. No model weights, Docker stack, Kubernetes or giant dataset is required.

The monitor checks aggregate paths before/after commands; worker reservations are serialized. At most two write-isolated executors, and one heavy benchmark/build at a time. On pressure, checkpoint, preserve source and compact evidence, remove only manifest-listed disposable artifacts, then resume. Never purge global caches, unrelated projects or user files. Hard enforcement requires an OS quota or bounded volume; if unavailable, keep local actions conservatively bounded and route growth-heavy optional tasks to an authorized remote environment. Do not claim a software scan alone guarantees no transient overshoot.

## Operational failure runbooks
Dependency install: verify official version/platform/hash; do not bypass TLS/signature; record BLOCKED, continue source/tests possible with labeled toolchain. Flaky test: reproduce and retain multiple outcomes, identify cause, never retry-until-green as a fix. API unavailable: only optional comparator/hosted tasks blocked, keep core local. Snapshot failure: test clean and corrupt fixtures, never manually patch a file and omit a converter. CI failure: preserve logs, compare versions/runner/caps, reproduce. Benchmark noise: retain variance and all cells, increase justified repetitions, no fastest-run selection. Merge conflict: orchestrator resolves and reruns affected tests. Weak executor output: reject and escalate role, not patches around bad architecture. Workspace corruption: preserve diff/evidence, use fresh owned checkout, compare hashes and recover. Credit interruption: persist task state; a resumed session performs a new live attempt instead of trusting old exhaustion. See private recovery protocol for detailed agent behavior.
