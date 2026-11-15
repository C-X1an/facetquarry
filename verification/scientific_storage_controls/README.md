# Scientific storage source and synthetic controls

Current curation note: sixteen selected files remain byte-exact copies.
The raw-reference implementation and analysis-driver implementation each
remove terminal empty LF lines only to satisfy default Git whitespace
checks. Their original measured hashes are unchanged in the historical
receipt; separate curation_derivations record both old and current hashes.
References below to exact prototype copies describe initial preparation,
before these two explicit EOF-only derivations. No test body was changed.

The public `run_controls.py` actually passed **114 controls, zero skips** on
2026-11-15 after independent first findings and repair. The measured technical
source was `98c843fbe8e0fc20ae5b5edcb4aa46b15ccea3aa06827f5c07c904a3ecd72078`.
The separately curated receipt is
`../published/scientific-storage-public-controls-20261115.json`. It retains
21 before/after source pins, 15 module origins, counts and real stream digests.
The earlier launch refusal remains a failed run. These results cover only the
selected source bytes and synthetic or fake-descriptor unit methods.
It does not qualify actual POSIX behavior, kernel faults, disk quota, child RAM,
transport custody, native Go integration, scientific measurements or release.

The packet under `../../scripts/scientific_storage/` contains all 12 exact
reviewed revision-2 source files, including nine Python files, README, BOUNDS and
the refusing admission template. This directory adds five exact test files and
the analysis driver. Their bytes and line endings are preserved; assertions are
unchanged. The repaired `raw_member_store` is confined to that packet. The
existing `scripts/raw_member_store.py` retains its legacy behavior.

Some original file headers say UNEXECUTED or SOURCE ONLY. Those historical
headers are preserved. The historical local controls described below actually
ran on their pinned prototype bytes. The public launcher now has its separate
114-control receipt; live integration remains unexecuted.

## Source pins and import closure

`CONTROL_SOURCE_MANIFEST.json` pins 21 selected files: all 12 packet members, the
public POSIX manifest, the six control/driver files, this launcher, and the
unchanged legacy `scripts/analyze_reference.py`. The latter has only stdlib
imports. The runner refuses any additional public import dependency. It uses
normal module imports without aliases, source rewriting, custom module loaders
or dynamic production monkeypatches. Existing injected unit controls use their
original scoped fakes and restore them through their existing context managers.

The expected origins are explicit:

| Module group | Count | Public location |
|---|---:|---|
| Capture, repaired store/raw reference, registry, publication, transport, adapter | 7 | `scripts/scientific_storage/` |
| POSIX launcher, imported only for fake-descriptor helper controls | 1 | `scripts/scientific_storage/` |
| Legacy analyzer | 1 | `scripts/analyze_reference.py` |
| Five test modules and analysis driver | 6 | `verification/scientific_storage_controls/` |

The actual POSIX integration module is present and pinned, but this unit runner
does not import or execute it. The runner checks `-I -S -B` before any shadowable
stdlib import. It removes environment keys outside a short platform, locale and
temporary-directory allowlist before importing the control graph; it prints no
environment values and starts no child process. It verifies every selected file,
source cap and expected origin before extending import paths. Stdlib lookup
keeps priority, and the repaired packet precedes the legacy scripts directory.
Actual module origins and source pins are checked before and after the tests.

The packet and control directories must contain exactly their declared regular
files. Unknown modules, packages, bytecode caches and hidden fixtures refuse.
Source symlinks/junctions and hardlinked selected files refuse. On POSIX, selected
paths must be owned by the caller or root and not writable by other users. The
source manifest is capped at 65,536 B, each selected source at 131,072 B and the
aggregate of its 21 rows at 750,000 B. These are source/input limits and provide
no OS-enforced disk or memory quota.

The control manifest's exact SHA256 is:

`fc3af483267a9b4add2704ed1e581760ed07cb9d85bf50ef82c01b6d46de4135`

An executing caller must obtain that digest from an independently trusted,
reviewed channel and pass it explicitly. Reading a digest from an untrusted
checkout does not establish trust. The manifest excludes itself. This README
is also excluded because it documents that digest; neither creates a self-hash
cycle. Its exclusions are not additional import inputs.

The separately curated POSIX manifest SHA256 is:

`6b79a1e10108a8322888d854469beef618c36df2e4d3bac2790100e0eab33271`

It retains format `scientific-posix-source-packet-v1`, revision 2, profile
`scientific-posix-integration-retain-all-v2`, and the launcher's required literal
source-only status. Every member origin points to its public packet path.
Neither manifest grants runtime admission. The admission template deliberately
refuses execution, and a real lifecycle/enforcement/custody runner is separate.

The digest `0444490f17abd4b9e74def5f36046a2fa9c58b9306a0f658b8a3dbf4fed6b0fa`
is historical base Go/source context. It is not the identity of this expanded
public checkout. Copying the technical source changes the working source
identity; the old context is not current-checkout release evidence.

## Exact control scope

| Test module | Required methods |
|---|---:|
| `test_dependency_release_pure` | 17 |
| `test_fd_ownership_paths` | 20 |
| `test_scientific_execution_registry` | 41 |
| `test_scientific_analyzer_adapter` | 21 |
| `test_scientific_reference_analysis` | 15 |
| Total | 114 |

The 37 descriptor controls intercept all synthetic descriptor integers with
their original fakes. The remaining 77 use synthetic in-memory original bytes,
metadata and samples. The runner requires these exact per-module and aggregate
counts, unique test IDs, no discovery errors, no skips, no expected failures and
no unexpected successes. Count or pin/origin changes fail. It creates no
filesystem fixtures, runs no Go command and performs no cleanup or evidence
deletion. A failed run remains a failed run; there is no hidden retry.

For reproduction after independent review and fresh bounded admission, run from
the public repository root using the existing evidence wrapper:

```text
python3 scripts/evidence.py --category scientific-storage-public-controls --requirements AC-021 --timeout 60 -- python3 -I -S -B verification/scientific_storage_controls/run_controls.py --manifest-sha256 fc3af483267a9b4add2704ed1e581760ed07cb9d85bf50ef82c01b6d46de4135
```

The command above is a reproduction instruction. The linked curated receipt
records the actual measured run separately. The evidence wrapper
must retain the real receipt, stdout and stderr on every outcome, including
launch/discovery errors, failed assertions and interruptions. Do not delete or
replace failed runs. The launcher emits actual counts, source pins and origins;
those outputs still need review before any public evidence export. Do not add
fixtures or bypass isolation to make a failure disappear.

## Historical prepublication evidence

`../published/scientific-storage-prepublication-controls-20261115.json` curates
three actual historical runs with verified stream digests and exact module
hashes mapped to these public copies:

| Historical run | Actual controls | Skips |
|---|---:|---:|
| `20261114T212459Z-259dbb98b2` | 37 descriptor controls | 0 |
| `20261114T212608Z-d5a3e25133` | 41 registry + 21 adapter + 15 driver = 77 | 0 |
| `20261114T213107Z-1b5614d349` | 4 startup/local controls | 0 |

These total 118 historical controls. The four-control run includes two real
native Python startup-isolation checks and two fake-descriptor local checks.
Its original test file is not exported: it used environment-specific source
paths and historical packet metadata. The new 114-test public launcher does
not contain those four checks. Its actual 114-control run is separate from the
historical 118.
Unmapped historical document/test pins are counted in the curated receipt but
are not relabeled as current public files. Raw commands, environment values,
source-machine paths and raw streams are excluded from that public summary.

These historical results establish only their local prototype/unit scope and
exact module bytes. They are not a run of the current public checkout or a
release qualification. Actual POSIX execution, disk and child-memory denial,
complete failure custody, native Go scientific collector/analyzer wiring,
post-retirement state, reference-host qualification and the full 5,400-cell,
5.4-million-sample matrix **separately for readers 1, 4 and 16** remain NOT RUN
or separate unfinished work. The historical summary preserves the launcher
status at initial preparation; the separate actual public receipt supersedes
that dated status without changing any historical run.
