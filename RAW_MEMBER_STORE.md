# Experimental raw-member store

Native Windows direct CLI and test discovery at technical source `9a802ccd82c34edef86eba2fc45c495eae049cb59d116128b6a70b5302d3811a` each recorded **4 passed / 24 explicit POSIX skips**, zero failures/errors. See [curated native controls](verification/published/raw-member-native-controls-20261107.json). This is preliminary platform-refusal/contract evidence; Linux execution remains NOT RUN.

This standalone experimental component retains caller-supplied original bytes.
Current public-candidate Linux execution is **NOT RUN**. It is unintegrated:
the engine, benchmark collection, analyzers, existing gzip formats, profiles,
fallbacks, admission guards and deadlines do not use it. Source availability
and synthetic tests do not qualify durability, capacity, performance or release.

The frozen scientific matrix and acceptance requirements remain unchanged.
This component supplies no scientific result, storage saving, original-retirement
credit, full-matrix admission or inode-fit evidence.

## Original-byte identity

[scripts/raw_member_store.py](scripts/raw_member_store.py) defines the explicit
`caller-raw-originals-v1` protocol. A trusted caller declares and supplies exact
builtin `bytes`, including binary/NUL/non-UTF8, malformed or partial output,
and noncanonical JSONL. The store does not interpret sample content.

An original is the exact supplied byte string. The store does not parse gzip,
reproduce compressed wrappers or claim that legacy gzip files existed.
Legacy `samples_sha256`, gzip member names and reconstruction meanings remain
unchanged. A future scientific adapter needs its own explicit versioned
raw-member references; new fields grafted onto a legacy schema do not supply
compatibility.

| Identity | Meaning |
|---|---|
| `protocol` and `version` | Exact new storage schema |
| `source` | Caller-trusted lowercase SHA-256 source identity |
| `transaction` | Caller-selected 32-character lowercase hexadecimal identity |
| `members[].name/size/sha256` | Complete declared original-byte membership |
| `members[].encoding` | Explicit `identity` or standards `xz` representation |
| `packed[].name/encoding/bytes/sha256` | Encoded member identity in the manifest |
| `plan` and `reservation` | Local staging/candidate/metadata/tail allowance |

Both supported representations may occur in a new-protocol transaction.
Unknown modes, versions, fields, legacy schemas, duplicate names and Boolean
substitutes for integers refuse. Membership is declared before staging and is
never inferred from surviving files. SHA-256 checks trusted byte bindings;
it is not a signature or authenticity proof against a privileged local writer.

## API and commit order

The module uses the Python standard library.

| Operation | Behavior |
|---|---|
| `Member(name, size, sha256, encoding='identity')` | Frozen original descriptor |
| `Plan(allowance, allocation_unit=4096, failure_tail=4096)` | Frozen local reservation request |
| `reservation(members, plan)` | Check exact types/caps and required allowance |
| `begin(root, source, transaction, members, plan, hook=None)` | Admit a fresh transaction under an existing explicit owned root |
| `handle.stage(name, raw)` | Exclusively write, synchronize and hash declared original bytes |
| `handle.finalize()` | Check complete staging, encode candidates, independently decode/hash originals, publish manifest and commit |
| `handle.close()` | Close the writer and synchronize a closure record |
| `handle.release()` | Close descriptors without deleting evidence or inventing closure |
| `recover(root)` | Read-only bounded report of committed, pending, partial, unknown and refused evidence |
| `restore(root, expected_source, transaction, name)` | Return exact original bytes from a checked closed commit |
| `handle.retire_staging()` | Explicit same-live-handle staging retirement after commit, closure and restorability checks |
| `resume(...)` | Always refuse; no takeover or automatic repair |

Preadmission precedes transaction creation. `transaction.json` fixes the
source, transaction, protocol, full member set and reservation before staging.
Existing paths refuse overwrite. An argument refused before staging remains
the caller's responsibility; the store cannot retain bytes it never accepted.

Every original is checked by size and SHA. Identity candidates are read back;
XZ candidates are independently decoded against the same original binding.
Files and relevant directories are synchronized before no-clobber commit
publication. `finalize()` retains staging by default.

A commit record without matching committed closure remains
`COMMIT_RECORD_PRESENT_CLOSURE_OR_DURABILITY_UNCERTAIN` and is not accepted
for restore. `release()` does not create a successful closure marker.

Cap, write, compression, verification or commit failure preserves existing
staging and written candidate/metadata prefixes. Test hooks raise at named
boundaries; they do not create kernel-fault evidence.

## Ownership and writer exclusion

Member names are flat lowercase ASCII, at most 64 bytes. Paths, Unicode,
case variants, Windows device stems, trailing dots/spaces, alternate streams,
tilde aliases and duplicates refuse.

POSIX mutations use owned directories, descriptor-relative `O_NOFOLLOW` and
`O_EXCL`. Checks cover regular files with one link, owner/type, no symbolic/
reparse/special entries, opened inode identity and parent-to-child bindings.
A nonblocking advisory `flock` on the root descriptor serializes cooperating
API writers until `release()`, including after `close()`. A handle also refuses
overlapping/reentrant operations. Every root entry consumes a slot, including
unknown evidence; capacity is checked under the root lock before mutation.

The explicit root path is reopened without following links and compared with
the retained root device/inode. This detects root-path replacement. Actors
ignoring advisory locks or modifying the process/filesystem outside the API
are outside the cooperating-writer guarantee.

## Durability and staging retirement limits

Actual base-directory `fsync` must succeed before transaction creation.
Unsupported locking or synchronization refuses. Windows and other unsupported
platforms explicitly refuse mutation and report unsupported recovery durability;
no no-op flush is labeled durable success.

Successful directory synchronization does not identify persistent backing
media: a memory filesystem can accept `fsync`. This module does not independently
prove persistent storage, historical stable ancestors, past kernel synchronization
or power-loss behavior.

Any sole-copy integration needs an independently caller-bound persistent
filesystem and ancestor/root identity contract, with corresponding execution
evidence. Synthetic staging-retirement tests exercise the API and ordering;
they do not authorize retirement of project originals.

Optional `retire_staging()` requires the same live, nonfailed handle after
verified commit and closure. Before unlink it requires the exact root-wide
restorability prerequisite used by `restore`, rechecks commit/closure,
original stage hashes and owned inodes, and durably records retirement start.
It synchronizes staging and records completion afterward.

An interrupted explicit retirement may remove a prefix. Recovery reports
exact missing stage names and `STARTED_MAY_BE_PARTIAL` while independently
checking full committed encoded membership. It does not shrink original
membership or infer completed retirement from absent staging. Recovered
handles cannot authorize retirement. Unlink totals do not establish available
space or resource credit.

## Finite caps and accounting

| Limit | Bound |
|---|---:|
| Declared members per transaction | 16 |
| Original bytes per member | 1 MiB |
| Aggregate original bytes | 4 MiB |
| Declaration or manifest | 64 KiB |
| Small control record | 2,048 bytes |
| Reserved failure tail | At most 4,096 bytes |
| Identity candidate | Original size |
| XZ candidate | Original size plus 65,536 bytes |
| XZ decoder memory | 64 MiB |
| Decoded chunk | At most 65,536 bytes, with size-plus-one sentinel |
| Transaction inventory | 128 entries, depth 3 |
| Root entries, including unknown evidence | 32 |
| Local plan allowance | At most 32 MiB |
| Allocation unit | Power of two, 4,096–65,536 bytes, at least actual fragment size |

Single-stream XZ decoding rejects truncation, concatenation, trailing data,
memory/output excess and original hash/size mismatch. XZ is an explicit
representation choice, not a promise of smaller output.

Reservation includes worst-case identity staging, bounded packed candidates,
metadata/finalization, failure tail, rounding and allocation headroom before
`begin`. Live writes check the next bounded chunk against the allowance and
observed file/block usage. A rejected chunk is not written; earlier prefixes
remain.

LZMA produces library output before the Python postallocation size check.
File caps are not peak-RSS bounds. Local reservation and monitoring are not
an OS hard quota or global project admission. Compressor/interpreter memory,
copies, filesystem internals and all attributable roots need separate admission.

Accounting includes every observed stage, packed, manifest, commit, closure,
failure and retirement file byte, with metadata/control totals. Observed block
counts cover scanned entries; base/transaction directory growth and filesystem
internal metadata require separate external accounting.

The 32-root-entry/32-MiB-plan caps do not establish 5,400-cell, 1.1-GB image or
inode fit. Future integration must solve cumulative space/inodes, complete
virtual-member coverage, failure retention and transport copies separately.

## Recovery and refusal

Recovery never deletes, resumes, repairs or rewrites evidence. Within its
bounds it reports every root entry and inventories transaction files with
sizes/hashes and unsafe observations.

Unknown artifacts, aliases, wrong kinds, corruption and incomplete metadata
refuse acceptance. Optional `failure-tail.bin` must be a regular file within
the immutable declared tail cap; an empty directory is not a valid empty tail.
These refusals also block restore and staging retirement.

Count/depth/size excess or unexamined unsafe subtrees produce explicit bounded
incomplete/refused reports. Root overflow reports observed entries and the
presence of unexamined entries. No partial inventory is accepted as complete.

Committed acceptance requires exact original/encoded membership, source,
transaction, protocol, manifest/commit bindings and recorded closure.
Retirement markers have separate start/completion relations. Stored bytes
do not independently attest historical `fsync`.

## Synthetic tests and verification status

[tests/test_raw_member_store.py](tests/test_raw_member_store.py) retains the
28 discovered synthetic cases, including inherited platform controls.
They cover byte identity, strict names/types/caps, root locking/replacement,
32/33 slots, tail limits, metadata cost, corruption, torn records, aliases,
XZ bounds, controlled boundary failures, restore and retirement ordering.

Current public-candidate Linux execution is **NOT RUN**. Windows controls
exercise pure contracts and explicit unsupported-durability refusal.
Linux-only controls remain explicit skips on unsupported platforms and do not
qualify POSIX mutations, synchronization, restore or retirement. Evidence from
a different source does not qualify this candidate.

From the repository root, targeted discovery lazily creates an exclusive short
fixture root under `.local/rms/`:

    python3 -B -m unittest discover -s tests -p test_raw_member_store.py -v

The direct CLI still requires an explicit absolute, owned, new directory:

    python3 -B tests/test_raw_member_store.py --test-root /absolute/owned/new-rms-tests

This test module uses no OS-global temporary directory, environment lookup,
subprocess or cleanup. It retains every generated fixture, including failed/
corrupt evidence. The post-suite guard is 16 MiB of persisted fixture bytes,
2,048 entries and depth 6. It is an accounting check, not a prewrite quota or
RSS proof; actual filesystem/library allocations require separate admission.

Controlled boundary exceptions do not reproduce actual process kill, short
write, ENOSPC, failed `fsync`, device loss or power failure. Those operational
fault/durability claims remain **NOT RUN**. The locked
[acceptance specification](ACCEPTANCE_SPEC.md) and current
[verification report](VERIFICATION_REPORT.md) define the wider release boundary.
