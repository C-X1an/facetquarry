# Experimental Linux evidence lifecycle

This source-only lifecycle supervises the synthetic POSIX integration profile and retains complete failure evidence. It is not a scientific benchmark, a release qualification, or a cloud transport implementation.

The selected module and test sources are unchanged byte copies. Nine portable fake-descriptor/error-data controls passed with zero skips on these exact module/test bytes before curation. That synthetic result does not establish real filesystems, process signals, kernel quotas, RAM enforcement, durability or custody. The original 22 Linux controls, public-location execution, actual quota/RAM proofs, supervision, cloud/native custody and scientific measurements remain **NOT RUN**. This newly curated source selection requires independent review before execution.

`LIFECYCLE_SOURCE_MANIFEST.json` pins current source bytes. Its `packet_files` list defines the six-file runtime packet; `ancillary_files` pins the separate nine-test portable file. The manifest cannot authenticate itself: obtain its complete SHA256 from an independent trusted source before starting Python.

## Bootstrap and placement

Do not invoke the lifecycle directly from this repository directory: the ancillary portable file is deliberately outside the launcher's exact runtime membership. A reviewed controller must stage exactly the six `packet_files` plus the unchanged manifest into a NEW owner-only directory. Do not stage the ancillary file, `.pyc`, packages, unlisted modules or fixture data there. Verify complete lengths, hashes and exact membership before executing any packet file or adding its directory to an import path. Staging is an exclusive byte copy, never an import or extraction of fixture content.

Require Linux, Python 3.11+, a trusted installed interpreter/stdlib/library tree, and pinned installed `mke2fs`, `mount` and `umount`. Use explicit installed binary paths; symlinked runtime files refuse. Trusted directory ancestors must be root-owned or owner-owned and not group/world writable. Runtime packet, contexts and files use 0700 directories and 0600 files. Ordinary shared `/tmp` does not satisfy this chain.

Use a NEW owned job root. The fixed placements are:

| Placement | Contents |
| --- | --- |
| Separate staged lifecycle packet | Six source files and manifest; available before job creation |
| `job/quota.img` | Entire fully allocated 256 MiB disk image, retained through custody verification |
| `job/volume` | Actual owned ext4 loop mount with `nodev,nosuid,noexec` |
| `job/volume/packet` | Independently pinned flat POSIX integration packet |
| `job/volume/work/fixture-ATTEMPT` | NEW fixture root; its entire tree is collection scope |
| `job/control` | Every admission, proof, process log, lock and lifecycle/finalization receipt; outside image |
| `job/exports` | Outside image: A `fixture.neutral` and B `fixture-copy.neutral`, including failed prefixes |
| Cloud and native return cache | Separate custody of A, B, full image and all control/source/receipt bytes |

Choose a new owned native return cache outside automatic synchronization. Account for every mirror, connector FileRef, transport container and additional copy. Keep old jobs, failures and collided files. The retained lock prohibits reuse; a resumed attempt requires new admission and a new job root.

## APIs

| Function | Behavior |
| --- | --- |
| `prepare_quota` | Creates the new image/mount, verifies actual mountinfo/sysfs/block-device/image identity and real beyond-capacity ENOSPC denial |
| `prepare_memory` | Runs an unprivileged child with the actual 512 MiB RLIMIT_AS pair and a real denied larger allocation |
| `run_process` | Clean environment, new process group/session, bounded streams/time/limits, TERM/KILL and bounded quiescence checks |
| `snapshot_tree`, `write_neutral`, `collect_tree` | No-follow whole-tree inventory, A/B byte copies, independent prefix readback and repeated source stability checks; refuse collection before producer quiescence |
| `verify_prefix` | Independently pinned length/SHA check, including malformed A/B; no framing claim |
| `verify_neutral` | Read-only framing/member/inventory verification; never extracts or executes |
| `supervise` | Binds actual proofs, source pins, actual available space and exact integration admission before launching the child; collects every child outcome |
| `finalize_image` | Separate root step after producer quiescence; ordinary exact unmount once, no active same-device mount/backing association, then full-image byte reference |

Errors preserve bounded nested leaf type/errno/message and group context, with explicit truncation/overflow. Cleanup attempts every acquired descriptor and retains primary and close failures. A/B receive independent byte readback even after a copy/cleanup failure. None of these APIs deletes, moves, overwrites, selects one successful prefix, or retries indefinitely.

## Future commands and required workflow

All commands below are **NOT RUN**. Variables denote independently verified concrete paths, lengths and complete hashes. Both JSON templates have refusing statuses, null proof fields and false admission flags; they are not grants. An external reviewed controller must enforce a finite overall lifetime, retain storage on failure, capture actual bounded receipts and implement authenticated cloud/native transport. This module supplies no provider authentication or upload/download mechanism.

Run each invocation with the exact installed interpreter and `-I -S -B` under an empty environment containing only LANG/LC_ALL/TZ. Require the `C.UTF-8` locale. Verify the external manifest pin and all staged sources BEFORE Python starts; the internal check is a second check. Root actions use `--owner-uid` for the intended non-root owner's source/context files.

1. Close independent source findings and admit all allocations from a fresh inventory, including the unchanged 2 GB reserve. Prepare a NEW reviewed context with real installed-tool/interpreter pins. Run as root:

```sh
env -i LANG=C.UTF-8 LC_ALL=C.UTF-8 TZ=UTC "$PY" -I -S -B "$LIFE/scientific_posix_lifecycle.py" prepare --manifest-sha256 "$LIFE_SHA" --context "$PREPARE" --context-sha256 "$PREPARE_SHA" --owner-uid "$OWNER_UID"
```

Require actual full image allocation and mount/device/backing identity. A real `posix_fallocate(268443648)` inside the volume must fail with ENOSPC and leave the retained probe at zero bytes/blocks. Any partial allocation, wrong errno, wrong geometry or helper failure refuses and preserves the job. No context boolean establishes these facts.

2. Keep the original context unchanged. Create a NEW preparation-format memory context containing the actual quota-proof SHA. Run as the admitted owner:

```sh
env -i LANG=C.UTF-8 LC_ALL=C.UTF-8 TZ=UTC "$PY" -I -S -B "$LIFE/scientific_posix_lifecycle.py" probe-memory --manifest-sha256 "$LIFE_SHA" --context "$MEMORY_CONTEXT" --context-sha256 "$MEMORY_CONTEXT_SHA"
```

Require the actual RLIMIT_AS pair `(536870912,536870912)` and MemoryError for a 536,870,913-byte allocation. RSS observations are not enforcement proof; optional cgroup counters do not attribute an OOM to a child.

3. Admit and run the original 22 Linux controls as the owner on a NEW hard-bounded controls root, retaining all generated files and actual command streams:

```sh
env -i LANG=C.UTF-8 LC_ALL=C.UTF-8 TZ=UTC "$PY" -I -S -B "$LIFE/test_scientific_posix_lifecycle.py" --test-root "$CONTROL_ROOT" --lifecycle-sha256 "$MODULE_SHA" --python "$PY" --python-bytes "$PY_BYTES" --python-sha256 "$PY_SHA"
```

The trusted controller must derive `job/control/external-profile-control-proof.json` from the actual command receipt. Required fields are `format=scientific-posix-external-profile-control-proof-v1`, the current `lifecycle_manifest_sha256`, `actual_linux_posix=true`, `actual_tests_run=22`, zero `actual_failures`, `actual_errors` and `actual_skips`, `process_returncode=0`, `all_control_prefixes_retained=true`, and `actual_command_receipt_sha256`. Retain and independently pin the underlying receipt. There is no such actual Linux proof in this selection.

The ancillary nine portable tests use a normal colocated import. A trusted pre-import runner must externally verify both module/test pins before adding their directory to `sys.path`, then load the suite under `-I -S -B` and require exactly nine tests/zero skips. Do not use that ancillary file or its synthetic PASS as the 22-test Linux proof. No portable runner is included here.

4. Independently stage the paired integration packet, for example from the separately reviewed `../scientific_storage` selection. Its exact profile is `scientific-posix-integration-retain-all-v2`, runner context `explicit-owned-quota-posix-v2`, admission format `scientific-posix-runner-admission-v2`. Bind its fresh manifest and admission, actual quota/memory/control proofs, independent findings and the same complete inventory in the lifecycle admission. Preserve the integration launcher's exact admission keys.

For this candidate `hard_quota_bytes=268435456`, `memory_limit_bytes=536870912`, SPI reservation `855638016` and entries `20608`. If additional lifecycle growth is G, SPI `other_growth_bytes` must be `G+637534208`. Require actual `f_bavail*f_frsize >= 201326592` AFTER packet staging and retained controls, before producer launch. If the 256 MiB filesystem cannot fit the unchanged source and headroom, refuse without shrinking source caps or removing evidence.

```sh
env -i LANG=C.UTF-8 LC_ALL=C.UTF-8 TZ=UTC "$PY" -I -S -B "$LIFE/scientific_posix_lifecycle.py" supervise --manifest-sha256 "$LIFE_SHA" --context "$ADMISSION" --context-sha256 "$ADMISSION_SHA"
```

5. Preserve the actual outcome and exact receipt even when the command fails. After actual child/group quiescence, independently verify the terminal receipt, admission and same image/mount, then finalize as root, including failed child outcomes:

```sh
env -i LANG=C.UTF-8 LC_ALL=C.UTF-8 TZ=UTC "$PY" -I -S -B "$LIFE/scientific_posix_lifecycle.py" finalize-image --manifest-sha256 "$LIFE_SHA" --context "$ADMISSION" --context-sha256 "$ADMISSION_SHA" --owner-uid "$OWNER_UID" --receipt-sha256 "$RECEIPT_SHA"
```

The outer controller must not short-circuit retention/custody on a nonzero command. A local zero means only `LOCAL_PROCESS_AND_NEUTRAL_COPY_VERIFIED_CUSTODY_PENDING`. Image finalization uses one ordinary unmount; no forced/lazy unmount, detach or cleanup is supplied. If setup/preflight failed before a terminal receipt, or quiescence/unmount/backing checks fail, retain the owned runner/storage and report incomplete custody until a separately reviewed salvage operation is admitted. Host destruction cannot produce a complete-custody claim.

6. Transfer A AND B as distinct objects even if B is a shorter, empty, malformed or failed prefix. Retain missing-file facts when an output never existed. Transfer the complete closed image regardless of neutral success, and every source/control/context/proof/log/receipt byte outside it. Authenticate actual cloud object identity, complete length/SHA and upload/download receipts; verify separately in the admitted native cache. Extra connector FileRefs and failed transfer objects remain allocations and evidence.

```sh
env -i LANG=C.UTF-8 LC_ALL=C.UTF-8 TZ=UTC "$PY" -I -S -B "$LIFE/scientific_posix_lifecycle.py" verify-prefix --manifest-sha256 "$LIFE_SHA" --context "$PREFIX_REFERENCE" --context-sha256 "$PREFIX_REFERENCE_SHA" --data "$RETURNED_PREFIX"
env -i LANG=C.UTF-8 LC_ALL=C.UTF-8 TZ=UTC "$PY" -I -S -B "$LIFE/scientific_posix_lifecycle.py" verify-neutral --manifest-sha256 "$LIFE_SHA" --context "$PREFIX_REFERENCE" --context-sha256 "$PREFIX_REFERENCE_SHA" --data "$RETURNED_PREFIX"
env -i LANG=C.UTF-8 LC_ALL=C.UTF-8 TZ=UTC "$PY" -I -S -B "$LIFE/scientific_posix_lifecycle.py" verify-image --manifest-sha256 "$LIFE_SHA" --context "$IMAGE_REFERENCE" --context-sha256 "$IMAGE_REFERENCE_SHA" --data "$RETURNED_IMAGE"
```

Use the independently pinned actual `neutral_prefix`/`second_prefix` reference objects from the receipt, format `scientific-posix-neutral-prefix-reference-v1`, for byte verification. Strict neutral verification may fail while prefix byte verification succeeds; preserve both outcomes. Image verification requires the actual closed-image reference and exact full size/hash. Never mount, extract, import or execute received data. The original image stays until independent complete cloud/native custody is verified; this module never deletes it afterward either.

## Failure semantics

The whole fixture tree includes every original, staging/packed output, partial/final catalog, tail, unknown entry, copied tree and normal/failure envelope. No success manifest chooses a subset. Nonzero exit, constructor/assertion failure, timeout, signal and real allocation denials retain all available prefixes after quiescence. An unknown KILL/OOM cause stays unknown. Unsafe links/FIFO/devices/sockets, foreign mounts, xattrs/ACLs, ownership changes, enumeration/read/close/fsync/race/bound failures make the neutral result explicitly incomplete and require the already-admitted full raw-image fallback. A failed B never becomes A.

This is supervision of reviewed trusted code in one process group/mount namespace, not a hostile-code sandbox. The paired child must not daemonize, escape via `setsid`, start outside writers or mutate supervisor paths. Exclude other writers and privileged mounts. Kernel I/O stalls, supervisor SIGKILL, provider loss and host failure can prevent receipts; the controller must retain storage and report the gap. Receipts are inspectable observations, not cryptographic third-party attestations. Resource arithmetic is in `BOUNDS.md`; no arithmetic or source manifest grants execution.
