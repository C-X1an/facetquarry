# Original22 bounded Linux proof job

This is a **source-only, unexecuted** implementation for the original 22 lifecycle controls. Actual Linux execution, quota/RAM proofs, image closure and cloud/native custody remain **NOT RUN**. Independent first findings preceded the P2 repairs; their final closure and actual execution remain separate gates. This job runs no SPI case, Go, benchmark, scientific matrix, package install, Docker, SDK acquisition or ML workload.

The push-only workflow accepts exactly the NEW branch `scientific-posix-proof-20261115`: Ubuntu 24.04, existing pinned checkout/upload actions, `contents: read`, `persist-credentials: false`, shared `reference-evidence` concurrency and unchanged 20-minute job limit. Root must verify branch absence, no other live heavy run and fresh admission before the separately authorized one push. This document grants no execution permission.

The command-receipt reader separately accepts the existing evidence wrapper's finite top-level `duration_seconds` (0..1200 seconds); all remaining receipt values and integer-only admission documents keep their strict decoder. Original receipt bytes remain unchanged for hashing. Fallback readback compares identity, ownership, mode, links, size, mtime and ctime while excluding access time. The bounded source subtotal grows from 95,000 to 100,000 B for these repairs; per-file limits, 16 MiB source, 64 MiB supplement, payload, disk, RAM and global reservations stay fixed.

## Fresh admission

Root separately creates `verification/scientific-posix-proof-admission-20261115.json` after review and a fresh complete all-attributable inventory. The job never authors this admission. Its exact schema is:

```json
{
  "format": "scientific-posix-proof-job-admission-v1",
  "status": "REFUSE_UNTIL_REVIEWED_AND_FRESHLY_ADMITTED",
  "branch": "refs/heads/scientific-posix-proof-20261115",
  "attempt_id": "new-owned-proof-attempt",
  "created_unix_seconds": null,
  "expires_unix_seconds": null,
  "baseline_including_reserve_bytes": null,
  "global_reserve_bytes": 2000000000,
  "fresh_inventory_sha256": null,
  "base_lifecycle_bytes": 1493172224,
  "connector_bytes": 536870912,
  "supplement_bytes": 67108864,
  "other_growth_bytes": 603979776,
  "no_other_heavy_process": false,
  "independent_review_closed": false,
  "source_pins": {
    "job_script_sha256": null,
    "lifecycle_manifest_sha256": "6b60f65bbbda7ad077a50e141fd5d6f88bf49ee67e7bdd4ca3b342cd57386604",
    "evidence_sha256": "f3e187eeefc5e0c0208572b58df3e41110b8591be6a1b476d11343836ef8d469",
    "common_sha256": "15f8f1027ffcc94c3219f1c6a7c86788aeb62d5531056cc5825d11a9d33367cf"
  }
}
```

Only status `AUTHORIZED_REVIEWED_ORIGINAL22_ONLY`, both true flags, exact nonzero pins and baseline at most **9,600,000,000 B**, already including the unchanged **2,000,000,000 B reserve**, pass. Admission lasts at most six hours with bounded clock skew; an expired queued job refuses without automatic extension/retry. Only the inventory digest and public-safe numeric summary are published.

Independently hash the immutable admission/final driver, then replace the two still-refusing all-zero `FQ_ADMISSION_SHA256` / `FQ_JOB_SOURCE_SHA256` scalars. Review/pin the final workflow too; omitting its digest from admission avoids a hash cycle. Changed source needs new review/pins/admission. The repair allowance is driver <=80,000 B and these three public files together <=100,000 B, with no runtime growth increase.

## Exact runtime and controls

An isolated bootstrap checks the selected driver digest before invoking `/usr/bin/python3.12 -I -S -B` with a clean LANG/LC_ALL/TZ environment. The driver refuses another branch, reused namespace, stale admission, mismatched pins or missing exact installed runtime paths. It observes root-owned, non-writable Python, mke2fs, mount, umount, git, sudo and env bytes and rechecks their pins. These are trusted Ubuntu runner observations, not vendor/library attestations; the installed stdlib/library tree remains an explicit trusted precondition. Nothing is downloaded or installed.

The NEW private namespace is `/srv/fq-posix-proof-RUN-ATTEMPT`, for the actual runner UID/GID. Immediately after namespace creation, `recovery.json` records the trusted run/path/owner/source/admission/runtime inputs, before any source or packet staging. Every exclusively created driver output receives descriptor ownership **before its first write**. A short write can therefore leave a readable owner prefix. A partial recovery record is preserved failure data and never becomes a fabricated context or proof.

A bounded source snapshot excludes Git metadata and named ignored generated roots. Exclusive copies/readback retain inventories, admission and exactly six `packet_files` plus the unchanged manifest; ancillary tests stay outside that packet. Unchanged `evidence.py` / `common.py` capture controller/original22 commands. The non-Git snapshot may record null Git identity; retained context binds checkout commit and before/after source hashes.

The wrapper PATH references only pinned git, so its Go lookup cannot execute Go. Caches stay in the snapshot. Owner `os.execve` resets LANG/LC_ALL/TZ before unchanged original22; lifecycle children retain clean environment/limits. No credential, proxy, PATH, HOME or provider token enters a fixture or captured argument.

Existing `prepare_quota` fully allocates **268,435,456 B**, formats ext4 with fixed 4 KiB blocks, zero reserved percentage and nodiscard, and mounts nodev/nosuid/noexec. Actual mountinfo/sysfs/device/backing-image identity and a **268,443,648 B** ENOSPC attempt with zero retained probe bytes/blocks are required. Existing `prepare_memory`, as the non-root owner, must observe RLIMIT_AS **(536870912,536870912)** and MemoryError for **536,870,913 B**. Actual available-space admission precedes original22.

Original22 fixtures, failed A/B prefixes, links and FIFOs stay inside the image; no A/B copy is added. Actual receipt/exit/source/streams must agree on 22 distinct verbose `ok` tests, `Ran 22 tests`, final `OK`, no termination or failures/errors/skips before deriving a proof. Failure excludes no image, stream or outside control from safe payload admission.

## Partial recovery and closure

The always-run recovery receives the actual run ID/attempt, UID/GID, workspace/temp paths, commit and externally selected source/admission pins as explicit arguments. It validates the exact namespace and private ownership; it does not infer a new trusted owner from incomplete context. Root/runner-owned directories and unique regular files may receive descriptor-based ownership/read-bit repair after exact type, UID/GID, no-follow and open/path identity checks, before hashing. No content is rewritten. This inventory/readability path works even if source staging, packet staging, recovery metadata or `context.json` is absent/partial. Missing context is recorded as incomplete custody, with no substitute evidence receipt, runtime execution or closure claim.

Complete, validated retained context and unchanged evidence/packet bytes are separately required for the real closure command. A recovery-once lock prevents another command attempt. Closure requires no active owned command, actual process-writer scans, an exact fully allocated image, correct mount identity, ordinary bounded unmount and no remaining relevant mount/loop association. A single exclusive unmount record prevents retry. No force/lazy unmount, detach, deletion, movement or image truncation occurs. Successful closure fsyncs and hashes every raw image byte into a distinct closed-image reference. It never calls SPI-dependent `finalize-image`, invents an SPI receipt or asserts scientific success.

| Failure | Result |
| --- | --- |
| Pre-namespace refusal | Fixed source/error fallback; no image/controls claimed |
| Partial staging/context | Independent inventory/repair; unavailable closure incomplete |
| Quota/RAM/original22 failure | All available image/source/control/receipt/failed-prefix bytes eligible together |
| Writer/unmount/hash/identity failure | No closed-image claim; safe retained bytes are failure data |
| Unsafe/unreadable entry or inventory/host bound rejection | Reject all namespace upload; fixed fallback marks omitted bytes incomplete |
| Transfer failure | Available copies only; no custody success or automatic retry |
| Cancellation/SIGKILL/stuck I/O/provider loss | Always steps best effort; missing bytes incomplete |

## Safe exact-file upload admission

The uploader receives no directory path, wildcard or recursive tree. Recovery scans the complete namespace under the unchanged 4,096-entry and finite time bounds. It never traverses `job/volume`; the full `job/quota.img` represents its fixture bytes. The one expected git runtime link is validated against its exact installed root-owned target and represented by complete link-text metadata, never followed or passed to upload. Any other outside-image link, FIFO, special file, unexpected mount, hardlink, foreign owner, unsafe name or unreadable file rejects the entire namespace payload. A stopped scan records unknown unexamined bytes as **INCOMPLETE**, rather than uploading its scanned prefix.

A safe scan includes every ordinary namespace file: failed prefixes, partial setup and hidden receipts/caches. Missing expected roots are explicit and cannot qualify a gate. Known checkout/action/temp allocations must pass host admission. Test success is independent: recovery exit 10 permits the complete admitted failure payload while failing the step. No PASS selector drops failed prefixes.

Only admitted bytes produce `upload-manifest.json`: exact regular-file paths, sizes, hashes and identities, plus bounded inventory/custody metadata and the fixed fallback. A final **unprivileged** pass rechecks the manifest's exact run/source inputs, every listed file's bytes/identity/readability and payload bounds before emitting the literal list. ASCII paths exclude glob metacharacters, exclusions, whitespace and newline injection. Output is <=256 KiB ASCII including framing and any existing output, below GitHub's UTF-16 output allowance; the fixed delimiter cannot equal an absolute path. The file list itself is bounded, unique and contains no directory, mounted alias or unsafe entry. The manifest does not hash itself: the output pass separately checks and adds that exact regular file. There is no hash cycle.

Before the controller, an independent always-run small fallback copies only the three public source files (combined <=100,000 B), admission (<=8,192 B) and an error/status stream (<=8,192 B), into five fixed ordinary filenames under an owned runner-temp directory. Absent, unreadable, oversized or partial copies are recorded. This fallback is at most **116,384 B**, receives no recursive input and can still upload when driver/admission pins refuse. Recovery appends bounded incomplete-custody diagnostics. If full admission or its final recheck fails, only this fixed fallback path list reaches the upload action. Its status explicitly says all omitted namespace/image/control/log/source-prefix bytes are unknown/incomplete; a source-only fallback never supplies their custody. I/O/platform loss can defeat even fallback preparation/upload and must be retained as an actual failure.

## Allocations and actual custody gates

The fixed growth reservation stays **1,493,172,224 + 603,979,776 = 2,097,152,000 B**. With the 9.6 GB baseline ceiling, peak is **11,697,152,000 B**, below the unchanged **12,000,000,000 B** heavy-growth threshold and **15,000,000,000 B** absolute cap. Fresh complete attribution/no-other-heavy-work admission remains mandatory. The 2 GB global reserve is never spent by this arithmetic.

Source snapshot accounting remains <=16 MiB, known host supplement <=64 MiB, full regular payload and accounted namespace allocations <=304 MiB, inventory/manifest metadata each <=4 MiB and exact upload/output lists <=256 KiB. Final payload accounting includes generated metadata and fallback. Bounded headers permit the conservative uncompressed 320 MiB archive reservation. A placement ledger retains 256 MiB image, <=320 MiB each uploader archive/cloud artifact/native return, <=512 MiB connector copy, <=64 MiB known host supplement and <=48 MiB other controller/source data: 1,840 MiB within the fixed 2,000 MiB growth envelope, with no compression savings assumed. The uploader uses compression zero, one unique artifact, one-day retention and explicit hidden files.

Known checkout/action/temp roots are measured before work, after controls and before upload. Failed host/payload admission blocks namespace archive/cloud growth regardless of test success; the tiny fixed fallback remains failure metadata. Monitoring is not a hard quota on GitHub uploader/service storage. Unexpected provider growth, extra copies/retries/mirrors need fresh inventory/admission. Native return needs an owned cache outside synchronization.

The image supplies actual allocation enforcement. Existing address-space/core/file/descriptor/CPU/process-group/time limits remain. The image-plus-unit probe is permitted; original22 keeps its unchanged 8 MiB hard file limit. Recovery/hash/output phases and the outer 20-minute lifetime are finite. The total lifetime can interrupt an always step; neither this source nor a green workflow guarantees ephemeral storage survival. A mutating/unclosed image may supply only incomplete failure data. This is a trusted reviewed runner, not a hostile-code sandbox or protection against other namespace writers.

Actual artifact upload and native independent verification remain separate gates. Authenticate the exact run/attempt, terminal result, artifact ID, actual archive size/digest and new allocation admission before downloading. Verify every recorded source/control/image byte and the entire archive without executing, mounting or extracting fixture contents. Inspect original22 receipt/proof, actual quota/RAM facts, before/after source identity, closure, full image length/hash and every missing/omitted/error flag. A green check, manifest or artifact ID alone proves none of those facts. No retirement, deletion, benchmark result or scientific qualification follows from this job.
