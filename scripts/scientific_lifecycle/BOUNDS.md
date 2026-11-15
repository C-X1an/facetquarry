# Lifecycle resource contract

These are finite candidate bounds, not measured enforcement or an execution grant. Actual Linux controls, quota/RAM proof and complete custody remain NOT RUN. The disk is 256 MiB; the distinct RAM hard limit is 512 MiB.

| Quantity | Bound |
| --- | ---: |
| Fully allocated original quota image, all unused headroom included | 268,435,456 B |
| Child/supervisor RLIMIT_AS | 536,870,912 B |
| Entire fixture logical regular-file data | 100,663,296 B |
| Entire fixture accounted source / entries including root | 167,772,160 B / 4,096 |
| Maximum allocation unit | 8,192 B |
| Required actual available space before producer, after staging/controls | 201,326,592 B |
| Single regular-file body | 8,388,608 B |
| Raw relative path / depth | 512 B / 16 components |
| Neutral header / framing prefix / magic | 2,048 B / 4 B / 11 B |
| Maximum neutral blob | 109,070,351 B |

Source accounting is `100663296 + 4096*(2*8192) = 167772160`. Each non-directory charges `max(st_size,st_blocks*512)+2*8192`; directories charge two units and become unsafe if their size/allocation exceeds one unit. Actual host allocation still needs inventory. No unknown entry may be silently discarded to meet a bound.

Neutral maximum is `100663296 + (4096+1)*(2048+4) + 11 = 109070351`. The additional header is the footer. Names are canonical base64 data, including non-UTF8 names. Safe regular bodies are copied exactly; unsafe entries have explicit metadata without following/reading their bodies. Neutral framing success alone is not complete source semantics. No archive extraction, compression ratio or executable payload is assumed.

Peak custody has SIX neutral instances: runner A/B, cloud A/B and native A/B. Their payload maximum is `6*109070351 = 654422106 B`; adding two allocation units for each gives 654,520,410 B, below four source equivalents (671,088,640 B). A/B remain separate even after a failed B. The full raw image remains mandatory regardless of neutral success.

| Base placement reservation | Bytes |
| --- | ---: |
| Original image | 268,435,456 |
| Four source equivalents covering all six neutral instances | 671,088,640 |
| Two full-image copies: cloud and native, original counted above | 536,870,912 |
| All admitted source/control/log/runner overhead | 16,777,216 |
| Base lifecycle job | **1,493,172,224** |

The unchanged SPI reservation is 855,638,016 B / 20,608 entries. Lifecycle adds 637,534,208 B to that reservation. For additional growth G, use lifecycle `other_growth_bytes=G` and SPI `other_growth_bytes=G+637534208`; both must evaluate the same complete peak.

The base does not include additional connector FileRefs, browser caches/downloads, packaging/encoding, sync mirrors, another native copy or image, failed retries, or other jobs. One possible connector copy of the raw image plus both neutral files is `268435456+2*109070351 = 486576158 B`, additive to the base. Add its metadata/container overhead and every further copy separately. An object reference and cloud object may be counted once only when actual evidence proves they are the same allocation; a file-backed reference is additional. Choose a native cache outside synchronization and inventory all other mirrors. Unknown/unbounded growth refuses transfer. Preserve failures and obtain fresh admission before a distinct retry.

Every attributable allocation, including external caches and cloud/native copies, counts. Admit only if `baseline_excluding_reserve + other_growth + global_reserve + 1493172224 < 12000000000`, with reserve at least 2,000,000,000 B; the absolute project cap remains 15,000,000,000 B. No historical inventory supplies current admission. Monitoring is not hard quota enforcement.

Preparation requires actual full image size/block allocation, ext4 loop identity bound through mountinfo/sysfs/actual block node/backing path and owned image inode, offset/capacity/geometry, and real ENOSPC denial beyond image capacity. Use 4 KiB ext4 blocks, no reserved percentage and `nodiscard`. After staging/retained controls, actual available bytes must still be at least 201,326,592. If a 256 MiB filesystem cannot meet this, refuse without weakening the 160 MiB source cap or deleting evidence. All source/packet/control-test allocations inside the image are already charged at full image capacity.

Source packet, `job/control` and neutral exports outside the image remain attributable. The external controller must bound complete control/source evidence to at most 5 MiB at each of runner, cloud and native placements, leaving 1 MiB of the 16 MiB overhead for remaining metadata. Additional connector copies are G. Combined staged lifecycle and SPI packets, including manifests, must fit 1 MiB before producer launch. A separate controls root is new and hard-bounded; preserve it in the image rather than deleting it to reclaim headroom. No uncounted temporary archive or second image is allowed.

SPI output keeps at most 524,288 B per stream; excess observed bytes cause termination while the retained prefix remains. Setup/finalization streams keep 65,536 B each, memory-proof streams 16,384 B each. Children inherit only LANG/LC_ALL/TZ, no credentials or path/search/cache variables. Use pinned installed executables and trusted root-owned stdlib/library trees, no runtime acquisition.

Every child independently receives RLIMIT_AS `(536870912,536870912)`, NOFILE 64, disabled cores and CPU 120/121 seconds. SPI FSIZE is 8 MiB; setup/finalization helpers may use image-sized FSIZE. The real unprivileged probe must observe the kernel limit pair and a denied 536,870,913-byte allocation. RSS and contextual cgroup counters do not prove enforcement or per-child OOM attribution.

SPI wall time is at most 120 s, helpers 90 s, memory probe 20 s. TERM has 2 s grace before KILL, with bounded drain/reap/group checks. Collection never starts before quiescence. Streaming inventory/copy/readback/hash passes check a 180 s deadline with 64 KiB reads; this cannot stop a kernel syscall stuck in I/O. The external finite lifetime must preserve owned storage on timeout/failure. A lost host never implies complete custody.

JSON documents cap at 256 KiB; lexical depth 24, 32,768 tokens, encoded strings 8,192 B and signed 64-bit integer tokens of at most 20 bytes. Duplicate keys/floats/nonfinite values refuse. Error records cap at 2 KiB, error lists at 16 KiB with explicit overflow/truncation and bounded nested context/leaves. A receipt exceeding its bound is failure with raw source retained. All existing A/B prefixes are independently hashed even when strict framing/copy/cleanup fails.

Finalize only after terminal producer/group proof and matching source/admission/image identity. Use one ordinary unmount and require no same-device mount or remaining backing association before streaming/fsyncing all 268,435,456 image bytes. Cloud/native verification must read actual complete bytes independently; never mount/extract the returned image. Originals and failed prefixes are never deleted, moved or replaced by this lifecycle. These controls concern synthetic integration only and cannot qualify scientific matrices or release gates.
