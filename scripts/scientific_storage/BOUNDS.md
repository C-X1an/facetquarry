# Revision 2 finite allocation and evidence bounds

These are conservative candidate bounds. They are not a quota grant or proof of
execution. The original first-source manifest and its failed/intermediate runs
remain historical and byte-preserved.

| Allocation | Bound |
|---|---:|
| Aggregate fixture logical content | 100,663,296 B (96 MiB) |
| Fixture entries, files and directories | 4,096 |
| Allocation plus parent-entry headroom per entry | 2 * 8,192 B |
| Complete fixture source reservation | 167,772,160 B (160 MiB) |
| Four additional source-copy equivalents | 671,088,640 B |
| Separate control/header overhead | 16,777,216 B |
| Integration arithmetic total | 855,638,016 B |
| Integration entries including copies/control | 20,608 |
| Maximum source packet | 16,777,216 B |
| Launcher on-volume minimum | 201,326,592 B |
| Candidate actual image capacity | 268,435,456 B (256 MiB) |
| Actual child/supervisor memory limit required | 536,870,912 B (512 MiB) |

The source reservation is 96 MiB + 4096 * 2 * 8192 = 160 MiB. The integration
total is 5 * 160 MiB + 16 MiB. The on-volume minimum is source + packet allowance
+ 16 MiB control allowance. External complete copies are outside the image;
requiring the combined 855,638,016 B as the image minimum would count their
placement incorrectly. The full image capacity is nevertheless charged once,
including all unused space and filesystem metadata.

The lifecycle candidate adds the image's unused-capacity headroom and two
complete raw-image export equivalents. Its base peak is:

`268435456 + 4*167772160 + 2*268435456 + 16777216 = 1493172224`.

Thus the lifecycle's integration admission must add exactly 637,534,208 B to
its own other-growth value before the launcher's unchanged 855,638,016 B
arithmetic is evaluated. The two expressions charge the same complete base
peak. No space is reclaimed merely because an image is sparse, a source is
compressible, a copy succeeded or the job is expected to terminate.

A neutral blob is bounded by 96 MiB data, 4097 framed headers of at most 2048 B
plus four framing bytes, and the fixed magic: at most 109,070,351 B. Both the
first blob and the second blob's failed or complete prefix must remain. Six
simultaneous instances (two remote, two cloud, two native) total 654,422,106 B,
within the four 160 MiB equivalents. This assumes no compression or equality
between failed copies. Temporary connector file references are additional:
one raw image plus two maximal neutral blobs add up to 486,576,158 B. Further
provider copies and mirrors are also additive; they cannot be hidden in a
success-only transport selector or silently deducted from the 2 GB reserve.

The candidate native custody path should be an explicitly inventoried owned
cache outside synchronization roots. If a synchronization copy can exist,
reserve its full size until actual provider evidence permits retirement.
Every current component of the global ledger, the unchanged 2,000,000,000 B
reserve, all job allocations and all other growth must total strictly below
12,000,000,000 B for a growth-heavy admission and always below 15,000,000,000 B.
A fresh inventory is necessary; old numeric examples never authorize a job.

The image must be newly and fully allocated, identity-bound to the actual loop
mount through mountinfo/sysfs, and tested with an allocation exceeding its
capacity that genuinely fails with ENOSPC. Before the payload, measured free
space must still cover the complete on-volume minimum. If actual geometry or
capacity cannot do that, refuse and preserve the setup; never lower source
bounds or label a declaration as enforcement. The 512 MiB memory limit needs
an independently recorded actual denial probe and actual inherited child
limit. No benchmark memory-fit claim follows from this small synthetic suite.

Collection begins only after producers are proven quiescent. Include the whole
fixture tree on every outcome, including failed/unrecognized/partial bytes.
Symlinks, unsafe identities, extended attributes, special objects, read errors,
bound violations and incomplete copies produce explicit incomplete custody.
Retain the source and every produced prefix. The closed full-image fallback
must already be admitted, pinned and independently byte-verified; no successful
normal-copy result authorizes deleting or dropping an unsafe tree.

All real enforcement, POSIX cases, transport custody and scientific gates are
NOT RUN for this revision until actual source-bound receipts establish them.
