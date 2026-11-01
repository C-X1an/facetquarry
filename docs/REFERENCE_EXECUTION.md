# Explicit reference execution policies

`reference-tracked-source-tmpfs-v1` preserves the guest's three existing QEMU
exports. Before dropping privileges it moves the original project mount to a
read-only origin, admits the complete tracked checkout plus both native binaries
against24MiB/8192inodes, verifies both originals and copies, binds the original
results/cache directories and read-only Git metadata, and remounts `/project`
read-only. The workload continues at its original paths. Original and copied
source/binary checks remain before, during and after execution. Scientific output
stays on the bounded disk. The strict qualification branch binds the exact tracked
selection, project export, mount roots, capacities, execution and provenance.

The source view plus4MiB`/tmp`,1MiB`/run` and1MiB`/dev` totals30MiB. The existing
32MiBRAM-filesystem ceiling and16MiBinitrd bound remain separate and unchanged.
Actual mount behavior, fit and full-run speed require measured Linux execution.
Legacy execution retains its16MiB`/tmp` and original qualification path.

`reference-verify-600s-v1` explicitly changes complete verification time reservation
from210to600seconds. The parent retains12seconds for cleanup and30for its receipt,
leaving558seconds for its worker. Premeasurement admission reserves20230seconds;
equality refuses. The package workflow step allows40minutes for1710seconds packing
plus600seconds verification and bounded transitions. Benchmark limits and all
complete/repeated live, metadata, fuzz, source, package and freeze checks remain.

Verification publishes durable ordered starts and completions for admission,
bundle decode, manifest read, first comparison, revalidation, second comparison,
freeze and retained-outer validation. Cutoff receipts retain the active stage.
Observations alone never establish complete comparisons or a successful freeze.

CLI flags select both policies explicitly. Unknown selections fail. Default and
legacy Python APIs ignore ambient policy variables. Native fixtures, source
review and smoke measurements cannot qualify a complete frozen full matrix.
