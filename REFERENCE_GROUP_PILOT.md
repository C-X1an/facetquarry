# Frozen benchmark group pilot

The workflow on `frozen-reference-group-r4` runs the first frozen group with four concurrent readers. It builds FacetQuarry with the pinned Linux Go SDK and exercises the bounded results filesystem and transport on the GitHub-hosted Ubuntu runner. Successful output covers 60 of the expected 5,400 cells for the four-reader profile. The coverage record retains the full denominator.

The workflow can export a verified bundle, a closed results image after a failure, or a small receipt for unresolved custody. Each artifact is tied to one commit and the first workflow attempt. Runner-side checks establish the artifact candidate. Download and verification are required to establish durable custody.

The release assessment and previously published verification reports apply to their recorded source versions. This pilot grants no release qualification. The complete reference profiles at 1, 4 and 16 readers each require all 5,400 cells and the locked acceptance checks.

The first attempt stopped during backing-file allocation verification before the benchmark ran. The retry records apparent length and allocated blocks independently and verifies the loop device size before the workload.

The second attempt measured backing allocation and stopped later in provisioning. This retry records each provisioning stage, including the actual filesystem allocation refusal. The prior failures are retained.

The third attempt observed the expected filesystem refusal and then ran out of space while writing the receipt. This retry releases the exclusively owned probe before persisting the receipt and rechecks the free-space floor.
