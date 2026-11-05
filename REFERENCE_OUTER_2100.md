# STRICT2.1GB outer-volume experiment

This separately named profile is unqualified. Select workflow input
`transport_profile=inside-outer-2100` to request reservation identity
`reference-inside-outer-2100-v1`. The workflow allocates an actual
2,100,000,000-byte outer image and requires an actual 2,200,000,000-byte
allocation to fail with ENOSPC on its mounted ext4 filesystem. Formatter,
loop/backing identity, filesystem context, nested setup, parent/worker,
freeze, upload and qualification proofs must agree on the explicit profile.
An observed smaller file or a smaller accounting estimate cannot select it.

`legacy-external` remains the workflow default. `inside-outer` retains its
2,300,000,000-byte image and 2,400,000,000-byte probe. The default Python
`growth_plan` API retains that exact geometry, even when the process selects
the new runtime profile. A pure strict-plan calculation requires both inputs:

```sh
python3 scripts/reference_internal_transport.py plan BASELINE_BYTES \
  --profile reference-inside-outer-2100-v1 --image-bytes 2100000000
```

The strict profile's maximum new allocation is 3,546,000,000 bytes. Its branches
are 2,400,000,000 bytes during packing, 2,895,000,000 bytes for verified bundle
upload and 3,546,000,000 bytes for failed-pack exact-results-image upload.
The fresh all-attributable baseline must include the unchanged 2,000,000,000-byte
global reserve. Admission requires the total to remain strictly below
12,000,000,000 bytes; the hard budget remains 15,000,000,000 bytes.

The frozen full workload remains 5,400 cells and 5.4 million samples for each
selected reader profile, with its existing seeds and checks. Supported
verification, race checks, 30-second fuzz runs, complete metadata and raw-byte
comparisons, tracked-source and executable tmpfs policy, per-cell source checks,
guest RAM, deadlines, cleanup and inode policy remain required. The named
600-second transport verification policy and legacy 210-second policy retain
their separate meanings. Packing still requires 921,000,000 free bytes,
including controls and the unchanged 500,000,000-byte filesystem floor.

Pure tests and shell command probes establish only control behavior. They
allocate no large image and demonstrate no Linux capacity, successful recovery
or benchmark completion. Historical 2GB supported-verification/clean successes
do not demonstrate that the full workload fits this 2.1GB profile. Fresh
supported Linux smoke, complete transport verification, independent review,
security review and fresh global admission are needed before a full attempt.
Full 1/4/16-reader qualification remains NOT RUN for this profile.
