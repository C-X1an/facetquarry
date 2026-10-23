# Recorded source4949 results

Measured commit625582e, technical source4949a016d1fc650cc80f18583e18b0ed487820801091508ea34b0a6b658a7dfe. These are historical as soon as implementation/tests change.

Full primary collection:5400/5400 cells,5.4million successful timed calls, zero call errors/zero-duration samples. Recall target FAIL:33 of45 pass,12 fail, all in ties. For each correlation, seeds11/23/47/83/131 yield recall0.90/1.00/0.90/0.90/0.40. Uniform minimum0.9865; clustered minimum0.9985. No averaged interval overrides a failing individual seed.

Supported Go1.27.3 Linux verification, race/oracle/controls/two30s fuzz campaigns, clean committed reproduction and online govulncheck passed. Shared host/process4CPU/8GiB constraints do not establish the named4-vCPU/8-GB reference environment; original reference_host_verified remainsfalse. Reader4/16 profiles unrun. Browser inspection and declined owner walkthrough are unrun.

All five-seed and paired analyses include every frozen cell, including failures. Bootstrap unit is the joint workload/build seed,2000 resamples, seed20261023. Five repeated timings are not independent datasets. Exact numerical-oracle qualification is separate from benchmark ID/order/filter checks. See analysis.json for limitations and manifest.json for byte provenance. Canonical security reports retain their declared historical baseline/delta scope; no whole-repository rescan at625 is claimed.

The original transport orchestration failed selecting mixed full/smoke profiles; its separately successful lossless27738-member packaging and verification remain retained. Corrected reanalysis succeeded without measuring the engine again. No output status or hash was rewritten.
