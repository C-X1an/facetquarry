# Changelog

## 2026-10-30 — actual trim headroom refusal and named pressure policy

[Run41008670963](verification/published/forced-trim-headroom-failure-41008670963.json), commit`cdf3f846`/source`93d9d64e`, passed supported Go1.27.3 verification, clean reproduction, online scanning and the21-cell/672-sample KVM smoke. Main verification ran495Python tests with7explicit skips. All20APT calls used the empty cache-name options, and the inspected owned inventories and complete selection contained neither binary cache. Complete provenance253entries/1,777,069logical bytes was retained. Guest trim passed, removing1,142entries/284,250,112accounted bytes. Its net availability gain was281,911,296bytes; accounted removal is not guaranteed free-space credit.

Packaging then refused881,876,992available bytes against the unchanged921,000,000-byte requirement:39,123,008bytes short. Six final control stages passed; the intentional timeout was **NOT RUN**. The workflow remains **FAIL**. Every available packet byte, supported receipt stream and whole1.1GBimage SHA256/CRC was verified; runner read-only recovery matched1,149members/19,133,375bytes. No native ext4 member walk or scientific raw replay was performed.

Current repair source`e9d3f61469917718bb04f29784f8f08343d5a7eba176a0aa3b017b856bdc2fe3` adds the explicit `reference-trim-pressure-700mb-v1` production policy while retaining the exact legacy600MBplanning API. The700MBtarget still forces the same pre-pack admission refusal; actual post-trim admission remains mandatory before any child launch. The500MBfloor,401MBpackage,20MBcontrol and70MBdiagnostic margins,2GBglobalreserve and all deletion/retention guards remain unchanged. Native receipt`20261030T062438Z-2f5cfda01e` ran399reference tests:372passed/27explicit skips. Both pre-branch and post-trim guard mutations were caught, restored controls passed, and independent read-only review closed the repair. Actual700MBLinux execution, current security review, frozen full1/4/16 and manual/release gates remain pending.

## 2026-10-30 — run31 evidence and pending provenance repair

[Run40946413302](verification/published/forced-trim-failure-40946413302.json), commit`51f8fae`/source`c345846b`, passed supported Go1.27.3 verification, clean reproduction and online scanning. Actual APT ownership handoff, nested inode geometry and retained physical-allocation replay passed. The one-reader smoke completed21cells/672successful samples; it does not qualify the full matrix.

The workflow failed before provenance copy, trim deletion or the deliberate timeout child. Post-download APT caches total125,265,213bytes; the complete trim-time selection was not retained, so its exact bytes/entry count remain unknown. The80,000,000-byte provenance ceiling remains unchanged. Producer/checkpoint repairs passed392native reference controls with27explicit skips at source93d9d64e; independent read-only review closed both demonstrated repair gaps. Fresh supported execution and repaired-source security review remain pending.

All earlier failures and curations remain preserved. See [the verification report](VERIFICATION_REPORT.md) and [acceptance assessment](ACCEPTANCE_ASSESSMENT.md); release remains **NOT QUALIFIED**.
