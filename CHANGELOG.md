# Changelog

## 2026-10-30 — run31 evidence and pending provenance repair

[Run40946413302](verification/published/forced-trim-failure-40946413302.json), commit`51f8fae`/source`c345846b`, passed supported Go1.27.3 verification, clean reproduction and online scanning. Actual APT ownership handoff, nested inode geometry and retained physical-allocation replay passed. The one-reader smoke completed21cells/672successful samples; it does not qualify the full matrix.

The workflow failed before provenance copy, trim deletion or the deliberate timeout child. Post-download APT caches total125,265,213bytes; the complete trim-time selection was not retained, so its exact bytes/entry count remain unknown. The80,000,000-byte provenance ceiling remains unchanged. Producer/checkpoint repairs passed392native reference controls with27explicit skips at source93d9d64e; independent read-only review closed both demonstrated repair gaps. Fresh supported execution and repaired-source security review remain pending.

All earlier failures and curations remain preserved. See [the verification report](VERIFICATION_REPORT.md) and [acceptance assessment](ACCEPTANCE_ASSESSMENT.md); release remains **NOT QUALIFIED**.
