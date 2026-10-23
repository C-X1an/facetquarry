# Contributor contract
Purpose: original bounded filtered vector-search engineering experiment.
Read ACCEPTANCE_SPEC.md, PRD.md, ARCHITECTURE.md, THREAT_MODEL.md, API_SPEC.md and LIMITATIONS.md before changing behavior. Locked acceptance and phase definitions may not be weakened; record an explicit exception with evidence instead.

Use one writer per path; preserve existing work. Keep index generations immutable, scope host-derived, distance work charged before computation, and approximation distinct from exactness. No ANN library, model API or database dependency in the core.

Commands: make bootstrap; make build; make format (writes); make fmt (checks); make lint; make check; make test; make integration; make acceptance; make race; make property; make fuzz; make mutation; make security; make security-online; make benchmark-smoke; make benchmark; make demo; make clean-verify; make release-verify.

Record real execution with scripts/evidence.py. Preserve failures, source hashes, raw output and exit codes. Do not invent results, weaken tests, hide skips, replace integration with mocks, or represent a target as measured. Independent review must initially be read-only; self-review is not independent.

Only source, tests, synthetic fixtures, reproducibility tools, public docs and deliberately reviewed evidence belong here. No secrets, private resumes/research, model routing, chat logs, raw personal environment or generated indexes. Keep generated files in owned ignored .local/.cache paths. Inventory all attributable resources; scripts/disk_guard.py is monitoring, not a hard quota.

Missing external access blocks only that task. Leave precise status and continue independent work. Full release requires every applicable locked gate with current evidence; green core tests alone are insufficient. Update VERIFICATION_REPORT.md and CLAIMS_EVIDENCE.md after meaningful verified changes.
