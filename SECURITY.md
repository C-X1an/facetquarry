# Security policy and boundary
FacetQuarry is experimental local retrieval software. Its design uses host-fixed tenant partitions and bounded input/search contracts; this is not a claim of audited security or production readiness.

Do not expose the CLI through an unauthenticated web service. Never let client input choose the tenant scope, snapshot path, output path or build options. Metadata filters refine relevance, not authorization. The process owner and OS can read every loaded partition. No protection from timing inference, malicious host code or filesystem administrator is provided.

Use synthetic/publicly licensed data in demos. Do not commit credentials or employer material. SHA-256 snapshot/receipt digests detect accidental changes but are not signatures or third-party attestation. See THREAT_MODEL.md and LIMITATIONS.md.

Until a private vulnerability reporting channel has actually been configured, do not claim one exists. For sensitive findings use GitHub's private vulnerability reporting only after the repository indicates it is enabled; otherwise request a private maintainer contact without posting exploit details or secrets in a public issue. Public non-sensitive correctness bugs should include a minimal synthetic reproducer, source revision, runtime, expected/observed behavior and commands.

Only a source revision with a passing release audit is supported as a qualified experimental release. No long-term-support commitment is made. Security dependency/toolchain updates require rerunning affected validation, not merely changing version text.
