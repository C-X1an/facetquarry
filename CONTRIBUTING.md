# Contributing
Start with the README, API contract, architecture and threat model. Keep the core small: no network service, ANN dependency or model API is required.

Run `make ci property fuzz security`. Use `make format` before `make fmt`. Include a regression test for behavioral changes and preserve source-bound execution receipts. Do not weaken the locked acceptance specification to accommodate a defect. Propose a documented criterion exception only when the specification is objectively mistaken and obtain an independent assessment.

Changes to approximate search must retain unfavorable recall/work results. Exactness, eligible result count and graph-method completion are distinct properties. Do not publish generated indexes, real user data, secrets, private research or raw agent transcripts. Public tests and reproducibility scripts are part of the product, not disposable development clutter.

The reference release platform is Linux x86_64 with the pinned Go version. Other platforms need their own runtime evidence. Production hardening and full acceptance are not implied by a successful build or CI badge.
