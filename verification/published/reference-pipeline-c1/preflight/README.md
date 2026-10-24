# Reference pipeline preflight

These are actual bounded tooling checks. They do not establish a new engine measurement, VM cleanup, supported-toolchain release or full-matrix qualification. Each receipt retains its original technical source. The final workflow input validation changes source to `c1f4ced957a77739e0d2e60bb0fd9298f627f92ab90d0a0ed426d591be341473`; older hashes are not relabeled.

Independent read-only review reported the directory-format failure before repair, along with missing fuzz preservation, conditional guest-unit checks and incomplete source binding. The integrator repaired these, and the independent verifier passed eight byte-preservation controls. The 16 proof controls use synthetic 5,400-cell descriptors and a real tiny transport/ZIP; they do not simulate a successful VM or engine benchmark. The final input-handling delta was independently checked read-only. Workflow stage limits total352minutes within the360minute job, subject to actual runtime.

The lossless transport has 15 controls; the standalone analyzer has seven. Shell/Python parsing is a syntax check, not GitHub YAML validation. Actual full workflow, cleanup, source-bound clean reproduction and the repaired 1/4/16-reader matrices remain unrun at this checkpoint.

Curated receipts declare original and exported digests. Only local user/handoff path prefixes were replaced. Original successful and failed streams remain privately retained.
