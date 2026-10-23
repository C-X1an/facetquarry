# Engineering decisions
| Decision | Reason | Alternative / cost |
|---|---|---|
| Original Go index, standard library only | Inspectable algorithm and small installation | Rust/C++ are viable; language prestige is not the objective |
| Offline immutable generation | Read ownership is tractable; eliminates online transaction machinery | Updates require rebuild; no live database claim |
| Host-selected tenant scope and separate graphs | Query cannot choose a foreign graph | Host remains fully trusted; no arbitrary ACL or timing privacy |
| Float32 storage, float64 squared L2 | Explicit reproducible numeric contract | Not SIMD-optimized; ties ordered by ID |
| Small eligible set exact fallback at 256 | Simple disclosed comparison point | Threshold is not learned or proven optimal |
| Filtered graph bridges within one tenant | Avoid naively disconnecting all nonmatching nodes | Approximate stopping can still miss eligible neighbors |
| Empty eligible set uses exact plan | An empty set can be exhaustively established without distances | Explicit graph requests disclose this exact shortcut |
| Fresh no-clobber generation files | Preserve older snapshots on failed build/save | Requires hard-link-capable filesystem; no portable power-loss guarantee |
| Generation digest, not authentication | Detect accidental corruption and bind results to bytes | A malicious writer can recompute the hash |
| Compatibility go.mod, separate reference pin | Permit honest development checks in a constrained old runtime | Only Go 1.27.3 qualifies the designated reference-toolchain gate |
| Private control outside public git root | Prevent accidental research/resume/prompt disclosure | Start Codex at the handoff parent, publish only public/ |

## Mutant-selection correction
The first exact-label control changed an intermediate assignment. A later budget guard corrected that value, so the mutation did not create an externally observable defect. Its surviving result was retained. The revised control changes the final budget-exhaustion label; the unchanged behavioral test must reject it. This is a corrected negative-control design, not a relaxed product assertion.
