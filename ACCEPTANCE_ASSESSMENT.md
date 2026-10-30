# Current acceptance assessment

The locked [acceptance specification](ACCEPTANCE_SPEC.md) is unchanged. The older [criterion ledger](verification/criterion_status.json) retains its recorded source and receipts; this update does not relabel those results as current-source evidence.

[Run40946413302](verification/published/forced-trim-failure-40946413302.json) measured commit`51f8fae6ba348b648c4a334bfa3aad62a1bcf841`, technical source`c345846b4e0e2a85f259e51e9672a1acaf44773911fb7c997e1757f0628a4b1c`. Later producer and provenance-checkpoint repairs do not inherit its passes. Native392reference controls passed with27explicit skips at repair source93d9d64e; supported checks remain pending.

| Gate | Exact measured scope | Remaining requirement |
|---|---|---|
| Supported verification/reproduction | Go1.27.3 main and clean commands PASS; each488Python tests with7explicit skips | Repeat affected gates on repaired source; skips do not satisfy excluded platform/role checks |
| Oracle/fuzz controls | Actual1,000-seed oracle command and two30-second fuzz campaigns PASS; raw comparisons/corpus inventoried in retained image | No independent native raw replay claimed; preserve complete current-source evidence |
| APT and storage controls | Actual pinned partial-directory handoff,50,112observed nested inodes, full counter-based physical charge and retained replay PASS | Successful complete provenance selection, actual trim and intended timeout control remain unproved |
| Capacity | Post-copy1,017,532,416available bytes and49,622available inodes met the unchanged historical reference floors before smoke | Historical floor is not a full-output upper bound or full-run fit guarantee |
| AC-016/017 frozen performance | Nonqualifying one-reader smoke:21cells/672successful samples, no target cells or complete five-seed group | Complete current frozen1/4/16-reader measurements and required target outcomes |
| Retention/evidence | All available packet bytes and whole image SHA256/CRC checked; runner read-only recovery PASS | Complete controller retention remains false; no native ext4 member walk or scientific replay |
| Public/security source binding | Run31 online dependency scan PASS at its measured source | Fresh repaired-source security review and full public tree/history audit before publication |
| AC-013/manual gates | Browser and owner gates remain unmet | Actual qualifying manual evidence; generated output does not replace it |

Overall assessment: **EXPERIMENTAL / NOT RELEASE QUALIFIED**. Detailed failures, source identities and historical checkpoints remain in [VERIFICATION_REPORT.md](VERIFICATION_REPORT.md).
