# Current acceptance assessment

Current repair source`e9d3f61469917718bb04f29784f8f08343d5a7eba176a0aa3b017b856bdc2fe3` adds the explicit `reference-trim-pressure-700mb-v1` production policy while retaining the exact legacy600MBplanning API. The700MBtarget still forces the same pre-pack admission refusal; actual post-trim admission remains mandatory before any child launch. The500MBfloor,401MBpackage,20MBcontrol and70MBdiagnostic margins,2GBglobalreserve and all deletion/retention guards remain unchanged. Native receipt`20261030T062438Z-2f5cfda01e` ran399reference tests:372passed/27explicit skips. Both pre-branch and post-trim guard mutations were caught, restored controls passed, and independent read-only review closed the repair. Actual700MBLinux execution, current security review, frozen full1/4/16 and manual/release gates remain pending.

[Run41008670963](verification/published/forced-trim-headroom-failure-41008670963.json), commit`cdf3f846`/source`93d9d64e`, passed supported Go1.27.3 verification, clean reproduction, online scanning and the21-cell/672-sample KVM smoke. Main verification ran495Python tests with7explicit skips. All20APT calls used the empty cache-name options, and the inspected owned inventories and complete selection contained neither binary cache. Complete provenance253entries/1,777,069logical bytes was retained. Guest trim passed, removing1,142entries/284,250,112accounted bytes. Its net availability gain was281,911,296bytes; accounted removal is not guaranteed free-space credit.

Packaging then refused881,876,992available bytes against the unchanged921,000,000-byte requirement:39,123,008bytes short. Six final control stages passed; the intentional timeout was **NOT RUN**. The workflow remains **FAIL**. Every available packet byte, supported receipt stream and whole1.1GBimage SHA256/CRC was verified; runner read-only recovery matched1,149members/19,133,375bytes. No native ext4 member walk or scientific raw replay was performed.

Overall acceptance remains **NOT QUALIFIED**. The locked criteria and all older source-bound ledgers remain unchanged.

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
