# Original reference artifact transport

This auxiliary branch reanalyzes the retained artifact from run39973710730. It does not run engine measurements or change the measured main commit625582eb753e7bec76e057a8f368f62f6aaf3d1d, technical source4949a016d1fc650cc80f18583e18b0ed487820801091508ea34b0a6b658a7dfe. The auxiliary commit and script hashes are recorded separately. This workflow uses --analysis-only and does not create a duplicate transport bundle. The original packaging run and its failure receipts remain retained.

The original784433491-byte GitHub artifact exceeds the connector's512MiB limit. A packaging-only workflow retrieves that fixed same-repository artifact, validates public metadata and the full ZIP SHA256, reanalyzes its recorded results, and creates a bounded solid XZ member transport. API authentication is never forwarded to storage. The original cloud artifact is retained.

The transport recovers exact bytes of every original ZIP member, verified against recorded SHA256. It identifies the original outer ZIP; it does not reproduce the ZIP container byte for byte. Gzip recipes are admitted only after exact recompression proof. Otherwise the original member bytes are stored unchanged. Compressor-version differences during recovery fail hashes honestly.

The workflow requires an actual2GB loop filesystem with a failed oversized allocation probe, bounds process memory/CPU/runtime and admits the combined upload including receipts below450MB. A transport admission failure retains explicit diagnostics and exclusions rather than claiming successful transfer. Failed analyses remain failed; an artifact upload or packaging success cannot qualify benchmark recall, reference hardware, manual review or release gates.

The included analyzer recomputes5400 frozen full-profile cells,45 individually qualified recall targets,1080 five-seed intervals and972 paired comparison groups. Its resampling unit is workload/build seed, jointly changing corpus, queries and graph. It checks recorded responses against exact-baseline IDs; separate collector/oracle checks remain distinct. Five seeds and shared-host conditions limit uncertainty claims. See each generated analysis report for methods and limitations.

Run the small synthetic helper controls with:

```sh
python3 -m unittest discover -s scripts/evidence-transport -p 'test_*.py' -v
```

These controls establish helper behavior only. Live download, actual quota enforcement, compression size and benchmark acceptance require retained execution records. The auxiliary workflow must not be merged over the measured main workflow.

Profile selection first inspects bounded coverage records. Exactly one full/current-source/frozen-config candidate is required, independent of PASS/FAIL outcome. Every summary/sample in that folder, including failed and unexpected cells, is retained. Other profiles and their identities are explicitly listed as excluded from this analysis; their original bytes remain in the unchanged original artifact and lossless transport.
