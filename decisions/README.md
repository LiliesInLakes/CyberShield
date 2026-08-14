# Decision records

Architecture/design decisions with real tradeoffs, one file each. Not a bug log —
that's `CLAUDE.md` §6 (traps, `T1`…) and `docs/PROJECT_LOG.md` (full history).
A decision here is something a future contributor could plausibly reverse
without reading the whole log; the file exists so they see the tradeoff first.

| # | Decision | Status |
|---|---|---|
| [0001](decision-0001-evidence-spine.md) | One merged evidence spine, not per-layer artifacts | Accepted |
| [0002](decision-0002-no-brand-derivation.md) | Bank whitelist is hand-curated; no fuzzy or auto-derived matching | Accepted |
| [0003](decision-0003-yara-scan-granularity.md) | YARA scans per-file/per-class, never concatenated or whole-container | Accepted |
| [0004](decision-0004-l4-zero-score-weight.md) | L4 (GenAI) contributes zero points to the L5 score | Accepted |
| [0005](decision-0005-local-provider-stub.md) | On-prem LLM path is a raising stub, not a fallback | Accepted |
| [0006](decision-0006-gate-arming-threshold.md) | Score gates refuse to arm below B≥213 malware support | Accepted |
| [0007](decision-0007-cicmaldroid-corpus.md) | CICMalDroid banking set kept separate from the main corpus | **Open** |
| [0008](decision-0008-l1-scratch-on-ntfs.md) | L1's heavy per-sample output moved to the NTFS data partition | Accepted |
| [0009](decision-0009-pipeline-exit-codes.md) | Early stop is not success — exit codes carry corpus completeness | Accepted |
| [0010](decision_dynamic_analysis_automation.md) | L2 dynamic analysis automation: DroidBot + Frida + mitmproxy, no GenAI in L2 | **Open** |
