# 0001 — One merged evidence spine, not per-layer artifacts

**Status:** Accepted

## Context
Each layer needs its own artifact (`L0/artifacts/<sha>/evidence.json`,
`L1/artifacts/<sha>/analysis.json`, …) for debugging and reprocessing. But L5
scoring, L6 reporting and export all need one coherent view of a sample, and
`L0/ingest.py:run_l0` **destructively overwrites** `evidence.json` on every run
(T10) — so a shared record cannot live inside a layer's own directory.

## Decision
Every layer writes its own artifact, and additionally folds a distilled view
of itself into one spine at `artifacts/<sha256>/evidence.json`
(`spine.py:SPINE_ROOT`). Findings carry a stable `fingerprint` for diffing
across runs even as `id`s shift when findings are inserted.

## Consequences
- Downstream layers (L4, L5, L6) depend only on the spine, never on another
  layer's artifact path — confirmed when L1's artifact root moved to a
  different filesystem (0008) and nothing downstream needed to change.
- Two representations of L1 findings now exist (`L1/artifacts/.../analysis.json`
  and the spine's `layers.l1`); they must be kept in sync by `spine.update_layer`,
  not by hand.
