# Plan — L3 unified, pipeline-extracted dataset

**Status:** in progress (started 2026-08-24)
**Author:** implementation session

## Context

L3 today trains on **LAMDA's precomputed 4,561-column parquet** (`L3/train.py`),
but at inference the pipeline extracts its own tokens with `L3/features.py::extract_from_apk`
and matches them to LAMDA's vocabulary. Measured density on our own samples is only
**0.4–1.8%** vs LAMDA's 2.5% (see `L3/model/metrics.json` caveats) — i.e. our extractor
cannot fully reproduce LAMDA's token spellings. That is **train/serve skew**: the model was
fit on feature values a different extractor produced.

Decision (user, 2026-08-24): build a **unified dataset whose every column is extracted from
the APK by our own pipeline**, over the corpus we already hold. Drop the LAMDA dependency for
this model. This makes train and serve use the identical extractor, and lets the column space
include India-specific tokens LAMDA never had.

Feature-column source (chosen): **corpus-derived vocabulary** — columns = tokens
`extract_from_apk` actually emits across our corpus, filtered by document frequency.

## Population (from `corpus/labels.json`, verified)

- malware 3,090 = banking_cicmaldroid 2,451 + malware_raw 625 + india 14
- benign 604 (F-Droid)
- Usable rows = those whose spine's `identity.source_apk` is still on disk (CICMalDroid,
  F-Droid, malware_raw *loose* APKs, india). Zip-member malware whose temp APK was deleted are
  skip-counted (same contract as `L3b/dataset.py`); a later pass can re-read them from the
  password-protected zips via `tools/corpus_run.py`'s reader if the count is too low.

## Design

Reuse `L3/features.py::extract_from_apk` (already the pipeline's extractor, already used by
both L3 and L3b) and the metric helpers `auroc` / `expected_calibration_error` from
`L3/train.py`.

### New modules

1. **`L3/unified_features.py`**
   - `CorpusVocabulary` — `{token: col}` built from the corpus, `save()/load()` as JSON.
   - `build_vocabulary(token_sets, min_df, max_df_ratio)` — keep tokens with
     `min_df <= df <= max_df_ratio*N`. Drops singletons (overfitting) and near-ubiquitous
     base-rate tokens (T6/T23 discipline, though a learned model tolerates them).
   - `vectorise_unified(tokens, vocab) -> (int8 vector, diagnostics)`.

2. **`tools/build_unified_dataset.py`** — two resumable stages:
   - *Stage extract*: for every labeled sample, `extract_from_apk` → token set, appended to
     `L3/model/unified_tokens.jsonl` (`{sha,label,source,subclass,family,tokens}`). Resumable
     and the expensive part; separated so vocab tuning never re-extracts. Malware safety: reads
     one on-disk APK at a time, never bulk-extracts (§4).
   - *Stage build*: from the cache → `build_vocabulary` → matrix. Writes
     `L3/model/unified_vocab.json` and `L3/model/unified_dataset.npz`
     (`X, y, sha256, source, subclass, family`) + `unified_dataset_skips.json`.

3. **`L3/unified_train.py`** — load npz, **group-disjoint split** (group = family when known,
   else source) so variants of one family/source never span train/test (B37/T24 discipline),
   LightGBM + isotonic calibration on a held-out slice of train groups, save
   `L3/model/unified_lgbm.joblib` (`{model, calibrator, vocab_path}`) + `metrics.json`. Report
   **held-out** AUROC/ECE only; never in-sample. Honestly stamp that most malware lacks family
   labels so the split is source-grouped, not fully family-disjoint.

4. **`L3/unified_predict.py`** — load vocab + model, `extract_from_apk` → `vectorise_unified`
   → prob, refuse on implausible density, `spine.update_layer(sha,"l3",...)`. Same
   `layers.l3` contract as `L3/predict.py` (no findings emitted — a generic prior must not
   inflate the malware-category count). `predict.py` prefers the unified model when present.

### Scoring (unchanged mechanism)

`L5/score.py::apply_ml` already reads `layers.l3.summary.prob_malicious`, clips to ±10, and
refuses to reach Critical alone. Once spines carry `l3`, flip `ml.enabled: true` in
`L5/policy.yaml` (a separate, reviewed step — measure first).

## Verification

- Extraction sanity on ~20 mixed samples: vocab non-empty, per-sample density plausible,
  banking vs benign token counts sane.
- Full build → dataset shape, class balance, skip breakdown.
- Train → held-out AUROC honest (a source-grouped split should NOT give AUROC ~1.0; if it
  does, investigate leakage — near-dup CICMalDroid rows).
- `unified_predict.py` on one benign + one malware APK writes a plausible `layers.l3`.
- Full pytest stays green; add tests for `unified_features` vocab/vectorise + the density
  refusal.

## Out of scope (tracked separately)

- L2 `l2_engine.py:314-364` scope bug (globs all sandbox artifacts) — small, separate fix.
- Re-reading zip-member malware APKs for extraction — only if usable-row count is too low.
- MalRadar family labels for a fully family-disjoint banking split.
