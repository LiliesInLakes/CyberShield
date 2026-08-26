# 0011 — L3 trains on a unified, pipeline-extracted dataset (not LAMDA's parquet)

**Status:** Accepted (2026-08-24)
**Supersedes (in part):** the "L3 trains on LAMDA" direction from the two-agent
research debate (PROJECT_LOG §1). LAMDA stays available; it is no longer the
primary training source for the L3 prior.

## Context

L3 is a generic maliciousness prior bounded to ±10 points in L5. Two models
already exist on disk (`L3/model/lamda_lgbm.joblib`, `L3b/model/banking_lgbm.joblib`),
so training was never the blocker — the "empty model dir / needs 6 GB" notes were
stale.

The real defect is **train/serve skew**. LAMDA ships 4,561 precomputed binary
columns whose meanings live in `feature_mapping.csv`. At inference our pipeline
extracts its own tokens (`L3/features.extract_from_apk`) and matches them to those
columns — but measured density on our samples is only **0.4–1.8%** vs LAMDA's
**2.5%** (recorded in `L3/model/metrics.json` caveats). The model was fit on
feature values a *different* extractor produced, so a large fraction of LAMDA's
columns are never populated by our extractor and the ones that are may not mean
the same thing.

## Decision

Build a **unified dataset whose every column is a token our own pipeline emits**,
over the corpus we already hold, with a **corpus-derived vocabulary** (not LAMDA's
fixed schema). Train and serve then use one extractor, so there is no vocabulary
skew, and India-specific tokens LAMDA never had can become columns.

- Columns = tokens from `extract_from_apk` across our corpus, kept by document
  frequency (`min_df ≤ df ≤ max_df_ratio·N`), capped at the top-N by DF.
- A **relevance filter** (`L3.unified_features.meaningful_tokens`) keeps only the
  semantically meaningful tokens — permissions, intent-filter actions, hardware
  features, URL domains, and API calls into a curated set of **security-sensitive**
  framework classes (SMS, telephony, accessibility, device-admin, dex-loading,
  crypto, install, screen capture, …). It drops androidx/kotlin/library-signature
  noise and app-specific component class names.
- Modules: `L3/unified_features.py`, `tools/build_unified_dataset.py` (resumable
  extract → build), `L3/unified_train.py` (group-disjoint split, held-out-only
  metrics), `L3/unified_predict.py` (same `layers.l3` spine contract). Plan:
  `docs/plans/l3_unified_dataset_plan.md`.

## The tradeoff a future contributor must see

🔴 **The corpus is source-confounded.** Every benign sample is F-Droid and every
malware sample is CICMalDroid/GitHub — the *source* is almost perfectly correlated
with the label (T27). Consequences, all made explicit in the code and metrics:

1. Without the relevance filter, a model trivially learns "uses androidx →
   benign", which does not survive contact with a real benign banking app. The
   filter is what keeps the features behavioural rather than a library
   fingerprint.
2. Even with the filter, **any held-out AUROC is an UPPER BOUND**. `unified_train.py`
   stamps this in `unified_metrics.json` and flags AUROC ≥ 0.99 as probable
   source-artifact leakage, not detection skill.
3. A trustworthy banking false-positive rate still requires benign banking apps in
   the corpus (the hard-negative BFSI panel, T27). This model cannot supply one and
   must not claim to.

The split is **group-disjoint** (group = malware family when the provenance
reveals one, else the sample's own sha) so family variants never straddle
train/test (B37). Most malware lacks a family label (CICMalDroid has none, B40), so
the split is honestly recorded as source-grouped, not fully family-disjoint.

## Why not alternatives

- **Keep LAMDA's schema, populate with our pipeline** — considered and rejected by
  the user: ~98% of LAMDA's columns stay all-zero on our corpus (dead features),
  and it keeps a dependency the unified approach removes. LAMDA rows could still be
  unioned onto the shared schema later if cross-dataset comparison is wanted.
- **Do nothing (ship the LAMDA model)** — leaves the train/serve skew and its
  silent-constant-prediction failure mode in place.

## Consequences / follow-ups

- `l3` must be batch-populated on the corpus spines (`tools/corpus_run.py`,
  `run.py` currently do not call L3), then `ml.enabled` flipped in `L5/policy.yaml`
  (a separate, measured step — L3 is a ±10 prior with no `require_family_disjoint`
  gate, unlike L3b).
- The unified model does not resolve the L3b banking-family split (still pending
  MalRadar, B40).
