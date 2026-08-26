"""Deduplicated, stratified 5-fold evaluation + final fit for unified L3.

    source source_env.sh
    $SENTINEL_PYTHON L3/unified_cv.py

Why this exists: the single group-disjoint split reported AUROC 0.9958, which is
suspicious. CICMalDroid ships near-duplicate / repacked samples, and the
group=sha singletons for benign/CICMalDroid meant two rows with an *identical
feature vector* but different sha256 could land on opposite sides of the split —
free AUROC from a train/test intersection. This script:

1. **Deduplicates by feature-vector identity** (a row's exact int8 vector). It
   reports how many rows were duplicates so the intersection is quantified, not
   assumed. Vectors whose duplicates disagree on the label are dropped as
   ambiguous.
2. Runs **stratified 5-fold** cross-validation (LightGBM + per-fold isotonic
   calibration) and reports per-fold AUROC/ECE plus mean±std.
3. Refits a final model on all deduplicated rows and overwrites
   ``L3/model/unified_lgbm.joblib`` so prediction uses the deduped model.

The source confound (T27) is unchanged by dedup — benign=F-Droid vs
malware=CICMalDroid are still disjoint sources, so even the deduped CV AUROC is
an UPPER bound. Dedup removes the *duplicate-leakage* inflation; it does not
manufacture a benign banking app.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from L3.train import auroc, expected_calibration_error  # noqa: E402

MODEL_DIR = REPO_ROOT / "L3" / "model"
DATASET_PATH = MODEL_DIR / "unified_dataset.npz"
VOCAB_PATH = MODEL_DIR / "unified_vocab.json"
MODEL_PATH = MODEL_DIR / "unified_lgbm.joblib"
METRICS_PATH = MODEL_DIR / "unified_metrics.json"

LEAKAGE_AUROC = 0.99


def _row_hashes(X: np.ndarray) -> np.ndarray:
    """A stable content hash per row of the int8 feature matrix."""
    Xc = np.ascontiguousarray(X.astype(np.int8))
    return np.array([hashlib.blake2b(Xc[i].tobytes(), digest_size=16).hexdigest()
                     for i in range(Xc.shape[0])], dtype=object)


def deduplicate(X: np.ndarray, y: np.ndarray, extra: dict[str, np.ndarray]
                ) -> tuple[np.ndarray, np.ndarray, dict[str, np.ndarray], dict[str, Any]]:
    """Keep one row per unique feature vector; drop label-conflicting vectors."""
    hashes = _row_hashes(X)
    by_hash: dict[str, list[int]] = defaultdict(list)
    for i, h in enumerate(hashes):
        by_hash[h].append(i)

    keep: list[int] = []
    conflicts = 0
    dup_rows = 0
    cross_label_dupe_vectors = 0
    for idxs in by_hash.values():
        if len(idxs) > 1:
            dup_rows += len(idxs) - 1
            labels = {int(y[i]) for i in idxs}
            if len(labels) > 1:
                conflicts += 1
                cross_label_dupe_vectors += 1
                continue  # ambiguous — drop the whole group
        keep.append(idxs[0])

    keep_arr = np.array(sorted(keep))
    stats = {
        "n_before": int(len(y)),
        "n_unique_vectors": int(len(by_hash)),
        "n_duplicate_rows": int(dup_rows),
        "n_label_conflict_vectors_dropped": int(conflicts),
        "n_after": int(len(keep_arr)),
        "duplicate_fraction": round(dup_rows / len(y), 4) if len(y) else 0.0,
    }
    extra_kept = {k: v[keep_arr] for k, v in extra.items()}
    return X[keep_arr], y[keep_arr], extra_kept, stats


def near_deduplicate(X: np.ndarray, y: np.ndarray, extra: dict[str, np.ndarray],
                     threshold: float) -> tuple[np.ndarray, np.ndarray,
                                                 dict[str, np.ndarray], dict[str, Any]]:
    """Collapse rows whose cosine similarity >= ``threshold`` to one per cluster.

    Subsumes exact-dedup and also removes repacked near-variants (the analysis
    found 73.5% of rows have a >=0.95-cosine twin). Only **same-label**
    neighbours are unioned, so a rare benign/malware near-pair is never merged
    into one class. Keeps the first index per cluster.
    """
    from sklearn.neighbors import NearestNeighbors

    n = X.shape[0]
    parent = list(range(n))

    def find(a: int) -> int:
        while parent[a] != a:
            parent[a] = parent[parent[a]]
            a = parent[a]
        return a

    def union(a: int, b: int) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[max(ra, rb)] = min(ra, rb)

    nn = NearestNeighbors(radius=1.0 - threshold, metric="cosine").fit(X)
    neigh = nn.radius_neighbors(X, return_distance=False)
    for i, js in enumerate(neigh):
        for j in js:
            if j != i and y[j] == y[i]:
                union(i, j)

    reps: dict[int, int] = {}
    for i in range(n):
        r = find(i)
        if r not in reps:
            reps[r] = i
    keep = np.array(sorted(reps.values()))
    stats = {
        "threshold": threshold,
        "n_before": int(n),
        "n_clusters_kept": int(len(keep)),
        "n_removed": int(n - len(keep)),
        "removed_fraction": round((n - len(keep)) / n, 4) if n else 0.0,
    }
    return X[keep], y[keep], {k: v[keep] for k, v in extra.items()}, stats


def _fit_fold(X_tr, y_tr, X_te, seed: int, n_estimators: int):
    import lightgbm as lgb
    from sklearn.isotonic import IsotonicRegression

    rng = np.random.default_rng(seed)
    perm = rng.permutation(len(y_tr))
    cut = int(0.9 * len(perm))
    fit_idx, cal_idx = perm[:cut], perm[cut:]

    model = lgb.LGBMClassifier(
        n_estimators=n_estimators, learning_rate=0.05, num_leaves=64,
        min_child_samples=20, subsample=0.9, subsample_freq=1,
        colsample_bytree=0.6, reg_lambda=1.0, random_state=seed, verbose=-1,
    )
    model.fit(X_tr[fit_idx], y_tr[fit_idx])
    cal = IsotonicRegression(out_of_bounds="clip", y_min=0.0, y_max=1.0)
    cal.fit(model.predict_proba(X_tr[cal_idx])[:, 1], y_tr[cal_idx])
    return cal.predict(model.predict_proba(X_te)[:, 1])


def run(*, n_splits: int = 5, n_estimators: int = 400, seed: int = 20260825,
        near_threshold: float = 0.97) -> dict[str, Any]:
    import joblib
    import lightgbm as lgb
    from sklearn.isotonic import IsotonicRegression
    from sklearn.model_selection import StratifiedKFold

    d = np.load(DATASET_PATH, allow_pickle=True)
    X, y = d["X"].astype(np.float32), d["y"].astype(int)
    plausible = d["plausible"] if "plausible" in d else np.ones(len(y), bool)
    extra = {k: d[k] for k in ("sha256", "source_id", "family", "group") if k in d}
    X, y = X[plausible], y[plausible]
    extra = {k: v[plausible] for k, v in extra.items()}
    print(f"plausible rows: {len(y)}  ({int(y.sum())} malware / {int((y == 0).sum())} benign)")

    X, y, extra, dedup_stats = near_deduplicate(X, y, extra, near_threshold)
    print(f"near-dedup @cos>={near_threshold}: removed {dedup_stats['n_removed']} rows "
          f"({dedup_stats['removed_fraction']:.1%}) -> {dedup_stats['n_clusters_kept']} rows "
          f"({int(y.sum())} malware / {int((y == 0).sum())} benign)")

    skf = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=seed)
    fold_metrics = []
    print(f"\nstratified {n_splits}-fold (deduplicated):")
    print("  fold      n_test   AUROC    ECE    mean_p mal/ben")
    for k, (tr, te) in enumerate(skf.split(X, y), 1):
        p = _fit_fold(X[tr], y[tr], X[te], seed + k, n_estimators)
        m = {
            "fold": k, "n_test": int(len(te)),
            "auroc": round(auroc(y[te], p), 4),
            "ece": round(expected_calibration_error(y[te], p), 4),
            "mean_p_malware": round(float(p[y[te] == 1].mean()), 4),
            "mean_p_benign": round(float(p[y[te] == 0].mean()), 4),
        }
        fold_metrics.append(m)
        print(f"  {k:>4}    {m['n_test']:>7}   {m['auroc']:.4f}  {m['ece']:.3f}   "
              f"{m['mean_p_malware']:.3f}/{m['mean_p_benign']:.3f}")

    aurocs = np.array([m["auroc"] for m in fold_metrics])
    eces = np.array([m["ece"] for m in fold_metrics])
    cv_auroc_mean, cv_auroc_std = float(aurocs.mean()), float(aurocs.std())
    print(f"\n  AUROC {cv_auroc_mean:.4f} ± {cv_auroc_std:.4f}   "
          f"ECE {float(eces.mean()):.4f} ± {float(eces.std()):.4f}")

    # Final model on all deduplicated rows.
    rng = np.random.default_rng(seed)
    perm = rng.permutation(len(y))
    cut = int(0.9 * len(perm))
    fit_idx, cal_idx = perm[:cut], perm[cut:]
    model = lgb.LGBMClassifier(
        n_estimators=n_estimators, learning_rate=0.05, num_leaves=64,
        min_child_samples=20, subsample=0.9, subsample_freq=1,
        colsample_bytree=0.6, reg_lambda=1.0, random_state=seed, verbose=-1,
    )
    model.fit(X[fit_idx], y[fit_idx])
    calibrator = IsotonicRegression(out_of_bounds="clip", y_min=0.0, y_max=1.0)
    calibrator.fit(model.predict_proba(X[cal_idx])[:, 1], y[cal_idx])

    from L3.unified_features import CorpusVocabulary
    vocab = CorpusVocabulary.load(VOCAB_PATH)
    joblib.dump({"model": model, "calibrator": calibrator,
                 "vocab_path": str(VOCAB_PATH), "kind": "unified"}, MODEL_PATH)

    caveats = [
        "GENERIC maliciousness prior, bounded to +-10 points in L5; never a verdict",
        f"NEAR-DEDUPLICATED at cosine >= {near_threshold} (same-label clusters) before eval",
        "capability (absence) aggregates are first-class columns (cap:*)",
        "SOURCE-CONFOUNDED (T27): benign=F-Droid, malware=CICMalDroid — dedup removes "
        "duplicate-leakage but not the source confound; CV AUROC is still an UPPER bound",
    ]
    if cv_auroc_mean >= LEAKAGE_AUROC:
        caveats.insert(0, f"WARNING: CV AUROC {cv_auroc_mean:.4f} >= {LEAKAGE_AUROC} even "
                          "after dedup — the residual is the source confound, not skill")

    metrics = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "evaluation": "stratified_kfold_deduplicated",
        "n_features": vocab.size,
        "dedup": dedup_stats,
        "cv": {
            "n_splits": n_splits,
            "auroc_mean": round(cv_auroc_mean, 4), "auroc_std": round(cv_auroc_std, 4),
            "ece_mean": round(float(eces.mean()), 4), "ece_std": round(float(eces.std()), 4),
            "folds": fold_metrics,
        },
        "seed": seed,
        "lightgbm": lgb.__version__,
        "caveats": caveats,
    }
    METRICS_PATH.write_text(json.dumps(metrics, indent=2))
    for c in caveats:
        print(f"  · {c}")
    print(f"\nwrote {MODEL_PATH}\nwrote {METRICS_PATH}")
    return metrics


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--folds", type=int, default=5)
    ap.add_argument("--n-estimators", type=int, default=400)
    ap.add_argument("--near-threshold", type=float, default=0.97)
    args = ap.parse_args(argv)
    try:
        from loguru import logger
        logger.remove()
    except Exception:  # noqa: BLE001
        pass
    run(n_splits=args.folds, n_estimators=args.n_estimators,
        near_threshold=args.near_threshold)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
