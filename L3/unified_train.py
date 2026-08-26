"""Train the unified L3 prior on the pipeline-extracted corpus dataset.

    source source_env.sh
    $SENTINEL_PYTHON tools/build_unified_dataset.py extract
    $SENTINEL_PYTHON tools/build_unified_dataset.py build
    $SENTINEL_PYTHON L3/unified_train.py

Unlike ``L3/train.py`` (LAMDA, temporal split), this trains on our own corpus
with features our own pipeline produced, so there is no train/serve vocabulary
skew. It stays a **generic ±10 prior**, never a verdict — the bound lives in
``L5/score.py`` and is unchanged.

**Honesty guards, because this corpus is source-confounded.** Every benign
sample is F-Droid and every malware sample is CICMalDroid/GitHub — the source is
almost perfectly correlated with the label (T27). So:

* the split is **group-disjoint** (group = malware family when the provenance
  reveals one, else the sample's own sha), so variants of one family never
  straddle train/test (B37);
* only **held-out** AUROC/ECE is reported, never in-sample;
* the metrics file records the source confound loudly and flags a held-out
  AUROC above 0.99 as probable source-artifact leakage, not a real result.

A trustworthy banking false-positive rate still needs benign banking apps in
the corpus (T27); this model cannot supply one and must not claim to.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from L3.train import auroc, expected_calibration_error  # noqa: E402  (reuse)

MODEL_DIR = REPO_ROOT / "L3" / "model"
DATASET_PATH = MODEL_DIR / "unified_dataset.npz"
VOCAB_PATH = MODEL_DIR / "unified_vocab.json"
MODEL_PATH = MODEL_DIR / "unified_lgbm.joblib"
METRICS_PATH = MODEL_DIR / "unified_metrics.json"

LEAKAGE_AUROC = 0.99


def group_disjoint_split(groups: np.ndarray, y: np.ndarray, *,
                         test_frac: float, seed: int) -> tuple[np.ndarray, np.ndarray]:
    """Whole groups fall entirely into train or test; test is drawn per-class.

    Returns (train_idx, test_idx). Each group is single-class (a family, or a
    single benign/malware sample), so we stratify by taking ``test_frac`` of the
    positive groups and ``test_frac`` of the negative groups.
    """
    rng = np.random.default_rng(seed)
    group_label: dict[Any, int] = {}
    for g, label in zip(groups, y):
        group_label.setdefault(g, int(label))

    test_groups: set[Any] = set()
    for target in (1, 0):
        gs = np.array([g for g, l in group_label.items() if l == target], dtype=object)
        rng.shuffle(gs)
        n_test = max(1, int(round(test_frac * len(gs))))
        test_groups.update(gs[:n_test].tolist())

    in_test = np.array([g in test_groups for g in groups])
    return np.where(~in_test)[0], np.where(in_test)[0]


def train(*, test_frac: float = 0.2, n_estimators: int = 400,
          seed: int = 20260824) -> dict[str, Any]:
    import joblib
    import lightgbm as lgb
    from sklearn.isotonic import IsotonicRegression

    if not DATASET_PATH.is_file():
        raise SystemExit(f"{DATASET_PATH} not found — run "
                         "tools/build_unified_dataset.py first")
    d = np.load(DATASET_PATH, allow_pickle=True)
    X, y = d["X"].astype(np.float32), d["y"].astype(int)
    groups, source_id = d["group"], d["source_id"]
    plausible = d["plausible"] if "plausible" in d else np.ones(len(y), bool)

    keep = plausible
    X, y, groups, source_id = X[keep], y[keep], groups[keep], source_id[keep]
    print(f"dataset: X {X.shape}, {int(y.sum())} malware / {int((y == 0).sum())} benign "
          f"({int((~keep).sum())} dropped below density floor)")

    train_idx, test_idx = group_disjoint_split(groups, y, test_frac=test_frac, seed=seed)
    print(f"group-disjoint split: {len(train_idx)} train / {len(test_idx)} held-out "
          f"({len(set(groups.tolist()))} groups total)")

    # Calibration slice held out of the fit, from within the training groups.
    rng = np.random.default_rng(seed)
    perm = rng.permutation(train_idx)
    cut = int(0.9 * len(perm))
    fit_idx, cal_idx = perm[:cut], perm[cut:]

    model = lgb.LGBMClassifier(
        n_estimators=n_estimators, learning_rate=0.05, num_leaves=64,
        min_child_samples=20, subsample=0.9, subsample_freq=1,
        colsample_bytree=0.6, reg_lambda=1.0, random_state=seed, verbose=-1,
    )
    model.fit(X[fit_idx], y[fit_idx])

    raw_cal = model.predict_proba(X[cal_idx])[:, 1]
    calibrator = IsotonicRegression(out_of_bounds="clip", y_min=0.0, y_max=1.0)
    calibrator.fit(raw_cal, y[cal_idx])

    p_test = calibrator.predict(model.predict_proba(X[test_idx])[:, 1])
    held = {
        "n": int(len(test_idx)),
        "n_malware": int(y[test_idx].sum()),
        "n_benign": int((y[test_idx] == 0).sum()),
        "auroc": round(auroc(y[test_idx], p_test), 4),
        "ece": round(expected_calibration_error(y[test_idx], p_test), 4),
        "mean_p_malware": round(float(p_test[y[test_idx] == 1].mean()), 4)
        if y[test_idx].any() else None,
        "mean_p_benign": round(float(p_test[y[test_idx] == 0].mean()), 4)
        if (y[test_idx] == 0).any() else None,
    }

    from L3.unified_features import CorpusVocabulary
    vocab = CorpusVocabulary.load(VOCAB_PATH)
    joblib.dump({"model": model, "calibrator": calibrator,
                 "vocab_path": str(VOCAB_PATH), "kind": "unified"}, MODEL_PATH)

    caveats = [
        "GENERIC maliciousness prior, bounded to +-10 points in L5; never a verdict",
        "SOURCE-CONFOUNDED: benign=F-Droid, malware=CICMalDroid/GitHub — source is "
        "near-perfectly correlated with label (T27), so held-out AUROC is an UPPER "
        "bound and cannot represent a real benign banking app",
        "features are pipeline-extracted (L3.unified_features), security-relevant "
        "tokens only; no train/serve vocabulary skew",
    ]
    if held["auroc"] >= LEAKAGE_AUROC:
        caveats.insert(0, f"WARNING: held-out AUROC {held['auroc']} >= {LEAKAGE_AUROC} — "
                          "treat as source-artifact leakage, not detection skill")

    metrics = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "n_features": vocab.size,
        "n_train_fit": int(len(fit_idx)), "n_calibration": int(len(cal_idx)),
        "held_out": held,
        "source_composition": dict(Counter(source_id.tolist())),
        "family_grouping": {
            "n_groups": int(len(set(groups.tolist()))),
            "n_samples": int(len(y)),
            "note": "most malware lacks a family label (CICMalDroid has none per "
                    "B40), so the split is source-grouped, not fully family-disjoint",
        },
        "seed": seed,
        "lightgbm": __import__("lightgbm").__version__,
        "caveats": caveats,
    }
    METRICS_PATH.write_text(json.dumps(metrics, indent=2))
    print(f"\nheld-out: AUROC {held['auroc']}  ECE {held['ece']}  "
          f"mean_p mal={held['mean_p_malware']} ben={held['mean_p_benign']}")
    for c in caveats:
        print(f"  · {c}")
    print(f"\nwrote {MODEL_PATH}\nwrote {METRICS_PATH}")
    return metrics


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--test-frac", type=float, default=0.2)
    ap.add_argument("--n-estimators", type=int, default=400)
    args = ap.parse_args(argv)
    try:
        from loguru import logger
        logger.remove()
    except Exception:  # noqa: BLE001
        pass
    train(test_frac=args.test_frac, n_estimators=args.n_estimators)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
