"""Train the L3b banking-specific prior.

    source source_env.sh
    $SENTINEL_PYTHON L3b/dataset.py --out L3b/model/dataset.npz
    $SENTINEL_PYTHON L3b/train.py --dataset L3b/model/dataset.npz --out L3b/model

Same model family as L3 (LightGBM + isotonic calibration) — there is no reason
to introduce a second modelling stack for a problem of the same shape. What
differs is the split: L3 splits by year because concept drift is what it
measures. L3b splits by malware **family**, because B37 (see
``docs/PROJECT_LOG.md`` §7.6) found that banking families are small and
tightly clustered — a random split trains and tests on variants of one
family and reports an AUROC that means nothing.

**The split's honesty is reported, not assumed.** ``family_disjoint_status``
in ``metrics.json`` is ``"verified"`` only when enough hand/expert-labelled
families exist to hold some out; otherwise it is
``"unverified_pending_malradar"`` and the model still trains (on everything,
including unverified-family and unknown-family rows) but ships with that
caveat instead of a number pretending to be one. ``L5/score.py``'s
``apply_banking_ml`` refuses to apply the delta while that status holds,
unless the policy explicitly overrides it.
"""

from __future__ import annotations

import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from L3.train import auroc, expected_calibration_error  # noqa: E402
from L3b.family_labels import FamilyLabel, split_family_disjoint  # noqa: E402


def load_dataset(path: Path) -> tuple[np.ndarray, np.ndarray, list[FamilyLabel]]:
    npz = np.load(path, allow_pickle=True)
    X, y = npz["X"], npz["y"]
    fam_labels = [
        FamilyLabel(sha256=sha, family=(fam or None), tier=tier, source="dataset")
        for sha, fam, tier in zip(npz["sha256"], npz["family"], npz["tier"])
    ]
    return X, y, fam_labels


def _rows_for(ids: tuple[str, ...], fam_labels: list[FamilyLabel]
             ) -> np.ndarray:
    index = {f.sha256: i for i, f in enumerate(fam_labels)}
    return np.array([index[sha] for sha in ids if sha in index], dtype=int)


def train(dataset_path: Path, out_dir: Path, *, n_estimators: int = 300,
         seed: int = 20260818) -> dict[str, Any]:
    import lightgbm as lgb
    from sklearn.isotonic import IsotonicRegression

    X, y, fam_labels = load_dataset(dataset_path)
    if X.shape[0] < 20:
        raise SystemExit(f"only {X.shape[0]} usable rows in {dataset_path} — "
                         "not enough to train on; is the banking corpus_run "
                         "finished and registered?")

    split = split_family_disjoint(fam_labels, seed=seed)
    train_idx = _rows_for(split.train_ids, fam_labels)
    test_idx = _rows_for(split.test_ids, fam_labels)

    print(f"family_disjoint_status = {split.status}")
    print(f"  train rows: {len(train_idx)}   held-out rows: {len(test_idx)}")
    if split.held_out_families:
        print(f"  held-out families: {', '.join(split.held_out_families)}")

    # A calibration slice held out of fitting, taken from the training rows
    # only — same discipline as L3/train.py, so held-out families never leak
    # into calibration either.
    rng = np.random.default_rng(seed)
    perm = rng.permutation(len(train_idx))
    cut = int(0.9 * len(perm))
    fit_idx = train_idx[perm[:cut]]
    cal_idx = train_idx[perm[cut:]]

    started = time.time()
    model = lgb.LGBMClassifier(
        n_estimators=n_estimators, learning_rate=0.05, num_leaves=31,
        min_child_samples=10, subsample=0.9, subsample_freq=1,
        colsample_bytree=0.7, reg_lambda=1.0,
        n_jobs=max(1, os.cpu_count() // 2), random_state=seed, verbose=-1,
    )
    model.fit(X[fit_idx], y[fit_idx])
    print(f"fitted in {time.time() - started:.1f}s on {len(fit_idx)} rows")

    raw_cal = model.predict_proba(X[cal_idx])[:, 1]
    calibrator = IsotonicRegression(out_of_bounds="clip", y_min=0.0, y_max=1.0)
    calibrator.fit(raw_cal, y[cal_idx])

    metrics: dict[str, Any] = {
        "n_train": int(len(fit_idx)), "n_calibration": int(len(cal_idx)),
        "n_held_out": int(len(test_idx)),
        "family_disjoint_status": split.status,
        "held_out_families": list(split.held_out_families),
        "in_sample": {
            "auroc": round(auroc(y[cal_idx], raw_cal), 4),
            "ece_raw": round(expected_calibration_error(y[cal_idx], raw_cal), 4),
            "ece_calibrated": round(expected_calibration_error(
                y[cal_idx], calibrator.predict(raw_cal)), 4),
        },
    }

    if len(test_idx):
        p_test = calibrator.predict(model.predict_proba(X[test_idx])[:, 1])
        metrics["held_out"] = {
            "auroc": round(auroc(y[test_idx], p_test), 4),
            "ece": round(expected_calibration_error(y[test_idx], p_test), 4),
            "mean_p": round(float(p_test.mean()), 4),
        }
        print(f"held-out (family-disjoint) AUROC: {metrics['held_out']['auroc']:.4f}")
    else:
        metrics["held_out"] = None
        print("no held-out rows — family_disjoint_status is "
             f"{split.status!r}, so there is nothing to report as a "
             "family-disjoint metric yet")

    out_dir.mkdir(parents=True, exist_ok=True)
    import joblib
    joblib.dump({"model": model, "calibrator": calibrator},
               out_dir / "banking_lgbm.joblib")

    metrics.update({
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "n_features": int(X.shape[1]),
        "lightgbm": __import__("lightgbm").__version__,
        "seed": seed,
        "malware_sources": ["banking_cicmaldroid"],
        "benign_source": "benign_fdroid",
        "scope": "banking_specific_prior",
        "caveats": [
            "trained on a small, partially family-verified banking-trojan "
            "corpus -- see family_disjoint_status and held_out_families "
            "before trusting any AUROC here as banking-specific",
            "labels are corpus provenance (CICMalDroid's own curation), not "
            "manual per-sample review",
            "benign source is F-Droid: zero commercial banking apps (T27) -- "
            "cannot validate a banking false-positive rate",
            "bounded to +-10 points in L5 and unable to reach Critical alone "
            "unless the held-out metric is family-disjoint-verified",
        ],
    })
    (out_dir / "metrics.json").write_text(json.dumps(metrics, indent=2))
    print(f"wrote {out_dir / 'banking_lgbm.joblib'}")
    print(f"wrote {out_dir / 'metrics.json'}")
    return metrics


def main(argv: list[str] | None = None) -> int:
    import argparse

    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--dataset", default=str(REPO_ROOT / "L3b" / "model" / "dataset.npz"))
    ap.add_argument("--out", default=str(REPO_ROOT / "L3b" / "model"))
    ap.add_argument("--n-estimators", type=int, default=300)
    args = ap.parse_args(argv)

    train(Path(args.dataset), Path(args.out), n_estimators=args.n_estimators)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
