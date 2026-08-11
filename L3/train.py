"""Train the L3 maliciousness prior on LAMDA.

    source source_env.sh
    $SENTINEL_PYTHON L3/train.py --train-until 2022 --out L3/model

**What this model is for, and what it is not.** L3 contributes a *generic*
maliciousness prior bounded to ±10 points on a 0–100 score, and it can never
produce a verdict on its own. LAMDA is ~99.6% non-banking, so a confident
output from it means "this resembles Android malware in general", never "this
is a banking trojan". The bound is enforced in ``L5/score.py`` and pinned by a
test; nothing here can widen it.

**The split is temporal, not random.** A random split over a 2013–2025 corpus
leaks the future into the past and produces an AUROC that will not survive
contact with a new sample. LAMDA is partitioned by year precisely so that
concept drift is measurable, so training stops at ``--train-until`` and every
later year is scored as a held-out future. The per-year table this prints is
the drift exhibit, and a model whose AUROC decays across it is behaving
honestly rather than failing.

**Calibration matters more than accuracy here.** L5 maps ``p`` to a bounded
point delta, so a miscalibrated 0.9 costs real score points. The classifier is
therefore wrapped in isotonic regression fitted on a held-out slice of the
training years, never on the future ones.

Memory: LAMDA is 1,008,381 × 4,561. Dense int8 would be 4.6 GB, which does not
fit alongside a corpus run on a 14 GB machine, so each year is converted to a
sparse matrix and the dense frame is dropped immediately.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

DATA_ROOT = Path(os.environ.get("SENTINEL_DATA_ROOT", REPO_ROOT))
LAMDA_BASELINE = DATA_ROOT / "lamda" / "Baseline"

META_COLUMNS = ("hash", "label", "family", "vt_count", "year_month")


@dataclass
class YearData:
    year: int
    X: Any            # scipy.sparse.csr_matrix
    y: np.ndarray
    families: np.ndarray

    def __len__(self) -> int:
        return self.y.shape[0]


def available_years(root: Path = LAMDA_BASELINE) -> list[int]:
    if not root.is_dir():
        raise SystemExit(
            f"LAMDA not found at {root}. Fetch it with:\n"
            "    $SENTINEL_PYTHON L3/fetch_lamda.py")
    return sorted(int(p.name) for p in root.iterdir()
                  if p.is_dir() and p.name.isdigit())


def load_year(year: int, split: str, root: Path = LAMDA_BASELINE) -> YearData | None:
    """One year/split as a sparse matrix. The dense frame never outlives this call."""
    import pyarrow.parquet as pq
    from scipy import sparse

    path = root / str(year) / f"{year}_{split}.parquet"
    if not path.is_file():
        return None
    table = pq.read_table(path)
    names = table.column_names
    feat_cols = [c for c in names if c.startswith("feat_")]
    # Column order is the feature index; sorting lexically would put feat_10
    # before feat_2 and silently permute every column.
    feat_cols.sort(key=lambda c: int(c.removeprefix("feat_")))

    y = np.asarray(table.column("label").to_numpy(), dtype=np.int8)
    families = np.asarray(table.column("family").to_pylist(), dtype=object)

    # Built dense as int8 (the parquet's own type, 4.5x smaller than float32
    # while materialising a year), then converted straight to sparse float32.
    # LightGBM's CSR path rejects integer dtypes outright — _c_float_array
    # raises "Expected np.float32 or np.float64, met type(int8)" — so the cast
    # has to happen somewhere, and doing it here keeps the dense peak low.
    dense = np.empty((table.num_rows, len(feat_cols)), dtype=np.int8)
    for i, col in enumerate(feat_cols):
        dense[:, i] = table.column(col).to_numpy(zero_copy_only=False)
    del table
    X = sparse.csr_matrix(dense, dtype=np.float32)
    del dense
    return YearData(year=year, X=X, y=y, families=families)


def stack(parts: list[YearData]):
    from scipy import sparse
    X = sparse.vstack([p.X for p in parts], format="csr")
    y = np.concatenate([p.y for p in parts])
    fam = np.concatenate([p.families for p in parts])
    return X, y, fam


def auroc(y_true: np.ndarray, scores: np.ndarray) -> float:
    """Rank-based AUROC with tie averaging. No sklearn import needed for one number."""
    y_true = np.asarray(y_true).astype(int)
    n_pos = int((y_true == 1).sum())
    n_neg = int((y_true == 0).sum())
    if n_pos == 0 or n_neg == 0:
        return float("nan")
    order = np.argsort(scores, kind="mergesort")
    ranks = np.empty(len(scores), dtype=float)
    ranks[order] = np.arange(1, len(scores) + 1)
    # average ranks within ties
    s_sorted = scores[order]
    i = 0
    while i < len(s_sorted):
        j = i
        while j + 1 < len(s_sorted) and s_sorted[j + 1] == s_sorted[i]:
            j += 1
        if j > i:
            ranks[order[i:j + 1]] = (i + j + 2) / 2.0
        i = j + 1
    return float((ranks[y_true == 1].sum() - n_pos * (n_pos + 1) / 2) / (n_pos * n_neg))


def expected_calibration_error(y: np.ndarray, p: np.ndarray, bins: int = 10) -> float:
    """How far predicted probability sits from observed frequency."""
    edges = np.linspace(0, 1, bins + 1)
    total = 0.0
    for lo, hi in zip(edges[:-1], edges[1:]):
        m = (p >= lo) & (p < hi if hi < 1 else p <= hi)
        if not m.any():
            continue
        total += m.mean() * abs(p[m].mean() - y[m].mean())
    return float(total)


def train(train_until: int, out_dir: Path, *, n_estimators: int = 400,
          seed: int = 20260812) -> dict[str, Any]:
    import lightgbm as lgb
    from sklearn.isotonic import IsotonicRegression

    years = available_years()
    train_years = [y for y in years if y <= train_until]
    test_years = [y for y in years if y > train_until]
    if not train_years or not test_years:
        raise SystemExit(f"--train-until {train_until} leaves no split "
                         f"(years available: {years})")

    print(f"train years {train_years[0]}–{train_years[-1]}  "
          f"held-out future {test_years[0]}–{test_years[-1]}")

    started = time.time()
    parts: list[YearData] = []
    for y in train_years:
        for split in ("train", "test"):
            d = load_year(y, split)
            if d:
                parts.append(d)
        print(f"  loaded {y}: {sum(len(p) for p in parts):,} rows so far", flush=True)
    X, y_all, fam = stack(parts)
    del parts
    print(f"  training matrix {X.shape}, {X.nnz:,} nonzeros, "
          f"{X.data.nbytes / 1e6:.0f} MB")

    # Calibration slice held out of fitting, taken from the training years so
    # the future stays untouched.
    rng = np.random.default_rng(seed)
    idx = rng.permutation(X.shape[0])
    cut = int(0.9 * len(idx))
    fit_idx, cal_idx = idx[:cut], idx[cut:]

    model = lgb.LGBMClassifier(
        n_estimators=n_estimators, learning_rate=0.05, num_leaves=64,
        min_child_samples=50, subsample=0.9, subsample_freq=1,
        colsample_bytree=0.5, reg_lambda=1.0, n_jobs=max(1, os.cpu_count() // 2),
        random_state=seed, verbose=-1,
    )
    model.fit(X[fit_idx], y_all[fit_idx])
    print(f"  fitted in {time.time() - started:.0f}s")

    raw_cal = model.predict_proba(X[cal_idx])[:, 1]
    calibrator = IsotonicRegression(out_of_bounds="clip", y_min=0.0, y_max=1.0)
    calibrator.fit(raw_cal, y_all[cal_idx])

    metrics: dict[str, Any] = {
        "train_years": train_years, "test_years": test_years,
        "n_train": int(len(fit_idx)), "n_calibration": int(len(cal_idx)),
        "in_sample": {
            "auroc": round(auroc(y_all[cal_idx], raw_cal), 4),
            "ece_raw": round(expected_calibration_error(y_all[cal_idx], raw_cal), 4),
            "ece_calibrated": round(expected_calibration_error(
                y_all[cal_idx], calibrator.predict(raw_cal)), 4),
        },
        "per_year": {},
    }
    del X, y_all

    print("\n  held-out future (the drift exhibit):")
    print("    year      n      AUROC   ECE   mean p")
    for yr in test_years:
        parts = [d for d in (load_year(yr, s) for s in ("train", "test")) if d]
        if not parts:
            continue
        Xt, yt, _ = stack(parts)
        del parts
        p = calibrator.predict(model.predict_proba(Xt)[:, 1])
        metrics["per_year"][str(yr)] = {
            "n": int(len(yt)), "auroc": round(auroc(yt, p), 4),
            "ece": round(expected_calibration_error(yt, p), 4),
            "mean_p": round(float(p.mean()), 4),
            "positive_rate": round(float(yt.mean()), 4),
        }
        m = metrics["per_year"][str(yr)]
        print(f"    {yr}  {m['n']:>7,}   {m['auroc']:.4f}  {m['ece']:.3f}  {m['mean_p']:.3f}")
        del Xt, yt, p

    out_dir.mkdir(parents=True, exist_ok=True)
    import joblib
    joblib.dump({"model": model, "calibrator": calibrator},
                out_dir / "lamda_lgbm.joblib")

    from L3.features import Vocabulary
    vocab = Vocabulary.load()
    metrics.update({
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "n_features": vocab.size,
        "lightgbm": __import__("lightgbm").__version__,
        "seed": seed,
        "caveats": [
            "LAMDA is ~99.6% non-banking: this is a GENERIC maliciousness prior "
            "and must never make a banking claim",
            "bounded to +-10 points in L5 and unable to reach Critical alone",
            "trained on AndroZoo-derived features; our samples match its "
            "vocabulary only partially (measured 0.4-1.8% density vs LAMDA's 2.5%)",
            "labels are VirusTotal 4+ detections, not manual analysis",
        ],
    })
    (out_dir / "metrics.json").write_text(json.dumps(metrics, indent=2))
    print(f"\nwrote {out_dir / 'lamda_lgbm.joblib'}")
    print(f"wrote {out_dir / 'metrics.json'}")
    return metrics


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--train-until", type=int, default=2022,
                    help="last year used for training; later years are held out")
    ap.add_argument("--out", default=str(REPO_ROOT / "L3" / "model"))
    ap.add_argument("--n-estimators", type=int, default=400)
    args = ap.parse_args(argv)

    m = train(args.train_until, Path(args.out), n_estimators=args.n_estimators)
    first, last = list(m["per_year"])[0], list(m["per_year"])[-1]
    drop = m["per_year"][first]["auroc"] - m["per_year"][last]["auroc"]
    print(f"\nAUROC drift {first} -> {last}: {drop:+.4f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
