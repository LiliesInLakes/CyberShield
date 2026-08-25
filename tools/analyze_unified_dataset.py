"""Structural analysis of the unified L3 feature matrix.

    source source_env.sh
    $SENTINEL_PYTHON tools/analyze_unified_dataset.py

Answers four questions the AUROC-0.99 result raised:

1. **Repetition** — exact duplicates (already known ~59%) AND *near*-duplicates
   (repacked variants that differ in a few columns), via cosine nearest-neighbour.
2. **Covariance / eigen-structure** — the PCA singular spectrum, effective rank
   (how few directions carry the variance => how redundant the corpus is), and
   how strongly the top components align with the *label* vs the *source*
   (F-Droid vs CICMalDroid). If a top PC separates the sources, that PC *is* the
   T27 confound made visible.
3. **Absence as signal** — the matrix is binary (no literal NaN), so "missing an
   important column" = a token being 0. Reported as: near-empty rows (extraction
   produced almost nothing — a packing / anti-analysis proxy), per-class presence
   rates of security-critical token families, and dead (all-zero) columns.
4. **Confound fingerprints** — columns that are near-perfect separators (present
   in ~one class only). These are what an honest reviewer must see: often a
   library/signing artifact of the *source*, not a behaviour.

Writes docs/reports/unified_dataset_analysis.json and prints a summary.
Read-only; touches no model.
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

import numpy as np

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from L3.train import auroc  # noqa: E402

MODEL_DIR = REPO_ROOT / "L3" / "model"
DATASET_PATH = MODEL_DIR / "unified_dataset.npz"
VOCAB_PATH = MODEL_DIR / "unified_vocab.json"
OUT_PATH = REPO_ROOT / "docs" / "reports" / "unified_dataset_analysis.json"


def _pct(a: np.ndarray) -> dict[str, float]:
    return {p: round(float(np.percentile(a, int(p))), 2)
            for p in ("5", "25", "50", "75", "95")}


def main() -> int:
    d = np.load(DATASET_PATH, allow_pickle=True)
    X = d["X"].astype(np.float32)
    y = d["y"].astype(int)
    source = d["source_id"].astype(str) if "source_id" in d else np.array([""] * len(y))
    plausible = d["plausible"] if "plausible" in d else np.ones(len(y), bool)
    names = json.loads(VOCAB_PATH.read_text())["names"]

    X, y, source = X[plausible], y[plausible], source[plausible]
    n, m = X.shape
    is_cic = np.array(["cicmaldroid" in s for s in source])
    report: dict[str, Any] = {"shape": [int(n), int(m)],
                              "n_malware": int(y.sum()), "n_benign": int((y == 0).sum())}
    print(f"matrix: {n} x {m}   {int(y.sum())} malware / {int((y==0).sum())} benign")

    # --- 1. row sparsity (size confound) ---------------------------------
    nz = X.sum(axis=1)
    report["nonzero_per_row"] = {
        "overall": _pct(nz),
        "malware": _pct(nz[y == 1]),
        "benign": _pct(nz[y == 0]),
    }
    print(f"\nnonzero/row  malware median {np.median(nz[y==1]):.0f}  "
          f"benign median {np.median(nz[y==0]):.0f}  (size confound check)")

    # --- 2. exact + near duplicates --------------------------------------
    import hashlib
    hashes = [hashlib.blake2b(np.ascontiguousarray(X[i].astype(np.int8)).tobytes(),
                              digest_size=12).hexdigest() for i in range(n)]
    hc = Counter(hashes)
    exact_dupe_rows = sum(c - 1 for c in hc.values() if c > 1)
    multiplicity = Counter(hc.values())
    report["exact_duplicates"] = {
        "unique_vectors": len(hc),
        "duplicate_rows": int(exact_dupe_rows),
        "duplicate_fraction": round(exact_dupe_rows / n, 4),
        "top_multiplicities": dict(sorted(multiplicity.items(), reverse=True)[:6]),
    }
    print(f"exact dupes: {exact_dupe_rows} rows ({exact_dupe_rows/n:.1%}), "
          f"{len(hc)} unique vectors")

    from sklearn.neighbors import NearestNeighbors
    nn = NearestNeighbors(n_neighbors=2, metric="cosine").fit(X)
    dist, idx = nn.kneighbors(X)
    nn_sim = 1.0 - dist[:, 1]            # similarity to nearest *other* row
    same_src = np.array([source[i] == source[j] for i, j in enumerate(idx[:, 1])])
    same_lbl = np.array([y[i] == y[j] for i, j in enumerate(idx[:, 1])])
    report["near_duplicates"] = {
        "nn_similarity": _pct(nn_sim),
        "frac_ge_0.99": round(float((nn_sim >= 0.99).mean()), 4),
        "frac_ge_0.95": round(float((nn_sim >= 0.95).mean()), 4),
        "frac_ge_0.90": round(float((nn_sim >= 0.90).mean()), 4),
        "near_dup_same_source_frac": round(float(same_src[nn_sim >= 0.95].mean()), 4)
        if (nn_sim >= 0.95).any() else None,
        "near_dup_same_label_frac": round(float(same_lbl[nn_sim >= 0.95].mean()), 4)
        if (nn_sim >= 0.95).any() else None,
    }
    print(f"near dupes: {(nn_sim>=0.95).mean():.1%} of rows have a >=0.95-cosine twin "
          f"(>=0.99: {(nn_sim>=0.99).mean():.1%})")

    # --- 3. PCA / covariance eigen-spectrum ------------------------------
    from sklearn.decomposition import TruncatedSVD
    k = min(50, m - 1, n - 1)
    Xc = X - X.mean(axis=0, keepdims=True)
    svd = TruncatedSVD(n_components=k, random_state=0).fit(Xc)
    ev = (svd.singular_values_ ** 2) / (n - 1)          # covariance eigenvalues
    evr = svd.explained_variance_ratio_
    cum = np.cumsum(evr)
    eff_rank = int(np.argmax(cum >= 0.90) + 1) if (cum >= 0.90).any() else k
    scores = svd.transform(Xc)                          # row projections onto PCs
    # how well does each of the top PCs separate label vs source?
    pc_label_auroc = [round(max(a, 1 - a), 3) for a in
                      (auroc(y, scores[:, c]) for c in range(min(5, k)))]
    pc_source_auroc = [round(max(a, 1 - a), 3) for a in
                       (auroc(is_cic.astype(int), scores[:, c]) for c in range(min(5, k)))]
    report["pca"] = {
        "components": k,
        "top_eigenvalues": [round(float(v), 4) for v in ev[:10]],
        "explained_variance_ratio_top10": [round(float(v), 4) for v in evr[:10]],
        "cumulative_top10": [round(float(v), 4) for v in cum[:10]],
        "components_for_90pct_variance": eff_rank,
        "pc_separates_label_auroc_top5": pc_label_auroc,
        "pc_separates_source_auroc_top5": pc_source_auroc,
    }
    print(f"\nPCA: {eff_rank} components carry 90% variance (of {k}); "
          f"PC1 var {evr[0]:.1%}")
    print(f"  PC label-separation (top5): {pc_label_auroc}")
    print(f"  PC source-separation (top5): {pc_source_auroc}  "
          f"<- if these mirror label, the top PC IS the confound")

    # --- 4. column analysis: dead, discriminative, perfect separators ----
    pres_mal = X[y == 1].mean(axis=0)
    pres_ben = X[y == 0].mean(axis=0)
    dead = int((X.sum(axis=0) == 0).sum())
    delta = pres_mal - pres_ben
    # perfect-ish separators: present in >=60% of one class, <=2% of the other
    mal_sep = np.where((pres_mal >= 0.60) & (pres_ben <= 0.02))[0]
    ben_sep = np.where((pres_ben >= 0.60) & (pres_mal <= 0.02))[0]
    top_mal = sorted(mal_sep, key=lambda c: -delta[c])[:12]
    top_ben = sorted(ben_sep, key=lambda c: delta[c])[:12]
    report["columns"] = {
        "dead_all_zero": dead,
        "n_strong_malware_separators": int(len(mal_sep)),
        "n_strong_benign_separators": int(len(ben_sep)),
        "top_malware_separators": [
            {"token": names[c], "malware": round(float(pres_mal[c]), 3),
             "benign": round(float(pres_ben[c]), 3)} for c in top_mal],
        "top_benign_separators": [
            {"token": names[c], "malware": round(float(pres_mal[c]), 3),
             "benign": round(float(pres_ben[c]), 3)} for c in top_ben],
    }
    print(f"\ncolumns: {dead} dead, {len(mal_sep)} strong malware-separators, "
          f"{len(ben_sep)} strong benign-separators")
    print("  top malware-only tokens:", [names[c] for c in top_mal[:6]])
    print("  top benign-only tokens: ", [names[c] for c in top_ben[:6]])

    # --- 5. absence-as-signal --------------------------------------------
    floor = 10
    near_empty = nz < floor
    sms_cols = [i for i, nm in enumerate(names)
                if "SmsManager" in nm or "RECEIVE_SMS" in nm or "READ_SMS" in nm
                or "telephony.SmsManager" in nm]
    has_sms = X[:, sms_cols].sum(axis=1) > 0 if sms_cols else np.zeros(n, bool)
    report["absence_signal"] = {
        "near_empty_rows_lt10feat": int(near_empty.sum()),
        "near_empty_malware": int((near_empty & (y == 1)).sum()),
        "near_empty_benign": int((near_empty & (y == 0)).sum()),
        "sms_token_cols": len(sms_cols),
        "sms_present_rate_malware": round(float(has_sms[y == 1].mean()), 3),
        "sms_present_rate_benign": round(float(has_sms[y == 0].mean()), 3),
    }
    print(f"\nabsence: {near_empty.sum()} near-empty rows (<{floor} feat) "
          f"[{(near_empty&(y==1)).sum()} mal / {(near_empty&(y==0)).sum()} ben] "
          f"— extraction-poor = packing/anti-analysis proxy")
    print(f"  SMS-capability present: malware {has_sms[y==1].mean():.1%} vs "
          f"benign {has_sms[y==0].mean():.1%}")

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps(report, indent=2))
    print(f"\nwrote {OUT_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
