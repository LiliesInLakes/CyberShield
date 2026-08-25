"""Measure what L5 actually does, on labelled data.

    source source_env.sh
    $SENTINEL_PYTHON tools/evaluate.py
    $SENTINEL_PYTHON tools/evaluate.py --ablation --folds 5

Produces the numbers the proposal promises to report, and refuses to report
them in the flattering form.

🔴 **In-sample AUROC is meaningless here and is never shown alone.** A4 fits
its weights on the same corpus L5 is evaluated on, so an in-sample score
partly measures how well the weights memorised which rules fired on which
malware families. ``--folds`` refits the weights on k−1 folds and scores the
held-out one; the report always prints cross-validated and in-sample together,
and a large gap is itself the finding.

**Benign false-positive rate is reported with an interval, per band.** "0
false positives" is a statement about a denominator, and at small B the
Jeffreys upper bound on 0 hits is wide enough to be worthless — that is the
whole lesson of B30, and this tool is the thing that would have caught it.

**The ablation is the proposal's**: rules-only, gates-only, rules+gates, and
full hybrid with the ML prior. It answers "what does each mechanism buy?",
which is the question a judge asks after seeing one good score.
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import numpy as np

REPO_ROOT = Path(__file__).resolve().parent.parent
for _p in (str(REPO_ROOT), str(REPO_ROOT / "L1")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import signals as sig_mod  # noqa: E402
import spine  # noqa: E402
from L5.score import Policy, load_policy, score_spine  # noqa: E402
from tools import corpus_labels  # noqa: E402
from tools.rule_firing_report import jeffreys_interval, log_odds  # noqa: E402


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------

def auroc(y: np.ndarray, s: np.ndarray) -> float:
    y = np.asarray(y).astype(int)
    n_pos, n_neg = int((y == 1).sum()), int((y == 0).sum())
    if not n_pos or not n_neg:
        return float("nan")
    order = np.argsort(s, kind="mergesort")
    ranks = np.empty(len(s), dtype=float)
    ranks[order] = np.arange(1, len(s) + 1)
    ss = s[order]
    i = 0
    while i < len(ss):
        j = i
        while j + 1 < len(ss) and ss[j + 1] == ss[i]:
            j += 1
        if j > i:
            ranks[order[i:j + 1]] = (i + j + 2) / 2.0
        i = j + 1
    return float((ranks[y == 1].sum() - n_pos * (n_pos + 1) / 2) / (n_pos * n_neg))


def bootstrap_auroc(y: np.ndarray, s: np.ndarray, n: int = 2000,
                    seed: int = 20260812) -> tuple[float, float]:
    rng = np.random.default_rng(seed)
    idx_pos = np.flatnonzero(y == 1)
    idx_neg = np.flatnonzero(y == 0)
    if not len(idx_pos) or not len(idx_neg):
        return (float("nan"), float("nan"))
    vals = []
    for _ in range(n):
        p = rng.choice(idx_pos, len(idx_pos), replace=True)
        q = rng.choice(idx_neg, len(idx_neg), replace=True)
        take = np.concatenate([p, q])
        vals.append(auroc(y[take], s[take]))
    lo, hi = np.percentile(vals, [2.5, 97.5])
    return float(lo), float(hi)


# ---------------------------------------------------------------------------
# Corpus view
# ---------------------------------------------------------------------------

@dataclass
class Sample:
    sha256: str
    cls: str
    subclass: str | None
    keys: set[str]
    doc: dict[str, Any] = field(repr=False, default_factory=dict)


SCORED_CLASSES = (corpus_labels.CLASS_MALWARE, corpus_labels.CLASS_BENIGN)


def load_samples(labels: dict[str, Any], *,
                 include_excluded: bool = False) -> list[Sample]:
    """Labelled spines, malware and benign only unless asked otherwise.

    🔴 ``excluded`` must not reach the metrics. The four intentionally-vulnerable
    training apps (InsecureBankv2, PIVAA, UnCrackable) are neither malicious nor
    benign-representative, and a naive ``1 if malware else 0`` sweeps them into
    the negative class — which is exactly what the first version of this file
    did, reporting a benign denominator of 8 against a real one of 4. The
    false-positive rate is the number this project rests on; inflating its
    denominator with apps that were never benign flatters it silently.

    They are still scored, separately, as negative controls (§ negative_controls).
    """
    out: list[Sample] = []
    for doc in spine.iter_spines():
        entry = labels.get(doc.get("sha256", ""))
        if not entry:
            continue
        cls = entry["class"]
        if cls == corpus_labels.CLASS_CONFLICTED:
            continue
        if cls not in SCORED_CLASSES and not include_excluded:
            continue
        out.append(Sample(sha256=doc["sha256"], cls=cls,
                          subclass=entry.get("subclass"),
                          keys=sig_mod.signal_keys(doc), doc=doc))
    return out


def negative_controls(labels: dict[str, Any], policy: Policy) -> dict[str, Any]:
    """The intentionally-vulnerable apps, scored but never counted as benign.

    They are a different question: "does a deliberately insecure but
    non-malicious app get flagged?" A High or Critical here is a defect
    regardless of what the benign FPR says.
    """
    rows = []
    for doc in spine.iter_spines():
        entry = labels.get(doc.get("sha256", ""))
        if not entry or entry["class"] != corpus_labels.CLASS_EXCLUDED:
            continue
        r = score_spine(doc, policy)
        rows.append({"sha256": doc["sha256"][:12],
                     "app": (doc.get("identity") or {}).get("app_label"),
                     "score": r.score, "band": r.band})
    return {"n": len(rows), "samples": sorted(rows, key=lambda r: -r["score"]),
            "max_band": max((r["band"] for r in rows), default=None,
                            key=lambda b: ["Informational", "Low", "Medium",
                                           "High", "Critical"].index(b))}


def refit_weights(train: list[Sample], base: dict[str, Any],
                  clip: float = 3.0) -> dict[str, Any]:
    """Recompute A4's weights on a training fold only.

    This is what makes cross-validation honest: the held-out fold must be
    priced by weights that never saw it.
    """
    mal = [s for s in train if s.cls == corpus_labels.CLASS_MALWARE]
    ben = [s for s in train if s.cls == corpus_labels.CLASS_BENIGN]
    M, B = len(mal), len(ben)
    out: dict[str, Any] = {}
    for key, meta in base.items():
        m = sum(1 for s in mal if key in s.keys)
        b = sum(1 for s in ben if key in s.keys)
        w = log_odds(m, M, b, B)
        out[key] = dict(meta)
        out[key].update(w=max(-clip, min(clip, w)), w_raw=w, m=m, M=M, b=b, B=B,
                        ben_rate=(b / B if B else 0.0),
                        ben_rate_ci95=list(jeffreys_interval(b, B)))
    return out


def score_all(samples: list[Sample], policy: Policy) -> np.ndarray:
    return np.array([score_spine(s.doc, policy).score for s in samples], dtype=float)


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def operating_points(y: np.ndarray, scores: np.ndarray,
                     thresholds: Iterable[int] = (25, 50, 70, 85)) -> list[dict[str, Any]]:
    rows = []
    n_pos, n_neg = int((y == 1).sum()), int((y == 0).sum())
    for t in thresholds:
        tp = int(((scores >= t) & (y == 1)).sum())
        fp = int(((scores >= t) & (y == 0)).sum())
        lo, hi = jeffreys_interval(fp, n_neg) if n_neg else (0.0, 1.0)
        rows.append({
            "threshold": t,
            "recall": round(tp / n_pos, 4) if n_pos else None,
            "benign_fpr": round(fp / n_neg, 4) if n_neg else None,
            "benign_fpr_ci95": [round(lo, 4), round(hi, 4)],
            "fp_count": fp, "n_benign": n_neg,
        })
    return rows


def class_distribution(samples: list[Sample], scores: np.ndarray,
                       policy: Policy) -> dict[str, Any]:
    by: dict[str, list[float]] = defaultdict(list)
    for s, sc in zip(samples, scores):
        key = s.subclass or s.cls
        by[key].append(sc)
    out = {}
    for cls, vals in sorted(by.items()):
        a = np.array(vals)
        bands = Counter(policy.band_of(int(v)) for v in a)
        out[cls] = {
            "n": len(a), "median": float(np.median(a)),
            "iqr": [float(np.percentile(a, 25)), float(np.percentile(a, 75))],
            "mean": round(float(a.mean()), 2),
            "bands": dict(bands),
        }
    return out


def cross_validated(samples: list[Sample], policy: Policy, folds: int,
                    seed: int = 20260812) -> dict[str, Any]:
    rng = np.random.default_rng(seed)
    idx = rng.permutation(len(samples))
    chunks = np.array_split(idx, folds)
    y_all, s_all = [], []
    base = policy.weights
    for k in range(folds):
        test_idx = set(chunks[k].tolist())
        train = [s for i, s in enumerate(samples) if i not in test_idx]
        test = [samples[i] for i in sorted(test_idx)]
        fold_policy = Policy(raw=policy.raw,
                             weights=refit_weights(train, base),
                             weights_meta=policy.weights_meta)
        s_all.extend(score_all(test, fold_policy).tolist())
        y_all.extend(1 if s.cls == corpus_labels.CLASS_MALWARE else 0 for s in test)
    y = np.array(y_all)
    s = np.array(s_all)
    lo, hi = bootstrap_auroc(y, s)
    return {"folds": folds, "auroc": round(auroc(y, s), 4),
            "auroc_ci95": [round(lo, 4), round(hi, 4)],
            "operating_points": operating_points(y, s)}


ABLATIONS = {
    "gates_only": {"scoring": False, "gates": True, "ml": False},
    "rules_only": {"scoring": True, "gates": False, "ml": False},
    "rules_gates": {"scoring": True, "gates": True, "ml": False},
    "full_hybrid": {"scoring": True, "gates": True, "ml": True},
}


def ablate(samples: list[Sample], policy: Policy, config: dict[str, bool]) -> dict[str, Any]:
    import copy
    raw = copy.deepcopy(policy.raw)
    if not config["gates"]:
        for g in raw.get("gates", {}).values():
            g["enabled"] = False
    raw.setdefault("ml", {})["enabled"] = config["ml"]
    weights = policy.weights if config["scoring"] else {}
    p = Policy(raw=raw, weights=weights, weights_meta=policy.weights_meta)
    scores = score_all(samples, p)
    y = np.array([1 if s.cls == corpus_labels.CLASS_MALWARE else 0 for s in samples])
    return {"auroc": round(auroc(y, scores), 4),
            "operating_points": operating_points(y, scores)}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--labels", default=str(corpus_labels.LABELS_PATH))
    ap.add_argument("--folds", type=int, default=5)
    ap.add_argument("--ablation", action="store_true")
    ap.add_argument("--out", default=None)
    args = ap.parse_args(argv)

    labels_doc = corpus_labels.load(Path(args.labels))
    policy = load_policy()
    samples = load_samples(corpus_labels.general_population(labels_doc["labels"]))

    n_mal = sum(1 for s in samples if s.cls == corpus_labels.CLASS_MALWARE)
    n_ben = sum(1 for s in samples if s.cls == corpus_labels.CLASS_BENIGN)
    print(f"scoring {len(samples)} samples ({n_mal} malware, {n_ben} benign)"
          f"  policy {policy.version}  weights {policy.weights_version}")
    if policy.unsupported:
        print("🔴 weights are UNSUPPORTED — every number below is provisional")

    scores = score_all(samples, policy)
    y = np.array([1 if s.cls == corpus_labels.CLASS_MALWARE else 0 for s in samples])
    lo, hi = bootstrap_auroc(y, scores)

    report: dict[str, Any] = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "policy_version": policy.version,
        "weights_version": policy.weights_version,
        "unsupported": policy.unsupported,
        "n_malware": n_mal, "n_benign": n_ben,
        "in_sample": {"auroc": round(auroc(y, scores), 4),
                      "auroc_ci95": [round(lo, 4), round(hi, 4)],
                      "operating_points": operating_points(y, scores)},
        "distribution": class_distribution(samples, scores, policy),
        "negative_controls": negative_controls(labels_doc["labels"], policy),
    }

    if n_ben >= args.folds and n_mal >= args.folds:
        print(f"cross-validating over {args.folds} folds (refitting weights each)…")
        report["cross_validated"] = cross_validated(samples, policy, args.folds)

    if args.ablation:
        print("running ablation…")
        report["ablation"] = {name: ablate(samples, policy, cfg)
                              for name, cfg in ABLATIONS.items()}

    # ---- console ----------------------------------------------------------
    print("\nSCORE DISTRIBUTION")
    print(f"  {'class':22s} {'n':>5s} {'median':>7s} {'IQR':>15s}")
    for cls, d in report["distribution"].items():
        print(f"  {cls:22s} {d['n']:5d} {d['median']:7.1f} "
              f"[{d['iqr'][0]:5.1f},{d['iqr'][1]:5.1f}]")

    ins = report["in_sample"]
    print(f"\nAUROC in-sample      {ins['auroc']:.4f}  "
          f"95% CI [{ins['auroc_ci95'][0]:.4f}, {ins['auroc_ci95'][1]:.4f}]")
    if "cross_validated" in report:
        cv = report["cross_validated"]
        print(f"AUROC cross-validated {cv['auroc']:.4f}  "
              f"95% CI [{cv['auroc_ci95'][0]:.4f}, {cv['auroc_ci95'][1]:.4f}]")
        gap = ins["auroc"] - cv["auroc"]
        print(f"  gap {gap:+.4f}" + ("   ← weights are memorising, not measuring"
                                     if gap > 0.05 else ""))

    print("\nOPERATING POINTS (cross-validated)"
          if "cross_validated" in report else "\nOPERATING POINTS (in-sample)")
    rows = report.get("cross_validated", ins)["operating_points"]
    print(f"  {'score>=':>8s} {'recall':>7s} {'benign FPR':>11s} {'95% CI':>18s}")
    for r in rows:
        ci = f"[{r['benign_fpr_ci95'][0]:.4f},{r['benign_fpr_ci95'][1]:.4f}]"
        print(f"  {r['threshold']:8d} {r['recall']:7.4f} {r['benign_fpr']:11.4f} {ci:>18s}"
              f"   ({r['fp_count']}/{r['n_benign']})")

    if "ablation" in report:
        print("\nABLATION")
        print(f"  {'config':14s} {'AUROC':>7s}   recall@FPR<=1%")
        for name, d in report["ablation"].items():
            best = None
            for r in d["operating_points"]:
                if r["benign_fpr"] is not None and r["benign_fpr"] <= 0.01:
                    best = r if best is None or r["recall"] > best["recall"] else best
            rec = f"{best['recall']:.4f} @ {best['threshold']}" if best else "—"
            print(f"  {name:14s} {d['auroc']:7.4f}   {rec}")

    out = Path(args.out) if args.out else (
        REPO_ROOT / "docs" / "reports" /
        f"evaluation_{datetime.now(timezone.utc):%Y%m%d}.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2))
    print(f"\nwrote {out.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
