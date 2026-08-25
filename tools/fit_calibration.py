"""Fit L5's two calibration anchors from labelled data.

    source source_env.sh
    $SENTINEL_PYTHON tools/fit_calibration.py
    $SENTINEL_PYTHON tools/fit_calibration.py --apply     # write into policy.yaml

L5 maps an unbounded log-odds total ``S`` to 0–100 through

    score = 100 · σ((S − s0) / T)

which has exactly two free parameters, and the whole point is that both have an
operational definition rather than being chosen because the output looked
reasonable.

**s0 is the 50-point anchor.** It is the log-odds at which the empirical
posterior ``P(malware | S)`` crosses 0.5 on the labelled corpus. So "score 50"
*means* "given this evidence, as likely malicious as benign" — which is what
the Medium boundary should mean, and is checkable against the data rather than
asserted.

**T is set by the 85-point anchor.** Let ``S_fp1%`` be the log-odds at which
the benign false-positive rate first reaches 1%. Since score 85 corresponds to
``(S − s0)/T = ln(0.85/0.15) = 1.7346``:

    T = (S_fp1% − s0) / 1.7346

so the Critical band begins exactly where 1 benign app in 100 would be caught.
Scores 25 and 70 then fall out of the sigmoid rather than being separately
invented.

🔴 **Refuses to fit on a denominator that cannot carry it.** With B benign
samples, the smallest false-positive rate distinguishable from zero is 1/B, so
estimating a 1% threshold needs B ≳ 100. Below ``--min-benign`` this tool
reports what it would have fitted and exits non-zero without writing anything —
because a calibration fitted on four apps is a decoration, and stamping it
``fitted`` would launder exactly the problem B30 documents.
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np

REPO_ROOT = Path(__file__).resolve().parent.parent
for _p in (str(REPO_ROOT), str(REPO_ROOT / "L1")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import signals as sig_mod  # noqa: E402
import spine  # noqa: E402
from L5.score import LOGIT_85, Policy, accumulate, load_policy  # noqa: E402
from tools import corpus_labels  # noqa: E402

MIN_BENIGN_FOR_FIT = 100
TARGET_FPR = 0.01

# Below this the sigmoid is a step function: every sample lands at 0 or 100 and
# the bands between them are never used. It happens whenever the two anchors
# coincide, which is what a degenerate corpus produces.
MIN_TEMPERATURE = 0.1

# The empirical posterior P(malware | S) is a posterior, so it carries the
# corpus prior. At 640 malware against 4 benign the prior is 0.994 and the
# posterior exceeds 0.5 almost everywhere, which pins s0 at the low end of S
# regardless of what the evidence says. Reported so a lopsided fit is visible
# rather than mistaken for a property of the detector.
MAX_SANE_PREVALENCE = 0.9


@dataclass
class Fit:
    s0: float
    temperature: float
    s_at_target_fpr: float
    n_malware: int
    n_benign: int
    target_fpr: float
    crossing_method: str
    supported: bool
    reason: str = ""

    def to_policy(self) -> dict[str, Any]:
        return {
            "method": "sigmoid",
            "s0": round(self.s0, 4),
            "temperature": round(self.temperature, 4),
            "status": "fitted" if self.supported else "declared",
            "fitted_on": {
                "date": datetime.now(timezone.utc).date().isoformat(),
                "n_malware": self.n_malware,
                "n_benign": self.n_benign,
                "target_fpr": self.target_fpr,
                "s_at_target_fpr": round(self.s_at_target_fpr, 4),
                "crossing_method": self.crossing_method,
            } if self.supported else None,
        }


def log_odds_for_corpus(policy: Policy, labels: dict[str, Any]
                        ) -> tuple[np.ndarray, np.ndarray]:
    """(S, y) over labelled spines. Excluded and conflicted classes are dropped."""
    S: list[float] = []
    y: list[int] = []
    for doc in spine.iter_spines():
        entry = labels.get(doc.get("sha256", ""))
        if not entry or entry["class"] not in (corpus_labels.CLASS_MALWARE,
                                               corpus_labels.CLASS_BENIGN):
            continue
        total, _ = accumulate(sig_mod.signals(doc), policy)
        S.append(total)
        y.append(1 if entry["class"] == corpus_labels.CLASS_MALWARE else 0)
    return np.array(S), np.array(y)


def posterior_crossing(S: np.ndarray, y: np.ndarray,
                       window: int = 101) -> tuple[float, str]:
    """Smallest S where the local empirical P(malware | S) crosses 0.5.

    A sliding window over S-sorted labels rather than fixed bins: bins put the
    crossing wherever the bin edges happen to fall, and S is not uniformly
    distributed.
    """
    order = np.argsort(S)
    s_sorted, y_sorted = S[order], y[order]
    n = len(s_sorted)
    if n < window:
        window = max(3, n // 3 | 1)

    half = window // 2
    kernel = np.ones(window) / window
    smoothed = np.convolve(y_sorted, kernel, mode="valid")
    centres = s_sorted[half:half + len(smoothed)]

    above = np.flatnonzero(smoothed >= 0.5)
    if len(above) == 0:
        return float(s_sorted[-1]), "no_crossing_used_max"
    i = int(above[0])
    if i == 0:
        return float(centres[0]), "crossing_at_lower_edge"
    # Linear interpolation between the two straddling window centres.
    x0, x1 = centres[i - 1], centres[i]
    p0, p1 = smoothed[i - 1], smoothed[i]
    if p1 == p0:
        return float(x1), "window_sliding"
    return float(x0 + (0.5 - p0) * (x1 - x0) / (p1 - p0)), "window_sliding_interp"


def threshold_at_fpr(S: np.ndarray, y: np.ndarray, target: float) -> float:
    """Smallest S whose benign false-positive rate is <= target."""
    benign = np.sort(S[y == 0])[::-1]
    if len(benign) == 0:
        return float(S.max())
    k = int(math.floor(target * len(benign)))
    # Allow k benign above the threshold; place it just above the (k+1)-th.
    if k >= len(benign):
        return float(benign[-1])
    return float(benign[k]) + 1e-9


def fit(policy: Policy, labels: dict[str, Any], *,
        min_benign: int = MIN_BENIGN_FOR_FIT,
        target_fpr: float = TARGET_FPR) -> Fit:
    S, y = log_odds_for_corpus(policy, labels)
    n_mal, n_ben = int((y == 1).sum()), int((y == 0).sum())

    s0, method = posterior_crossing(S, y)
    s_fpr = threshold_at_fpr(S, y, target_fpr)
    T = max((s_fpr - s0) / LOGIT_85, 1e-6)

    prevalence = n_mal / max(n_mal + n_ben, 1)
    problems: list[str] = []
    if n_ben < min_benign:
        problems.append(
            f"n_benign={n_ben} < {min_benign}: the smallest distinguishable "
            f"false-positive rate is 1/{n_ben} = {1/max(n_ben,1):.3f}, which "
            f"cannot locate a {target_fpr:.0%} threshold")
    if T < MIN_TEMPERATURE:
        problems.append(
            f"temperature {T:.4f} < {MIN_TEMPERATURE}: the two anchors have "
            f"collapsed onto each other, so the sigmoid is a step function and "
            f"every sample would land at 0 or 100")
    if prevalence > MAX_SANE_PREVALENCE:
        problems.append(
            f"malware prevalence {prevalence:.1%} > {MAX_SANE_PREVALENCE:.0%}: "
            f"the empirical posterior is dominated by the class prior, so s0 "
            f"reflects the corpus composition rather than the evidence")

    supported = not problems
    reason = "; ".join(problems)
    return Fit(s0=s0, temperature=T, s_at_target_fpr=s_fpr, n_malware=n_mal,
               n_benign=n_ben, target_fpr=target_fpr, crossing_method=method,
               supported=supported, reason=reason)


def apply_to_policy(f: Fit, path: Path) -> None:
    """Rewrite only the calibration block, preserving comments elsewhere.

    yaml.safe_dump would strip every comment in policy.yaml, and those comments
    are the justification for the numbers around them.
    """
    text = path.read_text()
    block = f.to_policy()
    lines = text.splitlines()
    out: list[str] = []
    i = 0
    while i < len(lines):
        if lines[i].startswith("calibration:"):
            out.append("calibration:")
            out.append("  method: sigmoid")
            out.append(f"  s0: {block['s0']}")
            out.append(f"  temperature: {block['temperature']}")
            out.append(f"  status: {block['status']}")
            if block["fitted_on"]:
                out.append(f"  fitted_on: {json.dumps(block['fitted_on'])}")
            else:
                out.append("  fitted_on: null")
            i += 1
            while i < len(lines) and (lines[i].startswith((" ", "\t"))
                                      or not lines[i].strip()):
                if lines[i].strip() and not lines[i].startswith(" "):
                    break
                i += 1
            continue
        out.append(lines[i])
        i += 1
    path.write_text("\n".join(out) + "\n")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--labels", default=str(corpus_labels.LABELS_PATH))
    ap.add_argument("--min-benign", type=int, default=MIN_BENIGN_FOR_FIT)
    ap.add_argument("--target-fpr", type=float, default=TARGET_FPR)
    ap.add_argument("--apply", action="store_true",
                    help="write the fitted anchors into L5/policy.yaml")
    args = ap.parse_args(argv)

    labels_doc = corpus_labels.load(Path(args.labels))
    policy = load_policy()
    f = fit(policy, corpus_labels.general_population(labels_doc["labels"]),
            min_benign=args.min_benign, target_fpr=args.target_fpr)

    print(f"corpus: {f.n_malware} malware, {f.n_benign} benign")
    print(f"  s0            {f.s0:+.4f}   (50-point anchor, {f.crossing_method})")
    print(f"  S @ {f.target_fpr:.0%} FPR  {f.s_at_target_fpr:+.4f}   (85-point anchor)")
    print(f"  temperature   {f.temperature:.4f}")

    # What the bands become under this fit.
    print("\n  band edges in log-odds:")
    for score, label in ((25, "Low"), (50, "Medium"), (70, "High"), (85, "Critical")):
        p = score / 100.0
        s = f.s0 + f.temperature * math.log(p / (1 - p))
        print(f"    score {score:3d} ({label:13s}) at S = {s:+.3f}")

    if not f.supported:
        print(f"\n🔴 NOT FITTED — {f.reason}")
        print("   policy.yaml is unchanged; calibration stays 'declared' and "
              "every score stays stamped unsupported.")
        return 1

    if args.apply:
        path = REPO_ROOT / "L5" / "policy.yaml"
        apply_to_policy(f, path)
        print(f"\nwrote calibration into {path.relative_to(REPO_ROOT)}")
    else:
        print("\n(--apply to write these into L5/policy.yaml)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
