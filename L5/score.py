"""L5 — auditable hybrid scoring.

    source source_env.sh
    $SENTINEL_PYTHON L5/l5.py <sha256> --explain

Every point in a final score traces to a named signal or gate carrying the
evidence ``id`` that produced it. That is the whole design constraint; the
arithmetic below exists to serve it.

**Weights are computed, not asserted.** They come from A4
(``tools/rule_firing_report.py``) as Jeffreys-smoothed log odds ratios over
measured counts. L5 refuses a weights file whose ``ruleset_version`` does not
match the current ruleset, and refuses to arm gates when its support stamp says
``unsupported`` — which, at ``n_benign = 4``, it does (T24).

**Four stages, in this order:**

1. *Accumulate*, with a per-family redundancy discount. Three SMS rules firing
   on one class is close to one fact, not three; naive addition double-counts
   correlated evidence and manufactures confidence.
2. *Map* the unbounded total to 0–100 through a sigmoid with two fitted
   anchors. A bare linear map has arbitrary endpoints; a plain ``sigmoid(S)``
   saturates so hard that nearly every malware sample lands at 99 and the Low
   and Medium bands are never used.
3. *Apply L3*, clipped to ±10 points and unable to reach Critical alone.
3b. *Apply L3b* (the banking-specific prior), independently clipped to ±10
   points, unable to reach Critical alone, and refused entirely unless its
   training run's held-out metric was family-disjoint-verified.
4. *Apply gates as floors* — ``max(score, floor)``, never an override. A gate
   can only raise, never lower, and the additive score may legitimately exceed
   the floor, in which case the full reason chain survives intact.

**The LLM contributes zero points.** There is no code path by which L4 output
reaches this module. It generates evidence and explanation; it never votes.
"""

from __future__ import annotations

import fnmatch
import math
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import signals as sig_mod  # noqa: E402

# ln(0.85/0.15) — the logit of the Critical band edge, used to solve for T.
LOGIT_85 = 1.7346010553881064


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Contribution:
    source: str
    evidence_ids: tuple[str, ...]
    family: str | None
    weight_raw: float
    discount: float
    weight_applied: float
    support: str
    status: str          # priced | negligible | degenerate | unpriced | capped

    def describe(self) -> str:
        ids = ",".join(self.evidence_ids) or "-"
        return (f"{self.weight_applied:+6.2f}  {self.source}  [{ids}]"
                f"  ({self.status}"
                + (f", x{self.discount:.2f}" if self.discount != 1.0 else "") + ")")


@dataclass(frozen=True)
class GateResult:
    gate_id: str
    state: str           # fired | not_fired | indeterminate | disabled
    floor: int
    legs: tuple[dict[str, Any], ...] = ()
    missing_inputs: tuple[str, ...] = ()
    note: str = ""


@dataclass(frozen=True)
class ScoreResult:
    sha256: str
    score: int
    band: str
    confidence: float
    confidence_band: str
    log_odds: float
    contributions: tuple[Contribution, ...]
    gates: tuple[GateResult, ...]
    binding_reason: str
    policy_version: str
    weights_version: str
    ruleset_version: str
    unsupported: bool
    ml_delta: int = 0
    banking_ml_delta: int = 0
    ai_delta: int = 0


# ---------------------------------------------------------------------------
# Policy
# ---------------------------------------------------------------------------

@dataclass
class Policy:
    raw: dict[str, Any]
    weights: dict[str, Any]
    weights_meta: dict[str, Any] = field(default_factory=dict)

    @property
    def version(self) -> str:
        return str(self.raw.get("policy_version", "unknown"))

    @property
    def weights_version(self) -> str:
        return str(self.weights_meta.get("generated_at", "unknown"))[:10]

    @property
    def unsupported(self) -> bool:
        return self.weights_meta.get("support", {}).get("status") != "supported"

    def family_of(self, key: str, category: str) -> tuple[str | None, float, float]:
        """(family, decay, cap) for a signal, matched on key glob or category."""
        for name, spec in (self.raw.get("families") or {}).items():
            for pattern in spec.get("members", []):
                if pattern.startswith("cat:"):
                    if category == pattern[4:]:
                        return name, spec.get("decay", 1.0), spec.get("cap", 99.0)
                elif fnmatch.fnmatch(key, pattern):
                    return name, spec.get("decay", 1.0), spec.get("cap", 99.0)
        return None, 1.0, 99.0

    def band_of(self, score: int) -> str:
        for lo, hi, name in self.raw.get("bands", []):
            if lo <= score <= hi:
                return str(name)
        return "Unknown"

    def confidence_band_of(self, c: float) -> str:
        for lo, hi, name in (self.raw.get("confidence") or {}).get("bands", []):
            if lo <= c <= hi:
                return str(name)
        return "unknown"


def load_policy(policy_path: Path | None = None,
                weights_path: Path | None = None) -> Policy:
    import json

    import yaml

    policy_path = policy_path or (REPO_ROOT / "L5" / "policy.yaml")
    raw = yaml.safe_load(policy_path.read_text())

    if weights_path is None:
        candidate = (policy_path.parent / raw.get("weights_file", "")).resolve()
        if not candidate.is_file():
            # Fall back to the newest weights file A4 produced.
            found = sorted((policy_path.parent / "weights").glob("rule_weights_*.json"))
            if not found:
                raise SystemExit(
                    "no weights file. Run:\n"
                    "    $SENTINEL_PYTHON tools/rule_firing_report.py"
                )
            candidate = found[-1]
        weights_path = candidate

    wdoc = json.loads(Path(weights_path).read_text())
    return Policy(raw=raw, weights=wdoc.get("weights", {}), weights_meta=wdoc)


# ---------------------------------------------------------------------------
# Stage 1 — accumulate
# ---------------------------------------------------------------------------

def accumulate(sigs: list[sig_mod.Signal],
               policy: Policy) -> tuple[float, list[Contribution]]:
    cfg = policy.raw.get("scoring") or {}
    floor = float(cfg.get("min_abs_weight", 0.0))
    drop_degenerate = bool(cfg.get("exclude_degenerate", True))

    staged: list[tuple[str | None, float, float, Contribution]] = []
    for s in sigs:
        entry = policy.weights.get(s.key)
        if entry is None:
            staged.append((None, 1.0, 99.0, Contribution(
                source=s.key, evidence_ids=s.evidence_ids, family=None,
                weight_raw=0.0, discount=1.0, weight_applied=0.0,
                support="unknown", status="unpriced")))
            continue

        w = float(entry.get("w", 0.0))
        if drop_degenerate and entry.get("degenerate"):
            status = "degenerate"
        elif abs(w) < floor:
            status = "negligible"
        else:
            status = "priced"

        family, decay, cap = policy.family_of(s.key, entry.get("category", "other"))
        staged.append((family, decay, cap, Contribution(
            source=s.key, evidence_ids=s.evidence_ids, family=family,
            weight_raw=w, discount=1.0,
            weight_applied=0.0 if status != "priced" else w,
            support=str(entry.get("support", "unknown")), status=status)))

    # Group by family, rank by |w| descending, discount geometrically, cap.
    by_family: dict[str | None, list[int]] = {}
    for i, (family, _d, _c, _c2) in enumerate(staged):
        by_family.setdefault(family, []).append(i)

    final: list[Contribution] = [c for _f, _d, _cap, c in staged]
    total = 0.0

    for family, idxs in by_family.items():
        priced = [i for i in idxs if staged[i][3].status == "priced"]
        priced.sort(key=lambda i: -abs(staged[i][3].weight_raw))

        if family is None:
            for i in priced:
                total += staged[i][3].weight_raw
            continue

        _f, decay, cap = staged[priced[0]][:3] if priced else (None, 1.0, 99.0)
        family_total = 0.0
        for rank, i in enumerate(priced):
            c = staged[i][3]
            disc = decay ** rank
            applied = c.weight_raw * disc
            family_total += applied
            final[i] = Contribution(
                source=c.source, evidence_ids=c.evidence_ids, family=family,
                weight_raw=c.weight_raw, discount=disc, weight_applied=applied,
                support=c.support, status=c.status)

        clamped = max(-cap, min(cap, family_total))
        if clamped != family_total and priced:
            # Attribute the clamp to the family's weakest member, so the audit
            # trail shows where the cap bit rather than silently rescaling.
            i = priced[-1]
            c = final[i]
            final[i] = Contribution(
                source=c.source, evidence_ids=c.evidence_ids, family=family,
                weight_raw=c.weight_raw, discount=c.discount,
                weight_applied=c.weight_applied - (family_total - clamped),
                support=c.support, status="capped")
        total += clamped

    return total, final


# ---------------------------------------------------------------------------
# Stage 2 — map to 0..100
# ---------------------------------------------------------------------------

def to_score(log_odds: float, policy: Policy) -> int:
    cal = policy.raw.get("calibration") or {}
    s0 = float(cal.get("s0", 3.0))
    T = float(cal.get("temperature", 2.0)) or 1e-9
    return int(round(100.0 / (1.0 + math.exp(-(log_odds - s0) / T))))


def solve_temperature(s0: float, s_at_1pct_fpr: float) -> float:
    """T such that the 1%-benign-FPR log-odds lands exactly on score 85."""
    return max((s_at_1pct_fpr - s0) / LOGIT_85, 1e-6)


# ---------------------------------------------------------------------------
# Stage 3 — L3
# ---------------------------------------------------------------------------

def apply_ml(score: int, doc: dict[str, Any],
             policy: Policy) -> tuple[int, int, str]:
    """Returns (score, delta, binding_reason_fragment)."""
    cfg = policy.raw.get("ml") or {}
    if not cfg.get("enabled"):
        return score, 0, ""
    l3 = (doc.get("layers", {}).get("l3") or {})
    prob = (l3.get("summary") or {}).get("prob_malicious")
    if prob is None:
        return score, 0, ""

    cap = int(cfg.get("max_delta", 10))
    delta = int(max(-cap, min(cap, round(2 * cap * (float(prob) - 0.5)))))
    new = max(0, min(100, score + delta))

    if score < 85 <= new and not cfg.get("may_reach_critical", False):
        # A generic maliciousness prior trained on a ~99.6% non-banking corpus
        # must not be able to declare a banking trojan by itself.
        return 84, delta, "ml_clamp"
    return new, delta, ""


# ---------------------------------------------------------------------------
# Stage 3b — L3b (banking-specific prior)
# ---------------------------------------------------------------------------

def apply_banking_ml(score: int, doc: dict[str, Any],
                     policy: Policy) -> tuple[int, int, str]:
    """Second, independently-bounded stage — see ``L3b/predict.py``.

    Kept separate from ``apply_ml`` rather than merged into one bound: L3 and
    L3b answer different questions (generic malware resemblance vs banking
    resemblance), L3b's training population is far smaller and weaker than
    L3's, and the audit trail (``--explain``, per-stage reason strings) needs
    them individually attributable.

    ``require_family_disjoint`` (default true) additionally refuses to apply
    the delta unless ``l3b.summary.family_disjoint_status == "verified"`` —
    the delta is still computed (so ``--explain`` can show what it *would*
    have been) but the score is left untouched, with a distinct reason string
    so this is visible rather than silently indistinguishable from "L3b was
    never run."
    """
    cfg = policy.raw.get("banking_ml") or {}
    if not cfg.get("enabled"):
        return score, 0, ""
    l3b = (doc.get("layers", {}).get("l3b") or {})
    summary = l3b.get("summary") or {}
    prob = summary.get("prob_banking_malicious")
    if prob is None:
        return score, 0, ""

    cap = int(cfg.get("max_delta", 10))
    delta = int(max(-cap, min(cap, round(2 * cap * (float(prob) - 0.5)))))

    if (cfg.get("require_family_disjoint", True)
            and summary.get("family_disjoint_status") != "verified"):
        return score, delta, "banking_ml_unverified_split"

    new = max(0, min(100, score + delta))
    if score < 85 <= new and not cfg.get("may_reach_critical", False):
        return 84, delta, "banking_ml_clamp"
    return new, delta, ""


# ---------------------------------------------------------------------------
# Stage 3c — L4 (AI) contribution — OFF by default, analyst-toggleable
# ---------------------------------------------------------------------------

def apply_l4(score: int, doc: dict[str, Any], policy: Policy,
             include_ai: bool = True) -> tuple[int, int, str]:
    """Bounded L4 (AI) contribution to the score, gated on evidence quality.

    This overrides the earlier "LLM contributes zero points" default at the
    user's explicit instruction (2026-08-26): the AI reasoning contributes **only
    when its evidence is strong enough** — either a class was *RAG-grounded*
    (a knowledge-base match survived the adversarial verifier) **or** L4's best
    class score is ``>= min_score`` (default 5). A weak, ungrounded reading still
    contributes nothing. The contribution is bounded, **positive-only** (AI
    reasoning only raises suspicion, never discounts), and — exactly like L3 —
    cannot push a sample to Critical on its own.

    ``include_ai=False`` forces it off (the ``/api/score?ai=0`` comparison view);
    the persisted score uses the default, so a qualifying L4 *is* reflected in
    the stored verdict and the report says so.
    """
    if not include_ai:
        return score, 0, ""
    cfg = policy.raw.get("ai") or {}
    if not cfg.get("enabled"):
        return score, 0, ""
    summary = (doc.get("layers", {}).get("l4") or {}).get("summary") or {}
    max_score = summary.get("max_score")
    if max_score is None:
        return score, 0, ""
    bands = summary.get("score_bands") or {}
    grounded = int(bands.get("grounded", 0)) > 0
    min_score = int(cfg.get("min_score", 5))
    # The gate: RAG-grounded, or a best class score at/above the floor.
    if not (grounded or float(max_score) >= min_score):
        return score, 0, "ai_below_threshold"
    cap = int(cfg.get("max_delta", 10))
    delta = int(max(0, min(cap, round((float(max_score) / 10.0) * cap))))
    new = max(0, min(100, score + delta))
    if score < 85 <= new and not cfg.get("may_reach_critical", False):
        return 84, delta, "ai_clamp"
    return new, delta, "ai_grounded" if grounded else "ai_scored"


# ---------------------------------------------------------------------------
# Stage 4 — gates as floors
# ---------------------------------------------------------------------------

def apply_gates(score: int, gates: list[GateResult]) -> tuple[int, str]:
    best: GateResult | None = None
    for g in gates:
        if g.state == "fired" and g.floor > score:
            if best is None or g.floor > best.floor:
                best = g
    if best is None:
        return score, "additive"
    return best.floor, f"gate:{best.gate_id}"


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def score_spine(doc: dict[str, Any], policy: Policy,
                include_ai: bool = True) -> ScoreResult:
    from L5 import confidence as conf_mod
    from L5 import gates as gates_mod

    sigs = sig_mod.signals(doc)
    log_odds, contributions = accumulate(sigs, policy)
    base = to_score(log_odds, policy)

    scored, ml_delta, ml_reason = apply_ml(base, doc, policy)
    scored, banking_ml_delta, banking_ml_reason = apply_banking_ml(scored, doc, policy)
    # L4 (AI) contribution — no-op unless the caller explicitly opts in; the
    # persisted score always passes include_ai=False (see apply_l4).
    scored, ai_delta, ai_reason = apply_l4(scored, doc, policy, include_ai)
    gate_results = gates_mod.evaluate_all(doc, policy)
    final, binding = apply_gates(scored, gate_results)
    if binding == "additive":
        binding = banking_ml_reason or ml_reason or ai_reason or binding

    unsupported = policy.unsupported
    c, c_band = conf_mod.confidence(doc, policy, gate_results, unsupported)

    return ScoreResult(
        sha256=doc.get("sha256", ""),
        score=final,
        band=policy.band_of(final),
        confidence=c,
        confidence_band=c_band,
        log_odds=log_odds,
        contributions=tuple(contributions),
        gates=tuple(gate_results),
        binding_reason=binding,
        policy_version=policy.version,
        weights_version=policy.weights_version,
        ruleset_version=str(policy.weights_meta.get("ruleset_version", "unknown")),
        unsupported=unsupported,
        ml_delta=ml_delta,
        banking_ml_delta=banking_ml_delta,
        ai_delta=ai_delta,
    )
