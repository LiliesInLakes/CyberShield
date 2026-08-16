"""Deterministic 0-10 class score — the last step of the L4 pipeline, not another LLM call.

Per `decisions/plan_l4_agentic_verdicts.md` §3, the score is a pure function
of artifacts the rest of the pipeline already produced: what `L4/verify.py`
mechanically kept and dropped, what `L4/knowledge/retriever.py` retrieved,
what the adversarial verifier agent (`L4/verify_verdict.py`) concluded, and
the analyst's own carried-unverified hunch. No network call happens here, so
a score is reproducible from its inputs and auditable the same way
`L5/l5.py --explain` is — re-run `score_class` on the same four inputs and
get the same number back.

**Bands** (mirrors the plan's table exactly):

===================================================  ===========================================
condition                                             score
===================================================  ===========================================
``verifier_result.status == "refuted"``               0 (dropped from the ranked list; kept in
                                                        `dropped_claims` for audit only)
no KB match, no kept claims, `suspicion.flag` and      1-4, scaled by the *verifier's* confidence
verifier did not refute it                             in its own counter-check (never the
                                                        analyst's self-reported confidence)
no KB match, >=1 kept mechanical claim                 3-5
KB match (sim >= 0.3) and status == "confirmed"        5-10, linear on similarity: 0.3 -> 5,
                                                        1.0 -> 10; then -1 per dropped claim,
                                                        floored at 5
KB match and status == "weakened"                      same band as ungrounded-confirmed, one
                                                        band down (i.e. capped at 5, the top of
                                                        the "no KB match, kept claims" band)
===================================================  ===========================================

This directly implements "unverified claims can be given a sub-5 score in
case the LLM provides a reasonable reason" — the reasonableness test is
whether the **verifier**, actively looking for a flaw, failed to find one.
That is not the analyst grading its own work, which is the same
anti-self-report discipline `L4/verify.py` already enforces on individual
claims, applied here to the aggregate score.

**Loose typing by design.** `kb_matches` items are expected to expose a
``.similarity: float`` attribute, matching `L4/knowledge/retriever.py`'s
``KBMatch`` dataclass, which is being built by a different agent in parallel
against the same plan. `verifier_result` is expected to expose
``.status: Literal["confirmed", "weakened", "refuted"]`` and
``.confidence: Literal["high", "medium", "low"]``, matching (in spirit)
`L4/verify_verdict.py`'s ``VerifierVerdict``, also being built in parallel.
This module does not import either dataclass — importing a module another
agent is actively writing would create a circular/premature dependency, and
duck-typing via a local :class:`Protocol` keeps this file buildable and
independently testable right now. If the real shapes differ once both land,
that is a small integration fix, not a redesign: only ``_verifier_confidence``
and the two ``.similarity``/``.status`` attribute reads below would need to
change.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal, Protocol, Sequence, runtime_checkable

Band = Literal["grounded", "plausible", "hunch", "refuted"]

_MIN_SIMILARITY = 0.3
_MAX_SIMILARITY = 1.0

# verifier_result.confidence -> where in the 1-4 hunch band it lands.
_HUNCH_CONFIDENCE_SCORE = {"high": 4, "medium": 2, "low": 1}


@runtime_checkable
class _HasSimilarity(Protocol):
    """Structural stand-in for `L4/knowledge/retriever.py`'s `KBMatch`."""
    similarity: float


@runtime_checkable
class _VerifierResult(Protocol):
    """Structural stand-in for `L4/verify_verdict.py`'s `VerifierVerdict`."""
    status: Literal["confirmed", "weakened", "refuted"]
    confidence: Literal["high", "medium", "low"]


@dataclass
class ClassScore:
    score: int                  # 0-10
    band: Band
    rationale: str               # one line, derived, not another LLM call


def _kept_claim_count(kept_claims: dict) -> int:
    """Number of individual mechanically-kept claims, across all claim kinds.

    Mirrors `L4/verify.py::Verdict.summary`'s counting convention: a dict or
    list claim kind counts its entries, anything else (an unexpected shape)
    counts as at most one so a malformed input degrades rather than crashes.
    """
    total = 0
    for value in (kept_claims or {}).values():
        if isinstance(value, (list, dict)):
            total += len(value)
        elif value:
            total += 1
    return total


def _best_similarity(kb_matches: Sequence[Any]) -> float | None:
    sims = [m.similarity for m in (kb_matches or []) if hasattr(m, "similarity")]
    return max(sims) if sims else None


def _has_kb_match(kb_matches: Sequence[Any]) -> bool:
    best = _best_similarity(kb_matches)
    return best is not None and best >= _MIN_SIMILARITY


def _verifier_status(verifier_result: Any) -> str | None:
    return getattr(verifier_result, "status", None)


def _verifier_confidence(verifier_result: Any) -> str:
    return getattr(verifier_result, "confidence", "low")


def _similarity_to_score(similarity: float) -> float:
    """Linear map: 0.3 -> 5.0, 1.0 -> 10.0."""
    similarity = max(_MIN_SIMILARITY, min(_MAX_SIMILARITY, similarity))
    span = _MAX_SIMILARITY - _MIN_SIMILARITY
    return 5.0 + (similarity - _MIN_SIMILARITY) / span * 5.0


def score_class(
    kept_claims: dict,
    dropped_claims: list,
    kb_matches: Sequence[Any],
    verifier_result: Any,
    suspicion: dict | None,
) -> ClassScore:
    """Compute a class's 0-10 score. Pure function — see module docstring for the bands."""
    status = _verifier_status(verifier_result)
    kb_match = _has_kb_match(kb_matches)
    kept_count = _kept_claim_count(kept_claims)
    dropped_count = len(dropped_claims or [])
    suspicion = suspicion or {}

    # Band 1: refuted -> 0, always, regardless of anything else.
    if status == "refuted":
        return ClassScore(
            score=0, band="refuted",
            rationale="verifier refuted the reasoning trail; dropped from the ranked list",
        )

    # Band 2 (KB-grounded): confirmed or weakened.
    if kb_match and status in ("confirmed", "weakened"):
        best_sim = _best_similarity(kb_matches) or _MIN_SIMILARITY
        if status == "confirmed":
            raw = _similarity_to_score(best_sim) - dropped_count
            score = max(5, min(10, round(raw)))
            rationale = (
                f"KB match (sim={best_sim:.2f}), verifier confirmed, "
                f"-{dropped_count} for dropped claims -> {score}"
            )
        else:  # weakened: one band down from ungrounded-confirmed, capped at 5
            score = min(5, 3 + kept_count)
            rationale = (
                f"KB match (sim={best_sim:.2f}) but verifier weakened it; "
                f"scored as an ungrounded solid claim, capped at 5 -> {score}"
            )
        return ClassScore(score=score, band="grounded", rationale=rationale)

    # Band 3: no KB match, but at least one mechanically kept claim.
    if not kb_match and kept_count >= 1:
        score = min(5, 3 + kept_count - 1)
        return ClassScore(
            score=score, band="plausible",
            rationale=(
                f"no KB match, {kept_count} mechanically kept claim(s), "
                f"no threat-intel grounding -> {score}"
            ),
        )

    # Band 4: no KB match, no kept claims, but a hunch the verifier didn't refute.
    if not kb_match and kept_count == 0 and suspicion.get("flag") and status != "refuted":
        confidence = _verifier_confidence(verifier_result)
        score = _HUNCH_CONFIDENCE_SCORE.get(confidence, 1)
        return ClassScore(
            score=score, band="hunch",
            rationale=(
                f"unverified hunch, verifier confidence={confidence}, "
                f"not refuted -> {score}"
            ),
        )

    # Nothing to go on: no KB match, no kept claims, no (unrefuted) hunch.
    return ClassScore(
        score=0, band="refuted",
        rationale="no KB match, no kept claims, no unrefuted suspicion",
    )
