"""The confidence axis — separate from risk, and never touching it.

Risk and analytical confidence are two different facts, and collapsing them
loses the one that matters most when analysis goes wrong. A packed sample whose
dex never decompiled and whose detonation never ran is not *low risk*; it is
*unknown risk*, and a single number cannot say so. Reporting them separately is
what lets L6 print

    High (confidence: moderate — 39% of the app did not decompile;
                                 no dynamic analysis was performed)

instead of quietly emitting a lower number and calling it caution.

Read directly from ``analysis_gaps``, which the spine derives from every
evidence layer's coverage. That is the contract A1 established for exactly this
purpose.

**Two deliberate asymmetries:**

*``ghidra_unavailable`` only counts when the sample has native libraries.* 149
samples carry that gap, and for the ~88% with no ``.so`` at all it describes a
tool that was never needed. Penalising them would make the axis measure our
toolchain rather than our coverage of the sample.

*L3–L6 absence is not a gap.* They are consumer layers; the spine deliberately
excludes them from ``EVIDENCE_LAYERS``. "The classifier has not run" is a
pipeline state, not a blind spot in the evidence.
"""

from __future__ import annotations

from typing import Any

from L5.score import GateResult


def _has_native(doc: dict[str, Any]) -> bool:
    """Does this sample actually contain native code?

    Conservative: when coverage does not say, assume it does, so an unknown
    never silently waives a penalty.
    """
    l1 = doc.get("layers", {}).get("l1") or {}
    cov = l1.get("coverage") or {}
    for key in ("native_lib_count", "native_libs", "so_count"):
        if key in cov:
            try:
                return int(cov[key]) > 0
            except (TypeError, ValueError):
                return bool(cov[key])
    if cov.get("ghidra_attempted"):
        return True
    for f in doc.get("findings", []):
        if f.get("category") == "native_payload":
            return True
    return False


def confidence(doc: dict[str, Any], policy: Any, gates: list[GateResult],
               unsupported_weights: bool = False) -> tuple[float, str]:
    cfg = policy.raw.get("confidence") or {}
    penalties: dict[str, float] = cfg.get("penalties") or {}
    c = float(cfg.get("start", 1.0))
    has_native = _has_native(doc)

    for gap in doc.get("analysis_gaps", []) or []:
        if gap == "ghidra_unavailable" and not has_native:
            continue
        c -= float(penalties.get(gap, 0.0))

    indeterminate = sum(1 for g in gates if g.state == "indeterminate")
    c -= float(penalties.get("gate_indeterminate", 0.0)) * indeterminate

    if unsupported_weights:
        # Weights that cannot be supported by the benign denominator must not
        # be reported with high confidence, whatever the score says (T24).
        c = min(c, float(cfg.get("unsupported_weights_cap", 0.5)))

    c = max(0.0, min(1.0, c))
    return c, policy.confidence_band_of(c)


def explain(doc: dict[str, Any], policy: Any, gates: list[GateResult],
            unsupported_weights: bool = False) -> list[str]:
    """Human-readable reasons for the confidence value, in applied order."""
    cfg = policy.raw.get("confidence") or {}
    penalties: dict[str, float] = cfg.get("penalties") or {}
    reasons: list[str] = []
    has_native = _has_native(doc)

    for gap in doc.get("analysis_gaps", []) or []:
        if gap == "ghidra_unavailable" and not has_native:
            reasons.append(f"{gap}: no penalty (sample has no native libraries)")
            continue
        p = float(penalties.get(gap, 0.0))
        if p:
            reasons.append(f"{gap}: -{p:.2f}")

    n = sum(1 for g in gates if g.state == "indeterminate")
    if n:
        p = float(penalties.get("gate_indeterminate", 0.0))
        reasons.append(f"{n} gate(s) indeterminate: -{p * n:.2f}")

    if unsupported_weights:
        cap = float(cfg.get("unsupported_weights_cap", 0.5))
        reasons.append(f"weights unsupported: capped at {cap:.2f}")
    return reasons
