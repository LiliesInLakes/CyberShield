"""Translate a ScoreResult into the shapes ``spine.update_layer`` accepts.

Follows ``L0/promote.py``: plain dicts in and out, no imports from other
layers, testable without a spine on disk.

Four decisions here, each with a reason that cost something to learn:

**1. L5 never writes ``gaps``.** ``spine._recompute`` extends ``analysis_gaps``
from *every* layer's gaps, not just the evidence layers. If L5 pushed one, it
would land in ``analysis_gaps`` — which L5's own confidence axis reads — and
scoring would change its own confidence on the next run. L5 is a consumer
layer; its coverage holes belong in ``coverage``.

**2. Gate findings use ``category: "other"``, never a malware category.**
``counts.malware_category`` is the frozen 37% headline denominator (T15, B23).
Emitting an L5 gate finding as ``sms_intercept`` would inflate it, and the
number would silently stop meaning what every prior measurement meant. The
semantics live in ``detail.gate_category`` instead, where nothing aggregates them.

**3. One finding per *fired* gate, and none for the additive score.** The
additive score is a function of findings that already exist; minting a finding
for it would double-count in ``counts.by_category``.

**4. ``detail["spine_key"]`` is mandatory.** ``spine.finding_key`` falls back to
the free-text ``evidence`` string when it is absent, so the fingerprint would
churn every time the wording changed.
"""

from __future__ import annotations

from typing import Any


def _gate_evidence_ids(gate: Any) -> list[str]:
    out: list[str] = []
    for leg in gate.legs:
        out.extend(leg.get("evidence_ids") or [])
    return sorted(set(out))


def gate_findings(result: Any) -> list[dict[str, Any]]:
    """One spine finding per fired gate. Empty when none fired."""
    findings: list[dict[str, Any]] = []
    for gate in result.gates:
        if gate.state != "fired":
            continue
        ids = _gate_evidence_ids(gate)
        legs = ", ".join(
            f"{leg['leg']}={'+'.join(leg.get('evidence_ids') or ['-'])}"
            for leg in gate.legs
        )
        findings.append({
            "engine": "l5_gate",
            # Deliberately 'other' — see module docstring, decision 2.
            "category": "other",
            "severity": "critical" if gate.floor >= 85 else "high",
            "evidence": f"[{gate.gate_id}] smoking-gun combination satisfied ({legs})",
            "location": "derived",
            "mitre_techniques": [],
            "observation": "inferred",
            "detail": {
                "spine_key": f"l5_gate:{gate.gate_id}",
                "gate_id": gate.gate_id,
                "floor": gate.floor,
                "supporting_evidence_ids": ids,
                "legs": [dict(leg) for leg in gate.legs],
            },
        })
    return findings


def l5_summary(result: Any) -> dict[str, Any]:
    return {
        "score": result.score,
        "band": result.band,
        "confidence": round(result.confidence, 3),
        "confidence_band": result.confidence_band,
        "log_odds": round(result.log_odds, 4),
        "binding_reason": result.binding_reason,
        "ml_delta": result.ml_delta,
        "unsupported": result.unsupported,
        "gates": {g.gate_id: g.state for g in result.gates},
        "policy_version": result.policy_version,
        "weights_version": result.weights_version,
        "ruleset_version": result.ruleset_version,
    }


def l5_coverage(result: Any) -> dict[str, Any]:
    priced = [c for c in result.contributions if c.status == "priced"]
    return {
        "signals_seen": len(result.contributions),
        "signals_priced": len(priced),
        "signals_unpriced": sum(1 for c in result.contributions if c.status == "unpriced"),
        "signals_negligible": sum(1 for c in result.contributions if c.status == "negligible"),
        "signals_degenerate": sum(1 for c in result.contributions if c.status == "degenerate"),
        "gates_evaluated": sum(1 for g in result.gates if g.state != "disabled"),
        "gates_fired": sum(1 for g in result.gates if g.state == "fired"),
        "gates_indeterminate": sum(1 for g in result.gates if g.state == "indeterminate"),
        "weights_supported": not result.unsupported,
    }


def score_artifact(result: Any) -> dict[str, Any]:
    """The full audit trail, written to L5/artifacts/<sha>/score.json.

    Kept out of the spine: the per-signal contribution list is large and only
    an analyst reading one sample needs it, while the spine is read in bulk.
    """
    return {
        "sha256": result.sha256,
        "score": result.score,
        "band": result.band,
        "confidence": round(result.confidence, 3),
        "confidence_band": result.confidence_band,
        "log_odds": round(result.log_odds, 6),
        "binding_reason": result.binding_reason,
        "unsupported": result.unsupported,
        "policy_version": result.policy_version,
        "weights_version": result.weights_version,
        "ruleset_version": result.ruleset_version,
        "ml_delta": result.ml_delta,
        "contributions": [
            {
                "source": c.source,
                "evidence_ids": list(c.evidence_ids),
                "family": c.family,
                "weight_raw": round(c.weight_raw, 4),
                "discount": round(c.discount, 4),
                "weight_applied": round(c.weight_applied, 4),
                "support": c.support,
                "status": c.status,
            } for c in result.contributions
        ],
        "gates": [
            {
                "gate_id": g.gate_id, "state": g.state, "floor": g.floor,
                "legs": [dict(leg) for leg in g.legs],
                "missing_inputs": list(g.missing_inputs),
                "note": g.note,
            } for g in result.gates
        ],
    }
