"""Translate an L2 report into the shapes ``spine.update_layer`` accepts.

Follows ``L0/promote.py``: plain dicts in and out, no imports from other layers,
testable without a sandbox.

L2 has been the only evidence layer never wired to the spine. `l2_engine.py`
has parsed telemetry into `L1Finding(observation=OBSERVED)` since it was
written, but nothing carried those findings into `artifacts/<sha>/evidence.json`,
so every one of the 1,248 spines still reads `l2: {"status": "not_attempted"}`.
This is that bridge. It is worth having even while the AVD refuses to boot
(T14), because it turns "L2 exists but is disconnected" into "L2 ran and found
nothing yet", which are different facts and only one of them is honest.

Three decisions, each mirroring a lesson from the layers above:

**Every finding gets a ``detail["spine_key"]``.** L2 findings are not YARA
findings, so ``spine.finding_key`` would otherwise fall back to the free-text
``evidence`` string and the fingerprint would churn whenever wording changed
(the same trap `L0/promote.py:_spine_key` exists to avoid).

**``observation`` stays ``observed``.** That field is the whole point of L2:
`inferred` means a static rule matched, `observed` means the behaviour actually
happened during detonation. Flattening it would discard the only thing dynamic
analysis adds.

**A detonation that ran and saw nothing is not the same as one that never ran.**
`l2_status_for` returns COMPLETE with zero findings in the first case and
SKIPPED in the second, so `analysis_gaps` keeps carrying
`detonation_not_attempted` only when it is true. L5's confidence axis reads that
directly.
"""

from __future__ import annotations

from typing import Any

# Categories L2 can legitimately observe. Anything else is recorded but is not
# allowed to claim a malware category it did not actually witness.
OBSERVABLE = frozenset({
    "sms_intercept", "overlay_attack", "accessibility_abuse", "c2_communication",
    "data_exfiltration", "ransomware", "clipboard_hijack", "notification_abuse",
    "screen_capture", "native_payload", "messaging_c2", "privilege_escalation",
    "evasion", "other",
})


def _spine_key(finding: dict[str, Any]) -> str:
    """Stable identity for one observed behaviour.

    Keyed on what was seen and where, never on the prose describing it.
    """
    detail = finding.get("detail") or {}
    for candidate in ("hook", "api", "endpoint", "event", "artifact"):
        value = detail.get(candidate)
        if value:
            return f"{finding.get('category', 'other')}:{candidate}:{value}"
    location = finding.get("location") or ""
    return f"{finding.get('category', 'other')}:{location or finding.get('evidence', '')[:80]}"


def l2_findings(report: dict[str, Any]) -> list[dict[str, Any]]:
    """Spine findings from an L2 report dict (``L1Report.to_dict()``)."""
    out: list[dict[str, Any]] = []
    for f in report.get("findings", []) or []:
        category = f.get("category", "other")
        detail = dict(f.get("detail") or {})
        detail.setdefault("spine_key", _spine_key(f))
        detail.setdefault("l2_engine", report.get("engine", "l2_sandbox"))
        out.append({
            "engine": f.get("engine") or "l2_sandbox",
            "category": category if category in OBSERVABLE else "other",
            "severity": f.get("severity", "medium"),
            "evidence": f.get("evidence", ""),
            "location": f.get("location", "runtime"),
            "mitre_techniques": list(f.get("mitre_techniques") or []),
            # The distinguishing claim of this layer: it happened, we watched.
            "observation": f.get("observation", "observed"),
            "detail": detail,
        })
    return out


def l2_summary(report: dict[str, Any]) -> dict[str, Any]:
    s = report.get("summary") or {}
    return {
        "engine": report.get("engine", "l2_sandbox"),
        "finding_count": s.get("finding_count", len(report.get("findings") or [])),
        "categories": s.get("categories", []),
        "severity_counts": s.get("severity_counts", {}),
        "sandbox_type": s.get("sandbox_type", "unknown"),
        "detonation_s": s.get("detonation_s", 0),
        "evasion_bypassed": s.get("evasion_bypassed", 0),
        "total_http_requests": s.get("total_http_requests", 0),
        "c2_count": s.get("c2_count", 0),
        "sandbox_confidence": s.get("confidence", "unknown"),
    }


def l2_coverage(report: dict[str, Any]) -> dict[str, Any]:
    s = report.get("summary") or {}
    return {
        "detonated": bool(s.get("detonation_s", 0)),
        "detonation_s": s.get("detonation_s", 0),
        "frida_attached": bool(s.get("finding_count", 0)) or bool(s.get("evasion_bypassed")),
        "network_captured": bool(s.get("total_http_requests", 0)),
        "observed_findings": s.get("finding_count", 0),
    }


def l2_gaps(report: dict[str, Any]) -> list[str]:
    """Coverage holes L5's confidence axis should see.

    L2 *is* an evidence layer, so unlike L3–L6 it is right for it to contribute
    gaps — a detonation that produced no network capture genuinely leaves a
    hole in what we can claim.
    """
    s = report.get("summary") or {}
    gaps: list[str] = []
    if not s.get("detonation_s", 0):
        gaps.append("detonation_incomplete")
    if not s.get("total_http_requests", 0):
        gaps.append("network_not_captured")
    if s.get("confidence") in ("low", "unknown"):
        gaps.append("sandbox_low_confidence")
    return gaps


def l2_status_for(report: dict[str, Any]) -> str:
    """`complete` | `partial` | `skipped`, as a plain string for LayerStatus.

    A detonation that ran and observed nothing is COMPLETE with zero findings.
    One that never ran is SKIPPED. Collapsing those two would let a failed
    sandbox read as a clean sample — the same error the ternary gates in
    ``L5/gates.py`` exist to avoid.
    """
    s = report.get("summary") or {}
    if not s.get("detonation_s", 0) and not (report.get("findings") or []):
        return "skipped"
    return "partial" if l2_gaps(report) else "complete"
