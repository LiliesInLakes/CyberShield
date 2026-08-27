"""Mechanically check what the recommendation model proposed, before any of
it is shown to an analyst.

This is `L4/verify.py`'s anti-hallucination discipline applied to a new
domain. `L4/verify.py`'s worked example (a model confidently mis-decoding
`aHR0cDovLzE5Mi4xNjguMS4xMDAvZ2F0ZS5waHA=` as `.../get.php` when the true
value is `gate.php`) is about a claim on *this sample's bytes*; the
equivalent danger here is a model confidently recommending an action that
sounds plausible but points at evidence that does not exist — "escalate to
CERT-In because of the SMS-interception finding" when this particular sample
has no such finding, say. Fluent and wrong in exactly the same way, and
exactly as cheap to catch mechanically.

So every proposed action is checked against facts already on record before
it is kept:

======================= ==================================================
check                   what fails it
======================= ==================================================
action taxonomy         the action string is not one of the fixed `Action`
                        enum members -- the model may never invent a new
                        action, only select from the closed menu
finding citations       a cited finding `id` does not exist in this
                        sample's spine `findings[]`
KB citations            a cited SOP-KB entry `id` does not exist in the
                        loaded `sop_kb.json`
IOC grounding           `BLOCK_IOC` cites a value not present in this
                        sample's own extracted IOC list (`L6.export.
                        load_iocs`) -- the model may never invent an
                        indicator to recommend blocking
======================= ==================================================

An action with zero citations left after checking is dropped entirely, not
kept with an empty citation list -- an unsupported recommendation is not a
weaker recommendation, it is not a recommendation. A dropped action's reason
is recorded (never silently discarded) so the audit trail shows what the
model proposed and why it didn't survive, mirroring `L4/verify.py::Verdict`'s
`dropped` list.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from L6.recommend_actions import ACTION_VALUES


@dataclass
class VerifyResult:
    kept: list[dict[str, Any]] = field(default_factory=list)
    dropped: list[dict[str, Any]] = field(default_factory=list)

    @property
    def drop_count(self) -> int:
        return len(self.dropped)

    def drop(self, proposed: dict[str, Any], reason: str) -> None:
        self.dropped.append({"proposed": proposed, "reason": reason})


def verify_actions(
    proposed: list[dict[str, Any]],
    *,
    finding_ids: set[str],
    sop_kb_ids: set[str],
    ioc_values: set[str],
) -> VerifyResult:
    """Check each proposed action against facts already on record.

    ``proposed`` is the model's raw output: a list of
    ``{"action": str, "rationale": str, "citations": [{"kind": "finding"|"kb",
    "id": str}]}`` dicts. Nothing here calls a model or the network -- pure
    checks against three sets the caller has already computed from the
    sample's own spine/KB/IOC data.
    """
    result = VerifyResult()

    for item in proposed:
        if not isinstance(item, dict):
            result.drop(item, "malformed_entry")
            continue

        action = item.get("action")
        if action not in ACTION_VALUES:
            result.drop(item, "unknown_action")
            continue

        raw_citations = item.get("citations") or []
        kept_citations: list[dict[str, Any]] = []
        for cite in raw_citations:
            if not isinstance(cite, dict):
                continue
            kind = cite.get("kind")
            cid = cite.get("id")
            if kind == "finding" and cid in finding_ids:
                kept_citations.append(cite)
            elif kind == "kb" and cid in sop_kb_ids:
                kept_citations.append(cite)
            # else: silently excluded from kept_citations -- an unresolved
            # citation is not itself fatal to the action, only to itself,
            # unless it was the action's only citation (checked below).

        if not kept_citations:
            result.drop(item, "no_supporting_evidence")
            continue

        if action == "block_ioc":
            target = item.get("ioc_value") or item.get("value")
            if target not in ioc_values:
                result.drop(item, "ioc_not_extracted")
                continue

        result.kept.append({
            "action": action,
            "rationale": str(item.get("rationale") or "").strip(),
            "citations": kept_citations,
            **({"ioc_value": item.get("ioc_value")} if action == "block_ioc" else {}),
        })

    return result
