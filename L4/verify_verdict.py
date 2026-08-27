"""L4 — Verifier agent: adversarial check of the reasoning trail.

Third of three LLM calls (see ``decisions/plan_l4_agentic_verdicts.md`` §1,
§6, and the prior plan's Phase 3 precedent in
``decisions/plan_l4_rag_verdicts.md``). Reads the source code (to check the
trail is not inventing something absent), the reasoning trail's steps, and
the KB entries it cited — nothing else. Its job is adversarial: find a flaw.
Could there be a benign explanation for the kept claims? Is a citation a
stretch, or fabricated outright?

Mirrors ``L4/verify.py``'s discipline: the LLM's self-report is not trusted
on the one thing that can be settled mechanically. Every ``kb_id`` the trail
claims to cite is cross-referenced against ``kb_index`` in this module, not
by asking the model to grade its own citations. Any citation that does not
resolve is a **fabricated citation**, full stop, and pushes ``status``
toward ``"weakened"`` or ``"refuted"`` regardless of what the adversarial
pass concluded — the mechanical check overrides the model.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Literal, Protocol


class _ReasoningTrailLike(Protocol):
    steps: list[str]
    kb_ids_cited: list[str]


class _KBIndexLike(Protocol):
    """Shape this module assumes for a KB index.

    ``L4/knowledge/retriever.py`` (built by another agent in parallel) is not
    guaranteed to expose an index with this exact method yet — the plan (§6)
    only commits to a ``retrieve()`` function returning ``KBMatch`` objects.
    This module assumes whatever is passed as ``kb_index`` supports
    ``.get(kb_id) -> KBMatch | None`` (dict-like lookup, `None`/KeyError-free
    on a miss), which is the minimal shape needed to mechanically check a
    citation. If the real retriever module ends up exposing a plain dict of
    ``{kb_id: KBMatch}`` instead of an object with ``.get``, that still
    satisfies this contract (``dict.get`` matches it exactly) — reconcile at
    integration time if it does not.
    """

    def get(self, kb_id: str) -> Any: ...


SYSTEM = (
    "You are an adversarial reviewer checking a malware-analysis reasoning "
    "trail against the actual source code. Your job is to find a flaw: is "
    "there a benign explanation for the claims cited in the trail? Is a "
    "cited knowledge-base entry actually a good match, or a stretch? Do not "
    "be agreeable — a trail that holds up under genuine scrutiny is rare, "
    "not the default outcome. Answer only with JSON matching the requested "
    "schema."
)

SCHEMA_HINT = """Return ONLY this JSON object:
{
  "status": "confirmed|weakened|refuted",
  "counter_argument": "<the strongest flaw you found, or why none was found>",
  "confidence": "high|medium|low"
}
"status" meanings:
- "confirmed": the trail's reasoning holds up; no benign explanation covers the claims as well.
- "weakened": the trail is directionally right but overstates certainty, or a citation is a stretch.
- "refuted": a benign explanation fits at least as well, or the reasoning does not follow from the claims."""


@dataclass
class VerifierVerdict:
    status: Literal["confirmed", "weakened", "refuted"]
    counter_argument: str
    fabricated_citations: list[str]
    confidence: Literal["high", "medium", "low"] = "medium"


def _mechanically_check_citations(
    kb_ids_cited: list[str], kb_index: Any
) -> list[str]:
    """Cross-reference every cited kb_id against kb_index. Never ask the LLM."""
    fabricated: list[str] = []
    for kb_id in kb_ids_cited or []:
        try:
            match = kb_index.get(kb_id)
        except Exception:  # noqa: BLE001 — a broken index is a miss, not a crash
            match = None
        if match is None:
            fabricated.append(kb_id)
    return fabricated


def _format_cited_kb_entries(kb_ids_cited: list[str], kb_index: Any) -> str:
    lines: list[str] = []
    for kb_id in kb_ids_cited or []:
        try:
            match = kb_index.get(kb_id)
        except Exception:  # noqa: BLE001
            match = None
        if match is None:
            lines.append(f"- kb_id={kb_id!r}: NOT FOUND in the KB index")
            continue
        title = getattr(match, "title", None) or (
            match.get("title") if isinstance(match, dict) else None)
        lines.append(f"- kb_id={kb_id!r} title={title!r}")
    return "\n".join(lines) if lines else "(no KB entries were cited)"


def verify_trail(
    trail: _ReasoningTrailLike, source: str, kb_index: Any, provider: Any
) -> VerifierVerdict:
    """Adversarially check a reasoning trail against source + cited KB entries.

    ``provider`` follows the ``L4/provider.py`` ``Provider`` protocol, same
    call pattern as ``L4/deobfuscate.py``'s ``explain_class`` and
    ``L4/reasoning_trail.py``'s ``build_trail``.

    ``fabricated_citations`` is computed mechanically here, not by the LLM:
    every kb_id in ``trail.kb_ids_cited`` is looked up in ``kb_index``, and
    any that fail to resolve are fabricated regardless of what the LLM's
    adversarial pass says about ``status``. If any citation is fabricated,
    the mechanically-checked status can only move toward ``"weakened"``
    (some fabricated, some real) or ``"refuted"`` (all cited citations
    fabricated) — it is never allowed to end up better than what the LLM
    itself proposed for the same reason ``verify.py`` never lets a claim
    "pass" once its check fails.
    """
    fabricated = _mechanically_check_citations(trail.kb_ids_cited, kb_index)

    prompt = (
        f"{SCHEMA_HINT}\n\n"
        f"Source code:\n```java\n{source}\n```\n\n"
        f"Reasoning trail steps:\n" + "\n".join(f"- {s}" for s in trail.steps) + "\n\n"
        f"KB entries the trail cited:\n{_format_cited_kb_entries(trail.kb_ids_cited, kb_index)}"
    )
    completion = provider.complete(
        [{"role": "system", "content": SYSTEM},
         {"role": "user", "content": prompt}],
        # 800 was sized for a non-reasoning model's direct JSON answer.
        # AICREDITS_REASONING_MODEL (z-ai/glm-5.3-flash as of 2026-08-27) is
        # a reasoning model that spends tokens on an internal chain-of-thought
        # before it ever emits the JSON answer -- 800 wasn't enough even for
        # a short smoke-test prompt (finish_reason="length", empty content),
        # and this call's prompt (full source + trail + KB entries) is larger.
        max_tokens=2500, temperature=0.0, json_object=True,
    )
    try:
        parsed = completion.json()
    except Exception:  # noqa: BLE001
        m = re.search(r"\{.*\}", completion.text, re.S)
        parsed = json.loads(m.group()) if m else {}

    status = parsed.get("status")
    if status not in ("confirmed", "weakened", "refuted"):
        status = "weakened"
    counter_argument = str(parsed.get("counter_argument") or "").strip()
    confidence = parsed.get("confidence")
    if confidence not in ("high", "medium", "low"):
        confidence = "medium"

    if fabricated:
        n_cited = len(trail.kb_ids_cited or [])
        all_fabricated = n_cited > 0 and len(fabricated) == n_cited
        # Mechanical override: a fabricated citation cannot leave status better
        # than the LLM's own verdict allowed, and it can only push status down.
        forced = "refuted" if all_fabricated else "weakened"
        rank = {"confirmed": 0, "weakened": 1, "refuted": 2}
        if rank[forced] > rank[status]:
            status = forced
        note = (
            f"Mechanical check found {len(fabricated)} fabricated citation(s) "
            f"not present in the KB index: {fabricated}."
        )
        counter_argument = f"{counter_argument} {note}".strip() if counter_argument else note
        # A trail that cites sources that don't exist is not evidence of a
        # careful reviewer's high confidence in whatever remains.
        if confidence == "high":
            confidence = "medium"

    return VerifierVerdict(
        status=status,
        counter_argument=counter_argument,
        fabricated_citations=fabricated,
        confidence=confidence,
    )
