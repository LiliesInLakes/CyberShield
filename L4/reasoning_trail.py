"""L4 — Reasoning-trail agent: build a cited evidence chain from kept claims.

Second of three LLM calls in the agentic-verdicts pipeline (see
``decisions/plan_l4_agentic_verdicts.md`` §1, §6). Its whole reason for
existing as a separate call from the Analyst is the input restriction: it
reads *only* the claims that already survived ``L4/verify.py`` — never a
claim ``verify.py`` dropped, never raw source. That keeps it a cheap,
narrowly-scoped call that can reason about what is already established, not
invent new claims from the code. The Analyst extracts; this agent explains
why the extraction supports (or does not support) a verdict, citing which
retrieved KB entry backs each step, or saying "no KB citation" when a step
has no grounding — a mechanical-sounding requirement that is enforced with a
simple parse of the model's own JSON, not trusted by prose alone.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Protocol


class _KBMatchLike(Protocol):
    """Shape this module assumes for a KB match.

    ``L4/knowledge/retriever.py`` is being built by another agent in parallel
    against the same interface contract (plan §6): ``KBMatch(kb_id, title,
    similarity, mitre_techniques)``. This module only ever reads ``kb_id`` and
    ``title`` plus a best-effort description-like field, so it is typed loosely
    here rather than importing the real dataclass and risking an import-order
    collision before that file exists.
    """

    kb_id: str
    title: str


SYSTEM = (
    "You are building a cited reasoning chain for a malware analysis report. "
    "You are given only claims that have already been mechanically verified "
    "against the sample, plus threat-intelligence knowledge-base entries "
    "retrieved for this class. You did not see the source code and must not "
    "invent facts beyond the claims given. For every step in your chain, "
    "either cite the kb_id of the knowledge-base entry that backs it, or "
    "state exactly \"no KB citation\" if the step has no grounding in the "
    "provided KB matches. Answer only with JSON matching the requested schema."
)

SCHEMA_HINT = """Return ONLY this JSON object:
{
  "steps": [
    {"text": "<one step of reasoning>", "kb_id": "<kb_id from the provided matches, or null>"}
  ]
}
Each step's "kb_id" must be either exactly one of the provided KB match ids, or null.
If you cite no KB match anywhere in a step's reasoning, set "kb_id" to null."""


@dataclass
class ReasoningTrail:
    steps: list[str] = field(default_factory=list)          # each cites a kb_id or "no KB citation"
    kb_ids_cited: list[str] = field(default_factory=list)


def _format_kept_claims(kept_claims: dict) -> str:
    """Render the analyst's kept claims for the prompt. Assumes verify.py's shape:
    decoded_strings/renamed/api_calls/iocs (checkable) plus any unverified narrative
    fields the analyst reported. Only kept_claims is passed in here — the caller is
    responsible for having already dropped anything verify.py rejected."""
    return json.dumps(kept_claims, indent=2, default=str)


def _format_kb_matches(kb_matches: list) -> str:
    lines: list[str] = []
    for m in kb_matches or []:
        kb_id = getattr(m, "kb_id", None) or (m.get("kb_id") if isinstance(m, dict) else None)
        title = getattr(m, "title", None) or (m.get("title") if isinstance(m, dict) else None)
        # Description-like field: try a few plausible names since the real
        # KBMatch dataclass (plan §6) is being built in parallel and may or
        # may not carry one under any of these names.
        desc = None
        for attr in ("description", "summary", "text", "content"):
            desc = getattr(m, attr, None) or (m.get(attr) if isinstance(m, dict) else None)
            if desc:
                break
        line = f"- kb_id={kb_id!r} title={title!r}"
        if desc:
            line += f" description={desc!r}"
        lines.append(line)
    return "\n".join(lines) if lines else "(no KB matches retrieved — treat every step as ungrounded)"


def _valid_kb_ids(kb_matches: list) -> set[str]:
    ids: set[str] = set()
    for m in kb_matches or []:
        kb_id = getattr(m, "kb_id", None) or (m.get("kb_id") if isinstance(m, dict) else None)
        if kb_id:
            ids.add(kb_id)
    return ids


def build_trail(kept_claims: dict, kb_matches: list, provider: Any) -> ReasoningTrail:
    """Build a step-by-step, per-step-cited reasoning chain.

    ``provider`` follows the ``L4/provider.py`` ``Provider`` protocol
    (``.complete(messages, ..., json_object=True) -> Completion``), same
    pattern as ``L4/deobfuscate.py``'s ``explain_class``.

    Reads ONLY ``kept_claims`` (post mechanical-verify) and ``kb_matches``
    (retrieved KB entries) — never raw source. A step's kb_id is only kept
    as a citation if it names a kb_id actually present in ``kb_matches``;
    otherwise the step is recorded as uncited ("no KB citation"), because a
    citation to a KB entry this agent was never shown is exactly the kind of
    fabrication ``L4/verify_verdict.py`` exists to also mechanically check —
    this is a first, cheap line of defense against that at the point where
    it originates.
    """
    valid_ids = _valid_kb_ids(kb_matches)

    prompt = (
        f"{SCHEMA_HINT}\n\n"
        f"Mechanically-verified kept claims:\n{_format_kept_claims(kept_claims)}\n\n"
        f"Retrieved KB matches:\n{_format_kb_matches(kb_matches)}"
    )
    completion = provider.complete(
        [{"role": "system", "content": SYSTEM},
         {"role": "user", "content": prompt}],
        max_tokens=1200, temperature=0.0, json_object=True,
    )
    try:
        parsed = completion.json()
    except Exception:  # noqa: BLE001
        m = re.search(r"\{.*\}", completion.text, re.S)
        parsed = json.loads(m.group()) if m else {}

    steps: list[str] = []
    kb_ids_cited: list[str] = []
    for step in parsed.get("steps") or []:
        if not isinstance(step, dict):
            continue
        text = str(step.get("text") or "").strip()
        if not text:
            continue
        kb_id = step.get("kb_id")
        if isinstance(kb_id, str) and kb_id in valid_ids:
            steps.append(f"[{kb_id}] {text}")
            if kb_id not in kb_ids_cited:
                kb_ids_cited.append(kb_id)
        else:
            # Either the model said null/omitted it, or it named a kb_id that
            # was never offered to it — both render as uncited. A fabricated
            # id is not smuggled through as a citation just because a string
            # happened to be present.
            steps.append(f"no KB citation: {text}")

    return ReasoningTrail(steps=steps, kb_ids_cited=kb_ids_cited)
