"""L6 post-verdict recommendation — "given the finished score, what should
the analyst actually do next?"

    source source_env.sh
    $SENTINEL_PYTHON L6/recommend.py <sha256>   # --budget defaults to $0.25

**Why this exists.** L0-L5 produce a score, a band, and an evidence-cited
audit trail — but no answer to the question a real analyst actually asks
next. This module answers it, using the exact discipline the rest of this
pipeline already established for using an LLM safely: the model *proposes*,
in prose, grounded in retrieved incident-response guidance; mechanical code
(`L6/recommend_verify.py`) *disposes* — anything not backed by a real,
allowed action and a real citation is dropped before an analyst ever sees
it. See that module's docstring for the exact checks, and
`docs/L6_RECOMMEND_EXPLAINER.md` for the full design writeup including where
the SOP knowledge base's content actually came from.

**Why not a trained ML model.** A supervised classifier here would need
labelled `(report -> correct action)` pairs from real, analyst-adjudicated
incidents; none exist for this project and manufacturing them credibly is
out of scope. This module instead reuses L4's already-proven shape (RAG +
mechanical verification) rather than building a second, parallel ML
pipeline for the same class of problem.

**Two different rigor levels, deliberately.** The *priority tier*
(`priority_tier()` below) is a pure, deterministic function of the already-
computed score — no model call, no chance of the AI talking itself out of an
urgent case. The *specific actions* are the model's job, but constrained to
a closed taxonomy (`L6/recommend_actions.py`) it can only select from, never
invent, and every selection must cite something real.

**Contributes zero points, same as L4.** This module runs strictly after L5
and only ever reads a `ScoreResult`; there is no path back into the score.
Its output is advisory guidance for a human, not evidence.

**Never enters an export.** `L6/export.py`'s STIX/CSV/YARA/Sigma feeds are
machine-consumed and carry a standing rule that nothing an LLM produced may
enter them. This module's output is deliberately excluded from that path —
see the note added to `L6/export.py`'s own docstring.
"""

from __future__ import annotations

import json
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
for _p in (str(REPO_ROOT), str(REPO_ROOT / "L1")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import spine  # noqa: E402
from L4.provider import CostLedger, Provider, get_provider  # noqa: E402
from L4.knowledge.retriever import _KBIndex  # noqa: E402
from L5.score import Policy, ScoreResult, load_policy, score_spine  # noqa: E402
from L6.export import load_iocs  # noqa: E402
from L6.recommend_actions import ACTION_DESCRIPTIONS, ACTION_VALUES  # noqa: E402
from L6.recommend_verify import verify_actions  # noqa: E402

SOP_KB_PATH = Path(__file__).resolve().parent / "knowledge" / "sop_kb.json"

# --------------------------------------------------------------------------
# Priority tier — pure function, no LLM, no network. Mirrors
# L4/scorer.py::score_class's determinism: the one part of this feature
# that must never be "creative" is decided by the score alone.
# --------------------------------------------------------------------------

_TIER_IMMEDIATE = "IMMEDIATE"
_TIER_URGENT_24H = "URGENT_24H"
_TIER_STANDARD = "STANDARD"
_TIER_MONITOR = "MONITOR"


def priority_tier(score: ScoreResult) -> str:
    """Deterministic mapping from (band, unsupported) to an urgency tier.

    `unsupported` overrides everything else: a statistically-unsupported
    score (see L5/score.py's own `unsupported` stamp and CLAUDE.md's T24)
    cannot justify urgent action regardless of what number it produced --
    the same "refuse to overclaim" discipline the rest of L5 already
    applies, extended here to what happens downstream of the score.
    """
    if score.unsupported:
        return _TIER_MONITOR
    if score.band == "Critical":
        return _TIER_IMMEDIATE
    if score.band == "High":
        return _TIER_URGENT_24H
    if score.band == "Medium":
        return _TIER_STANDARD
    return _TIER_MONITOR  # Low, Informational


# --------------------------------------------------------------------------
# Result shapes
# --------------------------------------------------------------------------

@dataclass
class RecommendedAction:
    action: str
    rationale: str
    citations: list[dict[str, Any]] = field(default_factory=list)
    ioc_value: str | None = None


@dataclass
class Recommendation:
    sha256: str
    priority_tier: str
    summary: str
    actions: list[RecommendedAction] = field(default_factory=list)
    dropped: list[dict[str, Any]] = field(default_factory=list)
    cost_usd: float = 0.0
    calls: int = 0
    model: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        return d


# --------------------------------------------------------------------------
# Prompting
# --------------------------------------------------------------------------

_SYSTEM = """You are a security analyst assistant. You are given a finished, \
already-scored malware-analysis report for one Android APK. You do not \
re-analyse the app -- everything about what it does has already been \
decided by upstream layers. Your only job is to recommend what a human \
analyst should do NEXT, grounded in the retrieved incident-response \
guidance you are given.

Rules, all strictly enforced by code after you respond (violating them \
means your suggestion is silently discarded, not corrected):
1. Every action you recommend MUST be one of the fixed action ids listed \
below -- never invent a new action.
2. Every action MUST cite at least one real finding id from this report's \
findings list, or a real SOP-KB entry id from the retrieved guidance you \
were shown. Never cite a finding id or KB id that was not shown to you.
3. If you recommend "block_ioc", you must name the exact IOC value \
(ioc_value field) and it must be one of the IOCs listed in this report -- \
never invent an indicator.
4. Write a short (2-4 sentence) plain-language "summary" of the situation \
for a non-technical reader, stating only what the report's findings and \
score actually say -- do not speculate beyond the evidence given.

Reply with STRICT JSON only, no prose, no markdown fences:
{"summary": "<string>",
 "actions": [{"action": "<action id>", "rationale": "<string>",
              "citations": [{"kind": "finding"|"kb", "id": "<string>"}],
              "ioc_value": "<string, only for block_ioc>"}]}"""


def _build_prompt(doc: dict[str, Any], score: ScoreResult,
                  kb_matches: list[Any], iocs: list[dict[str, Any]]) -> str:
    findings_brief = [
        {"id": f.get("id"), "category": f.get("category"),
         "severity": f.get("severity"), "evidence": f.get("evidence")}
        for f in doc.get("findings", [])
    ]
    gates_brief = [
        {"gate_id": g.gate_id, "state": g.state} for g in score.gates
    ] if score.gates else []
    kb_brief = [
        {"id": m.kb_id, "title": m.title} for m in kb_matches
    ]
    ioc_values = [i.get("value") for i in iocs if i.get("value")]

    action_menu = "\n".join(
        f"- {aid}: {desc}" for aid, desc in ACTION_DESCRIPTIONS.items()
    )

    return (
        f"Action menu (use these ids exactly):\n{action_menu}\n\n"
        f"Report:\n"
        f"  score: {score.score}/100 ({score.band})\n"
        f"  confidence: {score.confidence:.2f} ({score.confidence_band})\n"
        f"  unsupported: {score.unsupported}\n"
        f"  gates: {json.dumps(gates_brief)}\n"
        f"  findings: {json.dumps(findings_brief)}\n"
        f"  extracted IOCs (only these may be cited for block_ioc): "
        f"{json.dumps(ioc_values)}\n\n"
        f"Retrieved SOP/incident-response guidance (only these KB ids may "
        f"be cited):\n{json.dumps(kb_brief)}"
    )


def _retrieval_query(doc: dict[str, Any], score: ScoreResult) -> str:
    """Text to retrieve SOP guidance against -- built from the report's own
    category/technique vocabulary so retrieval grounds on what was actually
    found, not a generic query."""
    parts = [score.band]
    for f in doc.get("findings", []):
        parts.append(str(f.get("category", "")))
        parts.extend(f.get("mitre_techniques", []) or [])
    return " ".join(p for p in parts if p)


# --------------------------------------------------------------------------
# Orchestration
# --------------------------------------------------------------------------

def recommend(doc: dict[str, Any], score: ScoreResult, provider: Provider,
              *, top_k: int = 6) -> Recommendation:
    """Run the full propose -> mechanically-verify -> deterministic-override
    chain for one already-scored sample.

    ``provider`` is the single model tier used here -- unlike L4's
    analyst/verifier split, this step is one small-context call per sample
    (not per-class), so the cost case for a second reasoning-tier pass is
    weaker; kept as a single call for now, revisit if the real end-to-end
    cost measurement (see this module's CLI) shows citation fabrication is
    a real problem the way it was for L4's verify_trail.
    """
    tier = priority_tier(score)

    # A dedicated, locally-owned _KBIndex instance -- deliberately NOT
    # L4.knowledge.retriever's module-level retrieve()/reload_index(),
    # which share one process-wide global (_INDEX). Calling reload_index()
    # here would silently repoint L4's own malware-detection retrieval at
    # this SOP KB for the rest of the process's lifetime -- a real hazard
    # once this runs inside the long-lived FastAPI server alongside L4.
    # _KBIndex itself has no such global state, so owning one locally is safe.
    sop_index = _KBIndex(SOP_KB_PATH)
    query = _retrieval_query(doc, score)
    kb_matches = sop_index.search(query, top_k=top_k, min_sim=0.15)

    iocs = load_iocs(doc)
    ioc_values = {i.get("value") for i in iocs if i.get("value")}
    finding_ids = {f.get("id") for f in doc.get("findings", []) if f.get("id")}
    sop_kb_ids = {m.kb_id for m in kb_matches}

    prompt = _build_prompt(doc, score, kb_matches, iocs)
    completion = provider.complete(
        [{"role": "system", "content": _SYSTEM},
         {"role": "user", "content": prompt}],
        max_tokens=1500, temperature=0.0, json_object=True,
    )

    try:
        parsed = completion.json()
    except Exception:  # noqa: BLE001
        import re as _re
        m = _re.search(r"\{.*\}", completion.text, _re.S)
        parsed = json.loads(m.group()) if m else {}

    summary = str(parsed.get("summary") or "").strip()
    proposed = parsed.get("actions") or []
    if not isinstance(proposed, list):
        proposed = []

    verified = verify_actions(
        proposed, finding_ids=finding_ids, sop_kb_ids=sop_kb_ids,
        ioc_values=ioc_values,
    )

    kept_actions = [
        RecommendedAction(action=a["action"], rationale=a["rationale"],
                          citations=a["citations"],
                          ioc_value=a.get("ioc_value"))
        for a in verified.kept
    ]

    # Deterministic override 1: an IMMEDIATE-tier report must recommend
    # escalation even if the model didn't propose it -- the score's own
    # urgency is not something a less-alarmed model gets to silently
    # suppress.
    has_escalate = any(a.action == "escalate_cert_in" for a in kept_actions)
    if tier == _TIER_IMMEDIATE and not has_escalate:
        kept_actions.append(RecommendedAction(
            action="escalate_cert_in",
            rationale=(
                "Deterministically added: this report's priority tier is "
                "IMMEDIATE (band=Critical, statistically supported), which "
                "on its own meets the bar for CERT-In escalation regardless "
                "of what the model proposed."
            ),
            citations=[{"kind": "deterministic", "id": "priority_tier"}],
        ))

    # Deterministic override 2: an unsupported score cannot justify acting
    # on anything stronger than monitoring -- mirrors L5's own refusal to
    # let unsupported weights arm a gate.
    if score.unsupported:
        kept_actions = [
            RecommendedAction(
                action="insufficient_evidence",
                rationale=(
                    "Deterministically forced: this sample's score is "
                    "statistically unsupported (see L5's `unsupported` "
                    "stamp) -- acting on an unsupported score risks a false "
                    "positive/negative the scoring system itself flagged "
                    "as unreliable."
                ),
                citations=[{"kind": "deterministic", "id": "unsupported"}],
            )
        ]

    return Recommendation(
        sha256=doc.get("sha256", ""),
        priority_tier=tier,
        summary=summary,
        actions=kept_actions,
        dropped=verified.dropped,
        cost_usd=completion.cost_usd,
        calls=1,
        model=completion.model,
    )


def write_layer(rec: Recommendation) -> Path:
    out = REPO_ROOT / "L6" / "artifacts" / rec.sha256 / "recommendation.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(rec.to_dict(), indent=2))
    # "l6" is spine.py's reserved layer slot for L6 -- unused until now
    # (report.py/export.py only ever read the spine, never write it), so
    # this is the first thing to actually populate it.
    spine.update_layer(
        rec.sha256, "l6",
        status=spine.LayerStatus.COMPLETE,
        findings=[],  # advisory output, mints no evidence -- see L4's precedent
        summary={"priority_tier": rec.priority_tier,
                 "action_count": len(rec.actions),
                 "dropped_count": len(rec.dropped),
                 "cost_usd": rec.cost_usd},
        gaps=None,
        artifact=out,
    )
    return out


def main(argv: list[str] | None = None) -> int:
    import argparse

    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("sha256")
    ap.add_argument("--budget", type=float, default=0.25,
                    help="USD cap for this run. Default $0.25 -- this step "
                         "is one small-context call per sample (not "
                         "per-class like L4), measured live against a real "
                         "sample (XBot) at $0.037/run on the cheap-tier "
                         "model -- ~7x headroom over that measurement, not "
                         "a guess. See docs/L6_RECOMMEND_EXPLAINER.md.")
    ap.add_argument("--provider", default="aicredits")
    ap.add_argument("--no-write", action="store_true")
    args = ap.parse_args(argv)

    doc = spine.load_spine(args.sha256)
    if not spine.spine_path(args.sha256).is_file():
        print(f"no spine for {args.sha256}", file=sys.stderr)
        return 1

    policy = load_policy()
    score = score_spine(doc, policy, include_ai=True)

    ledger = CostLedger(cap_usd=args.budget)
    provider = get_provider(args.provider, ledger=ledger)

    rec = recommend(doc, score, provider)

    if not args.no_write:
        write_layer(rec)

    print(f"priority_tier={rec.priority_tier} actions={len(rec.actions)} "
          f"dropped={len(rec.dropped)} cost=${rec.cost_usd:.6f} "
          f"model={rec.model}")
    print(f"summary: {rec.summary}")
    for a in rec.actions:
        cites = ", ".join(f"{c['kind']}:{c['id']}" for c in a.citations)
        ioc_tag = f" ioc={a.ioc_value}" if a.ioc_value else ""
        print(f"  [{a.action}]{ioc_tag} {a.rationale}")
        print(f"    citations: {cites}")
    for d in rec.dropped:
        print(f"  ! dropped ({d['reason']}): {d['proposed']}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
