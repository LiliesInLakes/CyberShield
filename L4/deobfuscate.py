"""L4 — verified deobfuscation of the classes that already look interesting.

    source source_env.sh
    $SENTINEL_PYTHON L4/deobfuscate.py <sha256> --src <jadx_src_dir> --explain

**Six to eight calls per APK, not a hierarchical summarisation of the whole
app.** Summarising every class of a decompiled Android application costs
30–40 minutes of model time and mostly describes framework and SDK code that no
analyst would read. L1 has already located the classes worth explaining — they
are the ``location`` fields on its findings — so this layer explains those and
stops.

**Every checkable claim is checked before it is kept** (``L4/verify.py``). The
model's job here is to explain code, not to establish facts: decoded strings
are re-decoded, renamed identifiers must actually occur, claimed APIs must
actually be called, and an indicator that the deterministic layers did not
extract is discarded outright.

**L4 contributes zero points to the score.** There is no return path from this
module into L5. It produces explanation and, occasionally, a decoded string
that makes an existing finding legible — never a number.
"""

from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

REPO_ROOT = Path(__file__).resolve().parent.parent
for _p in (str(REPO_ROOT), str(REPO_ROOT / "L1")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import spine  # noqa: E402
from L4.provider import Completion, CostLedger, Provider, get_provider  # noqa: E402
from L4.verify import Verdict, verify  # noqa: E402
from L4.knowledge.retriever import KBMatch, retrieve  # noqa: E402
from L4.network_correlation import correlate  # noqa: E402
from L4.reasoning_trail import ReasoningTrail, build_trail  # noqa: E402
from L4.verify_verdict import VerifierVerdict, verify_trail  # noqa: E402
from L4.scorer import ClassScore, score_class  # noqa: E402

MAX_CLASSES = 8
MAX_CHARS_PER_CLASS = 12_000
_STRING_LITERAL_RE = re.compile(r'"((?:[^"\\]|\\.){4,200})"')
_SKILL_MD = REPO_ROOT / "L4" / "SKILL.md"


def _extract_skill_block(markdown: str, name: str) -> str:
    """Pull one ``<!-- BEGIN:NAME -->...<!-- END:NAME -->`` block from SKILL.md.

    Per the loader contract at the bottom of ``L4/SKILL.md`` — the spec file
    is data a prompt-builder reads, not prose duplicated in code.
    """
    m = re.search(rf"<!-- BEGIN:{name} -->\n(.*?)\n<!-- END:{name} -->",
                  markdown, re.S)
    if not m:
        raise ValueError(f"L4/SKILL.md missing block: {name}")
    return m.group(1).strip()


def _load_skill() -> tuple[str, str, str]:
    """Returns (system_message, schema_block, role_only) built from SKILL.md.

    Falls back to a minimal inline spec if SKILL.md is absent (e.g. a stripped
    deployment) rather than crashing L4 entirely — degraded, not silent: the
    fallback lacks the extended schema fields and negative instructions.
    """
    if not _SKILL_MD.is_file():
        role = ("You are a malware analyst reading decompiled Android code. "
                "Never guess: if you cannot determine something, omit it.")
        schema = SCHEMA_HINT_FALLBACK
        return role, schema, role
    text = _SKILL_MD.read_text(errors="replace")
    role = _extract_skill_block(text, "ROLE")
    schema = _extract_skill_block(text, "SCHEMA")
    negatives = _extract_skill_block(text, "NEGATIVE_INSTRUCTIONS")
    return f"{role}\n\n{negatives}", schema, role


SCHEMA_HINT_FALLBACK = """Return ONLY this JSON object:
{
  "purpose": "one sentence: what this class does",
  "renamed": {"<obfuscated identifier present in the code>": "<meaningful name>"},
  "decoded_strings": {"<encoded literal exactly as it appears>": "<decoded value>"},
  "api_calls": ["<security-relevant API actually called here>"],
  "iocs": ["<network indicator literally present in this code>"],
  "behaviours": ["<short tag, e.g. sms_interception>"],
  "confidence": "high|medium|low"
}"""

SYSTEM, SCHEMA_HINT, _ROLE_ONLY = _load_skill()


@dataclass
class ClassExplanation:
    location: str
    kept: dict[str, Any]
    unverified: dict[str, Any]
    dropped: list[dict[str, Any]]
    model: str
    cost_usd: float
    kb_matches: list[KBMatch] = field(default_factory=list)
    network_correlation: list[str] = field(default_factory=list)
    trail: ReasoningTrail | None = None
    verifier: VerifierVerdict | None = None
    score: ClassScore | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "location": self.location,
            "verified": self.kept,
            "unverified": self.unverified,
            "dropped_claims": self.dropped,
            "model": self.model,
            "cost_usd": round(self.cost_usd, 6),
            "kb_matches": [
                {"kb_id": m.kb_id, "title": m.title, "similarity": round(m.similarity, 4),
                 "mitre_techniques": m.mitre_techniques}
                for m in self.kb_matches
            ],
            "network_correlation": self.network_correlation,
            "reasoning_trail": (self.trail.steps if self.trail else []),
            "verifier": ({
                "status": self.verifier.status,
                "confidence": self.verifier.confidence,
                "counter_argument": self.verifier.counter_argument,
                "fabricated_citations": self.verifier.fabricated_citations,
            } if self.verifier else None),
            "score": ({
                "score": self.score.score,
                "band": self.score.band,
                "rationale": self.score.rationale,
            } if self.score else None),
        }


@dataclass
class DeobfuscationResult:
    sha256: str
    explanations: list[ClassExplanation] = field(default_factory=list)
    calls: int = 0
    cost_usd: float = 0.0
    errors: list[str] = field(default_factory=list)

    @property
    def dropped_total(self) -> int:
        return sum(len(e.dropped) for e in self.explanations)


def interesting_locations(doc: dict[str, Any], limit: int = MAX_CLASSES) -> list[str]:
    """Where L1 already found something, most severe first.

    Chosen rather than sampled: L1's findings are the reason a human would open
    this file at all, and explaining a random SDK class is a call spent on
    nothing.
    """
    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    seen: dict[str, int] = {}
    for f in doc.get("findings", []):
        if f.get("layer") != "l1":
            continue
        detail = f.get("detail") or {}
        locations = detail.get("locations") or ([f["location"]] if f.get("location") else [])
        for loc in locations:
            if not loc or loc.endswith((".apk", ".dex")) or "R.java" in loc:
                continue
            score = rank.get(f.get("severity", "low"), 9)
            seen[loc] = min(seen.get(loc, 99), score)
    return [loc for loc, _ in sorted(seen.items(), key=lambda kv: (kv[1], kv[0]))][:limit]


def package_l0_context(doc: dict[str, Any]) -> str:
    """One line of L0 context — brand claim / cert anomaly — best-effort.

    Per `L4/SKILL.md`'s INPUT_BUNDLE contract: context only, never re-derived
    here. Spine schema is read defensively since L4 does not own L0's shape.
    """
    l0 = ((doc.get("layers") or {}).get("l0") or {}).get("summary") or {}
    parts = []
    brand = l0.get("brand_claim") or l0.get("matched_bank")
    if brand:
        parts.append(f"app claims to be {brand}")
    if l0.get("certificate_anomaly") or l0.get("cert_anomaly"):
        parts.append("certificate anomaly present")
    return "; ".join(parts) if parts else "no L0 context available"


def package_l2_context(doc: dict[str, Any]) -> str:
    """One line of L2 package-level runtime context — best-effort."""
    l2 = ((doc.get("layers") or {}).get("l2") or {}).get("summary") or {}
    sms = bool(l2.get("sms_intercepted") or l2.get("sms_intercept"))
    overlay = bool(l2.get("overlay_displayed") or l2.get("overlay"))
    c2 = l2.get("c2_count", l2.get("c2_endpoints", 0))
    c2_count = c2 if isinstance(c2, int) else len(c2 or [])
    return (f"package behaviour: sms_intercepted={sms}, "
            f"overlay_displayed={overlay}, c2_endpoints={c2_count}")


def package_network_evidence(doc: dict[str, Any]) -> dict[str, Any]:
    """The L2 network summary, whichever of the shapes documented in
    `L4/network_correlation.py` this spine happens to carry."""
    l2 = ((doc.get("layers") or {}).get("l2") or {}).get("summary") or {}
    network = l2.get("network")
    if isinstance(network, dict):
        return network
    return l2 if isinstance(l2, dict) else {}


def extract_string_literals(source: str) -> list[str]:
    """Every double-quoted string literal in a class, for retrieval queries
    and network correlation. Not a full Java lexer — good enough for jadx
    output, which quotes consistently."""
    return [m.group(1) for m in _STRING_LITERAL_RE.finditer(source)]


def read_source(src_root: Path, location: str) -> str | None:
    """Resolve a finding's location to source text, tolerating layout drift."""
    candidates = [src_root / location]
    if location.startswith("sources/"):
        candidates.append(src_root / location[len("sources/"):])
    candidates.append(src_root / "sources" / location)
    for path in candidates:
        if path.is_file():
            try:
                return path.read_text(errors="replace")[:MAX_CHARS_PER_CLASS]
            except OSError:
                return None
    return None


def dex_symbols(apk_path: str | Path) -> list[str]:
    """Identifiers + strings read straight from the DEX, for ``verify``.

    Supplements the jadx-decompiled source so ``renamed``/``api_calls`` claims
    are not falsely dropped when jadx failed to decompile (or truncated) a
    class — grounding stops being coupled to decompiler success. Returns a
    single newline-joined haystack string (fast substring/word-boundary search),
    or ``[]`` on any failure (androguard missing, malformed dex — an
    anti-analysis technique, not a reason to crash).
    """
    try:
        from androguard.core.apk import APK
        from androguard.core.dex import DEX
    except ImportError:
        return []
    syms: set[str] = set()
    try:
        apk = APK(str(apk_path))
        for dex_bytes in apk.get_all_dex():
            try:
                dex = DEX(dex_bytes)
                for m in dex.get_methods():
                    name = m.get_name()
                    if name:
                        syms.add(name)
                    cls = m.get_class_name()
                    if cls.startswith("L"):
                        dotted = cls[1:].rstrip(";").replace("/", ".")
                        syms.add(dotted)
                        syms.add(dotted.rsplit(".", 1)[-1])
                        if name and not name.startswith("<"):
                            syms.add(f"{dotted.rsplit('.', 1)[-1]}.{name}")
                for f in dex.get_fields():
                    if f.get_name():
                        syms.add(f.get_name())
                for s in dex.get_strings():
                    text = s.get() if hasattr(s, "get") else str(s)
                    if text and len(text) < 200:
                        syms.add(text)
            except Exception:  # noqa: BLE001 — malformed dex; keep what we have
                continue
    except Exception:  # noqa: BLE001
        return ["\n".join(sorted(syms))] if syms else []
    return ["\n".join(sorted(syms))] if syms else []


def explain_class(provider: Provider, location: str, source: str,
                  extracted_iocs: Iterable[str], *,
                  l0_context: str = "", l2_context: str = "",
                  network_evidence: dict[str, Any] | None = None,
                  dex_haystack: Iterable[str] = (),
                  ) -> tuple[ClassExplanation, list[Completion]]:
    """Run the three-agent chain for one class: analyst -> mechanical verify
    -> reasoning-trail -> adversarial verifier -> deterministic score.

    Per `decisions/plan_l4_agentic_verdicts.md` §1: the analyst sees source +
    package-level context + retrieval; the reasoning-trail agent sees only
    what survived mechanical verification, never raw source; the verifier
    sees source + the trail + what it cited, nothing else.
    """
    completions: list[Completion] = []
    literals = extract_string_literals(source)

    query_text = f"{location}\n" + "\n".join(literals[:40])
    kb_matches = retrieve(query_text, top_k=3, min_sim=0.3)
    net_correlation = correlate(literals, network_evidence or {})

    bundle = (
        f"{SCHEMA_HINT}\n\n"
        f"File: {location}\n\n"
        f"L0 context: {l0_context or 'none'}\n"
        f"L2 context: {l2_context or 'none'}\n"
        f"Retrieved KB matches: "
        f"{[(m.kb_id, m.title, round(m.similarity, 2)) for m in kb_matches] or 'none (treat as novel)'}\n"
        f"Network correlation: {net_correlation or 'none'}\n\n"
        f"```java\n{source}\n```"
    )
    completion = provider.complete(
        [{"role": "system", "content": SYSTEM},
         {"role": "user", "content": bundle}],
        max_tokens=1500, temperature=0.0, json_object=True,
    )
    completions.append(completion)
    try:
        claims = completion.json()
    except Exception:  # noqa: BLE001
        # Salvage the first JSON object if the model wrapped it in prose.
        m = re.search(r"\{.*\}", completion.text, re.S)
        claims = json.loads(m.group()) if m else {}

    valid_kb_ids = [m.kb_id for m in kb_matches]
    v: Verdict = verify(claims, code=[source], extracted_iocs=extracted_iocs,
                        valid_kb_ids=valid_kb_ids, dex_symbols=dex_haystack)

    trail: ReasoningTrail | None = None
    verifier_result: VerifierVerdict | None = None
    try:
        trail = build_trail(v.kept, kb_matches, provider)
        kb_index = {m.kb_id: m for m in kb_matches}
        verifier_result = verify_trail(trail, source, kb_index, provider)
    except Exception:  # noqa: BLE001
        # A failed second/third call degrades to "no score signal", not a
        # crash — the analyst's mechanically-verified claims still stand.
        pass

    score = score_class(
        kept_claims=v.kept, dropped_claims=v.dropped, kb_matches=kb_matches,
        verifier_result=verifier_result, suspicion=claims.get("suspicion"),
    )

    # `cost_usd` here is just the analyst call; the run-level total in
    # `deobfuscate()` is read from `provider.ledger` so it captures the
    # trail + verifier calls too, not just this one completion.
    return ClassExplanation(
        location=location, kept=v.kept, unverified=v.unverified,
        dropped=v.dropped, model=completion.model, cost_usd=completion.cost_usd,
        kb_matches=kb_matches, network_correlation=net_correlation,
        trail=trail, verifier=verifier_result, score=score,
    ), completions


def deobfuscate(doc: dict[str, Any], src_root: Path, *,
                provider: Provider | None = None,
                extracted_iocs: Iterable[str] = (),
                limit: int = MAX_CLASSES) -> DeobfuscationResult:
    provider = provider or get_provider("openrouter")
    result = DeobfuscationResult(sha256=doc.get("sha256", ""))

    l0_context = package_l0_context(doc)
    l2_context = package_l2_context(doc)
    network_evidence = package_network_evidence(doc)

    # DEX symbols supplement the decompiled source so verify() doesn't drop true
    # claims on classes jadx failed to render (fix: grounding not coupled to
    # jadx). Best-effort and computed once per sample.
    apk_path = (doc.get("identity") or {}).get("source_apk")
    dex_haystack = dex_symbols(apk_path) if apk_path and Path(apk_path).is_file() else []

    spend_before = getattr(provider, "ledger", None)
    spend_before = spend_before.spent_usd if spend_before else 0.0

    for location in interesting_locations(doc, limit):
        source = read_source(src_root, location)
        if not source:
            result.errors.append(f"source not available: {location}")
            continue
        try:
            explanation, _completions = explain_class(
                provider, location, source, extracted_iocs,
                l0_context=l0_context, l2_context=l2_context,
                network_evidence=network_evidence, dex_haystack=dex_haystack,
            )
        except Exception as exc:  # noqa: BLE001
            result.errors.append(f"{location}: {type(exc).__name__}: {exc}")
            continue
        result.explanations.append(explanation)
        result.calls += 1

    ledger = getattr(provider, "ledger", None)
    result.cost_usd = (ledger.spent_usd - spend_before) if ledger else sum(
        e.cost_usd for e in result.explanations)

    return result


def promote(result: DeobfuscationResult) -> dict[str, Any]:
    """L4's spine summary. No findings, no score contribution to L5 — by
    design, unchanged from before. The 0-10 scores below are for L6's ranked
    report only (`decisions/plan_l4_agentic_verdicts.md` — the L5 edge is
    deferred behind the benign-corpus gate, T24)."""
    verified_counts: dict[str, int] = {}
    band_counts: dict[str, int] = {}
    scored = [e.score for e in result.explanations if e.score is not None]
    for e in result.explanations:
        for kind, value in e.kept.items():
            verified_counts[kind] = verified_counts.get(kind, 0) + (
                len(value) if isinstance(value, (list, dict)) else 0)
        if e.score is not None:
            band_counts[e.score.band] = band_counts.get(e.score.band, 0) + 1
    return {
        "classes_explained": len(result.explanations),
        "llm_calls": result.calls,
        "cost_usd": round(result.cost_usd, 6),
        "verified_claims": verified_counts,
        "dropped_claims": result.dropped_total,
        "score_bands": band_counts,
        "max_score": max((s.score for s in scored), default=None),
        "contributes_points": 0,
        "note": ("scored for report ranking only; every checkable claim was "
                 "re-derived from the artifact and discarded if it did not "
                 "match; the L5 scoring edge is deferred (T24)"),
        "errors": result.errors[:5],
    }


def write_layer(result: DeobfuscationResult) -> None:
    out = REPO_ROOT / "L4" / "artifacts" / result.sha256 / "deobfuscation.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(
        {"sha256": result.sha256,
         "explanations": [e.to_dict() for e in result.explanations],
         "errors": result.errors},
        indent=2))
    spine.update_layer(
        result.sha256, "l4",
        status=(spine.LayerStatus.COMPLETE if result.explanations
                else spine.LayerStatus.SKIPPED),
        findings=[],            # L4 never mints evidence
        summary=promote(result),
        coverage={"classes_seen": len(result.explanations),
                  "classes_unavailable": len(result.errors)},
        gaps=None,              # consumer layer
        artifact=out,
    )


def main(argv: list[str] | None = None) -> int:
    import argparse

    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("sha256")
    ap.add_argument("--src", required=True, help="jadx_src directory for this sample")
    ap.add_argument("--limit", type=int, default=MAX_CLASSES)
    ap.add_argument("--budget", type=float, default=1.0, help="USD cap for this run")
    ap.add_argument("--explain", action="store_true")
    ap.add_argument("--no-write", action="store_true")
    args = ap.parse_args(argv)

    doc = spine.load_spine(args.sha256)
    if not spine.spine_path(args.sha256).is_file():
        print(f"no spine for {args.sha256}", file=sys.stderr)
        return 1

    from L6.export import load_iocs
    iocs = [str(i.get("value", "")) for i in load_iocs(doc)]

    provider = get_provider("openrouter", ledger=CostLedger(cap_usd=args.budget))
    result = deobfuscate(doc, Path(args.src), provider=provider,
                         extracted_iocs=iocs, limit=args.limit)

    if not args.no_write and result.explanations:
        write_layer(result)

    print(f"{len(result.explanations)} classes explained, {result.calls} calls, "
          f"${result.cost_usd:.6f}, {result.dropped_total} claims dropped")
    ranked = sorted(result.explanations,
                    key=lambda e: e.score.score if e.score else -1, reverse=True)
    for e in ranked:
        score_tag = f"[{e.score.score}/10 · {e.score.band}]" if e.score else "[unscored]"
        print(f"\n  {score_tag} {e.location}")
        if e.score:
            print(f"    {e.score.rationale}")
        if e.verifier:
            print(f"    verifier: {e.verifier.status} ({e.verifier.confidence})"
                  + (f" — {e.verifier.counter_argument[:160]}" if e.verifier.counter_argument else ""))
        purpose = e.unverified.get("purpose")
        if purpose:
            print(f"    purpose (unverified): {purpose}")
        for kind, value in e.kept.items():
            if value:
                print(f"    {kind}: {json.dumps(value)[:160]}")
        for d in e.dropped:
            print(f"    ✗ dropped {d['kind']}: {json.dumps(d['claim'])[:90]}"
                  f"  ({d['reason']})")
    for err in result.errors:
        print(f"  ! {err}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
