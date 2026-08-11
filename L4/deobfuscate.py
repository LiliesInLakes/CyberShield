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

MAX_CLASSES = 8
MAX_CHARS_PER_CLASS = 12_000

SYSTEM = (
    "You are a malware analyst reading decompiled Android code. Answer only "
    "with a JSON object matching the requested schema. Never guess: if you "
    "cannot determine something from the code shown, omit it. Every string you "
    "claim to decode will be re-decoded mechanically and discarded if wrong."
)

SCHEMA_HINT = """Return ONLY this JSON object:
{
  "purpose": "one sentence: what this class does",
  "renamed": {"<obfuscated identifier present in the code>": "<meaningful name>"},
  "decoded_strings": {"<encoded literal exactly as it appears>": "<decoded value>"},
  "api_calls": ["<security-relevant API actually called here>"],
  "iocs": ["<network indicator literally present in this code>"],
  "behaviours": ["<short tag, e.g. sms_interception>"],
  "confidence": "high|medium|low"
}"""


@dataclass
class ClassExplanation:
    location: str
    kept: dict[str, Any]
    unverified: dict[str, Any]
    dropped: list[dict[str, Any]]
    model: str
    cost_usd: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "location": self.location,
            "verified": self.kept,
            "unverified": self.unverified,
            "dropped_claims": self.dropped,
            "model": self.model,
            "cost_usd": round(self.cost_usd, 6),
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


def explain_class(provider: Provider, location: str, source: str,
                  extracted_iocs: Iterable[str]) -> tuple[ClassExplanation, Completion]:
    prompt = (f"{SCHEMA_HINT}\n\nFile: {location}\n\n```java\n{source}\n```")
    completion = provider.complete(
        [{"role": "system", "content": SYSTEM},
         {"role": "user", "content": prompt}],
        max_tokens=1500, temperature=0.0, json_object=True,
    )
    try:
        claims = completion.json()
    except Exception:  # noqa: BLE001
        # Salvage the first JSON object if the model wrapped it in prose.
        m = re.search(r"\{.*\}", completion.text, re.S)
        claims = json.loads(m.group()) if m else {}

    v: Verdict = verify(claims, code=[source], extracted_iocs=extracted_iocs)
    return ClassExplanation(
        location=location, kept=v.kept, unverified=v.unverified,
        dropped=v.dropped, model=completion.model, cost_usd=completion.cost_usd,
    ), completion


def deobfuscate(doc: dict[str, Any], src_root: Path, *,
                provider: Provider | None = None,
                extracted_iocs: Iterable[str] = (),
                limit: int = MAX_CLASSES) -> DeobfuscationResult:
    provider = provider or get_provider("openrouter")
    result = DeobfuscationResult(sha256=doc.get("sha256", ""))

    for location in interesting_locations(doc, limit):
        source = read_source(src_root, location)
        if not source:
            result.errors.append(f"source not available: {location}")
            continue
        try:
            explanation, completion = explain_class(
                provider, location, source, extracted_iocs)
        except Exception as exc:  # noqa: BLE001
            result.errors.append(f"{location}: {type(exc).__name__}: {exc}")
            continue
        result.explanations.append(explanation)
        result.calls += 1
        result.cost_usd += completion.cost_usd

    return result


def promote(result: DeobfuscationResult) -> dict[str, Any]:
    """L4's spine summary. No findings, no score contribution — by design."""
    verified_counts: dict[str, int] = {}
    for e in result.explanations:
        for kind, value in e.kept.items():
            verified_counts[kind] = verified_counts.get(kind, 0) + (
                len(value) if isinstance(value, (list, dict)) else 0)
    return {
        "classes_explained": len(result.explanations),
        "llm_calls": result.calls,
        "cost_usd": round(result.cost_usd, 6),
        "verified_claims": verified_counts,
        "dropped_claims": result.dropped_total,
        "contributes_points": 0,
        "note": ("explanation only; every checkable claim was re-derived from "
                 "the artifact and discarded if it did not match"),
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
    for e in result.explanations:
        print(f"\n  {e.location}")
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
