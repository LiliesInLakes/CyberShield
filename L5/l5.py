"""L5 CLI — score one sample or the whole corpus.

    source source_env.sh
    $SENTINEL_PYTHON L5/l5.py <sha256> --explain     # the audit trail
    $SENTINEL_PYTHON L5/l5.py --all                  # every spine, idempotent
    $SENTINEL_PYTHON L5/l5.py --all --dry-run        # score, print, write nothing

``--explain`` is the artifact to show a judge: every point in the score, the
signal that produced it, the evidence id behind that signal, the redundancy
discount applied, and which constraint was ultimately binding.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import spine  # noqa: E402
from L5 import confidence as conf_mod  # noqa: E402
from L5 import promote  # noqa: E402
from L5.score import ScoreResult, load_policy, score_spine  # noqa: E402

ARTIFACT_ROOT = REPO_ROOT / "L5" / "artifacts"


def render_explain(doc: dict, result: ScoreResult, policy) -> str:
    L: list[str] = []
    a = L.append
    ident = doc.get("identity", {})
    a(f"sha256 {result.sha256[:12]}…  {ident.get('app_label') or '?'} "
      f"({ident.get('package') or '?'})")
    a(f"  score {result.score} ({result.band})   "
      f"confidence {result.confidence:.2f} ({result.confidence_band})")
    a(f"  binding: {result.binding_reason}   policy {result.policy_version}   "
      f"weights {result.weights_version}   ruleset {result.ruleset_version}")
    if result.unsupported:
        a("  🔴 UNSUPPORTED — the weights' benign denominator cannot carry them")

    a(f"\n  ADDITIVE  S = {result.log_odds:+.3f}  ->  {result.score - result.ml_delta}")
    by_family: dict[str, list] = {}
    for c in result.contributions:
        by_family.setdefault(c.family or "(ungrouped)", []).append(c)
    for family in sorted(by_family):
        rows = sorted(by_family[family], key=lambda c: -abs(c.weight_applied))
        total = sum(c.weight_applied for c in rows)
        a(f"    {family:16s} {total:+6.2f}")
        for c in rows:
            ids = ",".join(c.evidence_ids) or "-"
            extra = "" if c.status == "priced" else f"  [{c.status}]"
            disc = f"  x{c.discount:.2f}" if c.discount != 1.0 else ""
            a(f"      {c.weight_applied:+6.2f}  {c.source:52s} {ids:12s}{disc}{extra}")

    if result.ml_delta:
        a(f"\n  ML        {result.ml_delta:+d}  (l3 prior, bounded ±10)")

    a("\n  GATES")
    for g in result.gates:
        mark = {"fired": "FIRED", "not_fired": "not_fired",
                "indeterminate": "indeterminate", "disabled": "disabled"}[g.state]
        line = f"    {g.gate_id:40s} {mark}"
        if g.state == "fired":
            line += f"  floor {g.floor} -> score := {max(result.score, g.floor)}"
        if g.note:
            line += f"   ({g.note})"
        a(line)
        for leg in g.legs:
            sat = {True: "yes", False: "no", None: "?"}[leg["satisfied"]]
            ids = ",".join(leg.get("evidence_ids") or []) or "-"
            note = f"  {leg['note']}" if leg.get("note") else ""
            a(f"        {leg['leg']:28s} {sat:3s}  {ids}{note}")

    reasons = conf_mod.explain(doc, policy, list(result.gates), result.unsupported)
    if reasons:
        a("\n  CONFIDENCE")
        for r in reasons:
            a(f"    {r}")
    return "\n".join(L)


def write_layer(result: ScoreResult, dry_run: bool = False) -> None:
    if dry_run:
        return
    out = ARTIFACT_ROOT / result.sha256 / "score.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(promote.score_artifact(result), indent=2, sort_keys=True))

    spine.update_layer(
        result.sha256, "l5",
        status=spine.LayerStatus.PARTIAL if result.unsupported
        else spine.LayerStatus.COMPLETE,
        findings=promote.gate_findings(result),
        summary=promote.l5_summary(result),
        coverage=promote.l5_coverage(result),
        gaps=None,          # deliberate — see L5/promote.py, decision 1
        artifact=out,
    )


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("sha256", nargs="?", help="score one sample")
    ap.add_argument("--all", action="store_true", help="score every spine")
    ap.add_argument("--explain", action="store_true", help="print the audit trail")
    ap.add_argument("--dry-run", action="store_true", help="write nothing")
    ap.add_argument("--policy", default=None)
    ap.add_argument("--weights", default=None)
    args = ap.parse_args(argv)

    if not args.sha256 and not args.all:
        ap.error("give a sha256 or --all")

    policy = load_policy(Path(args.policy) if args.policy else None,
                         Path(args.weights) if args.weights else None)
    if policy.unsupported and policy.raw.get("require_supported_weights", True):
        print("⚠  weights are UNSUPPORTED "
              f"({policy.weights_meta.get('support', {}).get('reason', '')}). "
              "Scores are stamped unsupported and confidence is capped.",
              file=sys.stderr)

    if args.sha256:
        if not spine.spine_path(args.sha256).is_file():
            print(f"no spine for {args.sha256}", file=sys.stderr)
            return 1
        doc = spine.load_spine(args.sha256)
        result = score_spine(doc, policy)
        write_layer(result, args.dry_run)
        print(render_explain(doc, result, policy) if args.explain
              else f"{result.score} ({result.band})  confidence {result.confidence:.2f}")
        return 0

    bands: Counter[str] = Counter()
    gates_fired: Counter[str] = Counter()
    n = 0
    for doc in spine.iter_spines():
        result = score_spine(doc, policy)
        write_layer(result, args.dry_run)
        bands[result.band] += 1
        for g in result.gates:
            if g.state == "fired":
                gates_fired[g.gate_id] += 1
        n += 1
        if n % 200 == 0:
            print(f"  scored {n}…", flush=True)

    print(f"\nscored {n} spines"
          + ("  (dry run — nothing written)" if args.dry_run else ""))
    for _lo, _hi, name in policy.raw.get("bands", []):
        print(f"  {name:15s} {bands.get(name, 0):5d}")
    if gates_fired:
        print("  gates fired:")
        for gid, c in gates_fired.most_common():
            print(f"    {gid:42s} {c}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
