"""Summarise a corpus run: what was analysed, what was seen, what was missed.

    $SENTINEL_PYTHON tools/corpus_summary.py                    # newest run
    $SENTINEL_PYTHON tools/corpus_summary.py corpus/runs/<ts>

This answers "did the run work, and what did it see". It is **not** the
rule-firing report (A4): every sample here is malware, so there is no benign
denominator and therefore no discrimination to compute. Any per-rule number
derived from this file alone would be a base rate wearing a discrimination
score's clothes.
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

RUNS = REPO_ROOT / "corpus" / "runs"


def load_records(run_dir: Path) -> list[dict]:
    log = run_dir / "run_log.jsonl"
    records = []
    for line in log.read_text().splitlines():
        line = line.strip()
        if line:
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                # A crash can leave the final line half-written; everything
                # before it is still good, which is the point of JSONL.
                continue
    return records


def _bar(count: int, total: int, width: int = 28) -> str:
    filled = int(width * count / total) if total else 0
    return "█" * filled + "·" * (width - filled)


def summarise(run_dir: Path) -> int:
    records = load_records(run_dir)
    if not records:
        print(f"no records in {run_dir}")
        return 1
    total = len(records)
    ok = [r for r in records if r.get("status") == "ok"]
    analysed = [r for r in records if r.get("sha256")]

    print("=" * 76)
    print(f"CORPUS RUN — {run_dir.name}")
    print("=" * 76)
    print(f"  records            : {total}")
    print(f"  wall time          : {sum(r.get('duration_s', 0) for r in records)/60:.1f} min"
          f"   ({sum(r.get('duration_s', 0) for r in records)/max(total,1):.1f}s/sample)")
    print(f"  ruleset            : {records[0].get('ruleset_version')}")

    print("\n  status")
    for status, n in Counter(r.get("status") for r in records).most_common():
        print(f"    {status or '?':12s} {n:>4}  {_bar(n, total)}")

    skips = Counter(r.get("reason") for r in records if r.get("status") == "skipped")
    if skips:
        print("\n  skip reasons (every rejection is recorded, never silent)")
        for reason, n in skips.most_common():
            print(f"    {reason or '?':22s} {n:>4}")

    errors = [r for r in records if r.get("status") in ("error", "l1_failed")]
    if errors:
        print("\n  failures")
        for kind, n in Counter(
            (r.get("error") or "?").split(":")[0] for r in errors
        ).most_common(8):
            print(f"    {kind:34s} {n:>4}")

    # ---- coverage: the confidence axis's raw input --------------------
    print("\n" + "=" * 76)
    print("COVERAGE  (what the pipeline could not see is a result, not an error)")
    print("=" * 76)
    gaps = Counter(g for r in records for g in (r.get("analysis_gaps") or []))
    for gap, n in gaps.most_common():
        print(f"    {gap:32s} {n:>4} / {len(analysed)}  {_bar(n, max(len(analysed),1))}")
    no_src = [r for r in ok if not r.get("decompiled_files")]
    if ok:
        print(f"\n    decompiled 0 files            {len(no_src):>4} / {len(ok)}"
              f"   ({100*len(no_src)/len(ok):.0f}% yielded no Java source)")

    # ---- what L0 saw --------------------------------------------------
    print("\n" + "=" * 76)
    print("L0 TRIAGE")
    print("=" * 76)
    verdicts = Counter(r.get("l0_verdict") for r in analysed)
    for verdict, n in verdicts.most_common():
        print(f"    {verdict or 'n/a':26s} {n:>4} / {len(analysed)}  {_bar(n, max(len(analysed),1))}")
    entities = Counter(r["l0_entity"] for r in analysed if r.get("l0_entity"))
    if entities:
        print("\n  impersonated entities (attributed by name, not guessed)")
        for entity, n in entities.most_common(15):
            print(f"    {entity:34s} {n:>4}")

    # ---- findings ------------------------------------------------------
    print("\n" + "=" * 76)
    print("FINDINGS")
    print("=" * 76)
    fcounts = [r.get("spine_findings", 0) for r in ok]
    if fcounts:
        ordered = sorted(fcounts)
        print(f"    per sample: min={ordered[0]}  median={ordered[len(ordered)//2]}  "
              f"max={ordered[-1]}  mean={sum(ordered)/len(ordered):.1f}")
        zero = sum(1 for c in fcounts if c == 0)
        print(f"    samples with ZERO findings   {zero:>4} / {len(ok)}"
              f"   ({100*zero/len(ok):.0f}%)")
        print("      (near-zero by construction — structural rules fire on any valid")
        print("       APK, so total count is not a detection measure. See below.)")
    cats = Counter(c for r in ok for c in (r.get("l1_categories") or []))
    if cats:
        print("\n  L1 categories (share of analysed malware)")
        for cat, n in cats.most_common(18):
            print(f"    {cat:26s} {n:>4} / {len(ok)}  {_bar(n, max(len(ok),1))}")
    malcat = [r for r in ok if r.get("malware_category", 0) > 0]
    print(f"\n  ⚑ THE DETECTION GAP, QUANTIFIED")
    print(f"    >=1 malware-category finding : {len(malcat):>4} / {len(ok)}"
          f"  ({100*len(malcat)/max(len(ok),1):.0f}%)")
    print(f"    characterised as malware ONLY by hygiene/structural rules"
          f" : {len(ok) - len(malcat)} / {len(ok)}"
          f"  ({100*(len(ok)-len(malcat))/max(len(ok),1):.0f}%)")
    print("    Every sample in this corpus is known malware, so the second number")
    print("    is a false-negative rate for the malware-category rule set.")

    print("\n" + "=" * 76)
    print("READ THIS BEFORE QUOTING ANY NUMBER ABOVE")
    print("=" * 76)
    print("  * Every sample here is malware. There is no benign denominator, so")
    print("    nothing above is a discrimination rate — these are base rates on a")
    print("    malicious population. Per-rule weights need the benign set (A4).")
    print("  * Corpus vintage is 2020-2022. It does not evidence 2026 detection.")
    print("  * 'zero findings' counts samples the pipeline did not characterise;")
    print("    it is the honest measure of the current detection gap.")
    return 0


def main(argv: list[str]) -> int:
    if len(argv) > 1:
        run_dir = Path(argv[1])
    else:
        candidates = sorted(p for p in RUNS.iterdir() if (p / "run_log.jsonl").exists())
        if not candidates:
            print(f"no runs under {RUNS}", file=sys.stderr)
            return 1
        run_dir = candidates[-1]
    return summarise(run_dir)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
