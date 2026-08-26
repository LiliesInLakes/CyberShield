"""Diff two A4 weight files, or two evaluation reports, and say what moved.

    source source_env.sh
    $SENTINEL_PYTHON tools/compare_measurements.py weights OLD.json NEW.json
    $SENTINEL_PYTHON tools/compare_measurements.py eval    OLD.json NEW.json

Every frozen baseline in `tests/baseline/` exists so that a change is a **diff
rather than a recollection**. This is the tool that reads them.

It reports sign flips first, because a weight crossing zero is a change of
kind — a signal that argued for benign now argues for malware — while a weight
moving from +2.1 to +2.4 is a change of degree. The project has already been
wrong about a sign flip twice: once when `n_benign = 4` inverted 32 of 45
signals, and once when a scanner bug made three BFSI rules argue against
maliciousness.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent


def _load(path: str) -> dict[str, Any]:
    return json.loads(Path(path).read_text())


def compare_weights(old_path: str, new_path: str) -> int:
    old, new = _load(old_path), _load(new_path)
    ow, nw = old.get("weights", {}), new.get("weights", {})

    print(f"old: {Path(old_path).name}  ruleset {old.get('ruleset_version')}  "
          f"B={old.get('corpus', {}).get('n_benign')}  "
          f"support {old.get('support', {}).get('status')}")
    print(f"new: {Path(new_path).name}  ruleset {new.get('ruleset_version')}  "
          f"B={new.get('corpus', {}).get('n_benign')}  "
          f"support {new.get('support', {}).get('status')}")

    added = sorted(set(nw) - set(ow))
    removed = sorted(set(ow) - set(nw))
    shared = sorted(set(ow) & set(nw))

    flips_up = [k for k in shared if ow[k]["w"] < 0 <= nw[k]["w"]]
    flips_dn = [k for k in shared if nw[k]["w"] < 0 <= ow[k]["w"]]

    print(f"\nsignals: {len(ow)} -> {len(nw)}"
          f"   (+{len(added)} new, -{len(removed)} gone)")
    print(f"negative weights: {sum(1 for v in ow.values() if v['w'] < 0)} -> "
          f"{sum(1 for v in nw.values() if v['w'] < 0)}")

    if flips_up:
        print(f"\n🟢 {len(flips_up)} signal(s) flipped NEGATIVE -> POSITIVE "
              f"(now argue for malware):")
        for k in sorted(flips_up, key=lambda k: -(nw[k]["w"] - ow[k]["w"])):
            print(f"   {ow[k]['w']:+6.2f} -> {nw[k]['w']:+6.2f}   "
                  f"ben {ow[k]['b']:4d}/{ow[k]['B']} -> {nw[k]['b']:4d}/{nw[k]['B']}   {k}")
    if flips_dn:
        print(f"\n🔴 {len(flips_dn)} signal(s) flipped POSITIVE -> NEGATIVE "
              f"(now argue for benign):")
        for k in sorted(flips_dn, key=lambda k: nw[k]["w"] - ow[k]["w"]):
            print(f"   {ow[k]['w']:+6.2f} -> {nw[k]['w']:+6.2f}   "
                  f"ben {ow[k]['b']:4d}/{ow[k]['B']} -> {nw[k]['b']:4d}/{nw[k]['B']}   {k}")
    if not flips_up and not flips_dn:
        print("\nno sign flips")

    moved = sorted(shared, key=lambda k: -abs(nw[k]["w"] - ow[k]["w"]))
    big = [k for k in moved if abs(nw[k]["w"] - ow[k]["w"]) >= 0.25][:15]
    if big:
        print(f"\nlargest magnitude changes:")
        for k in big:
            d = nw[k]["w"] - ow[k]["w"]
            print(f"   {d:+6.2f}   {ow[k]['w']:+6.2f} -> {nw[k]['w']:+6.2f}   "
                  f"ben rate {ow[k]['ben_rate']:.3f} -> {nw[k]['ben_rate']:.3f}   {k}")

    ben_drop = [k for k in shared if nw[k]["b"] < ow[k]["b"]]
    if ben_drop:
        total_old = sum(ow[k]["b"] for k in ben_drop)
        total_new = sum(nw[k]["b"] for k in ben_drop)
        print(f"\nbenign hits fell on {len(ben_drop)} signal(s): "
              f"{total_old} -> {total_new} total")

    dead_o = set(old.get("dead_rules", {}))
    dead_n = set(new.get("dead_rules", {}))
    print(f"\ndead rules: {len(dead_o)} -> {len(dead_n)}")
    if dead_n - dead_o:
        print(f"   newly dead: {sorted(dead_n - dead_o)}")
    if dead_o - dead_n:
        print(f"   revived:    {sorted(dead_o - dead_n)}")
    return 0


def compare_eval(old_path: str, new_path: str) -> int:
    old, new = _load(old_path), _load(new_path)

    def line(label: str, o: Any, n: Any, fmt: str = "{:.4f}") -> None:
        try:
            delta = f"  ({n - o:+.4f})"
        except TypeError:
            delta = ""
        os_ = fmt.format(o) if isinstance(o, (int, float)) else str(o)
        ns_ = fmt.format(n) if isinstance(n, (int, float)) else str(n)
        print(f"  {label:34s} {os_:>10s} -> {ns_:>10s}{delta}")

    print(f"old: {Path(old_path).name}\nnew: {Path(new_path).name}\n")
    line("n_malware", old["n_malware"], new["n_malware"], "{:.0f}")
    line("n_benign", old["n_benign"], new["n_benign"], "{:.0f}")
    line("AUROC in-sample",
         old["in_sample"]["auroc"], new["in_sample"]["auroc"])
    if "cross_validated" in old and "cross_validated" in new:
        line("AUROC cross-validated",
             old["cross_validated"]["auroc"], new["cross_validated"]["auroc"])

    print("\n  operating points (cross-validated where available):")
    ops_o = (old.get("cross_validated") or old["in_sample"])["operating_points"]
    ops_n = (new.get("cross_validated") or new["in_sample"])["operating_points"]
    by_o = {r["threshold"]: r for r in ops_o}
    for r in ops_n:
        o = by_o.get(r["threshold"])
        if not o:
            continue
        print(f"    >={r['threshold']:3d}  recall {o['recall']:.4f} -> {r['recall']:.4f}"
              f"   benign FPR {o['benign_fpr']:.4f} -> {r['benign_fpr']:.4f}"
              f"   ({o['fp_count']}/{o['n_benign']} -> {r['fp_count']}/{r['n_benign']})")

    print("\n  score distribution:")
    for cls in sorted(set(old.get("distribution", {})) | set(new.get("distribution", {}))):
        o = old.get("distribution", {}).get(cls)
        n = new.get("distribution", {}).get(cls)
        if o and n:
            print(f"    {cls:22s} median {o['median']:6.1f} -> {n['median']:6.1f}"
                  f"   n {o['n']} -> {n['n']}")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("kind", choices=("weights", "eval"))
    ap.add_argument("old")
    ap.add_argument("new")
    args = ap.parse_args(argv)
    return (compare_weights if args.kind == "weights" else compare_eval)(
        args.old, args.new)


if __name__ == "__main__":
    raise SystemExit(main())
