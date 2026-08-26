"""Measure which token combinations actually separate malware from benign.

    source source_env.sh
    $SENTINEL_PYTHON tools/mine_cooccurrence.py --rule Android_BFSI_Accessibility_Driven_Exfil
    $SENTINEL_PYTHON tools/mine_cooccurrence.py --tokens AccessibilityNodeInfo,getMessageBody --limit 200

This is the method B1 used to author the BFSI primitives, run again with a
benign denominator that means something. B1 mined 50 malware against **4**
benign and produced rules whose own metadata says "0/4 benign"; three of them
later measured as *anti*-discriminative against 604. The method was right and
the denominator was not.

**Co-location is inside one dex class, never across an APK.** A conjunction
evaluated over a whole application is satisfied by unrelated SDKs — that is
T2 at file scope, T21 at dex scope, and T28 at container scope, which is three
separate occasions the same mistake has cost this project a measurement. This
tool only ever asks: *did these tokens appear together in a single class?*

**It reports the benign rate first.** A combination firing on 40% of malware is
uninteresting if it also fires on 15% of benign apps, and the ordering of the
output is deliberate: discrimination, not prevalence.

Reads samples one at a time from their archives, never extracts in bulk, and
never executes anything — the same constraints as ``tools/corpus_run.py``.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile
import zipfile
from collections import Counter, defaultdict
from dataclasses import dataclass
from itertools import combinations
from pathlib import Path
from typing import Iterable, Iterator

REPO_ROOT = Path(__file__).resolve().parent.parent
for _p in (str(REPO_ROOT), str(REPO_ROOT / "L1")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

DATA_ROOT = Path(os.environ.get("SENTINEL_DATA_ROOT", REPO_ROOT))
MALWARE_RAW = REPO_ROOT / "corpus" / "malware_raw"
BENIGN_DIR = DATA_ROOT / "fdroid" / "apks"

APK_MAGIC = b"PK\x03\x04"


@dataclass
class Sample:
    label: int              # 1 malware, 0 benign
    display: str
    archive: Path | None = None
    member: str | None = None
    path: Path | None = None


def iter_samples(n_mal: int, n_ben: int, seed: int = 11) -> Iterator[Sample]:
    import random

    rng = random.Random(seed)

    loose = sorted(BENIGN_DIR.glob("*.apk"))
    rng.shuffle(loose)
    for p in loose[:n_ben]:
        yield Sample(label=0, display=p.name, path=p)

    members: list[tuple[Path, str]] = []
    for archive in sorted(MALWARE_RAW.rglob("*.zip")):
        try:
            with zipfile.ZipFile(archive) as zf:
                for info in zf.infolist():
                    if not info.is_dir() and info.file_size > 10_000:
                        members.append((archive, info.filename))
        except Exception:  # noqa: BLE001
            continue
    rng.shuffle(members)
    taken = 0
    for archive, member in members:
        if taken >= n_mal:
            break
        yield Sample(label=1, display=f"{archive.name}!{Path(member).name}",
                     archive=archive, member=member)
        taken += 1


def class_buffers(sample: Sample) -> list[tuple[str, bytes]]:
    """Per-dex-class byte buffers, the only scope where co-location is a claim."""
    from engines.yara_scan import _dex_class_buffers

    data: bytes | None = None
    tmp: tempfile.TemporaryDirectory | None = None
    try:
        if sample.path:
            apk_bytes = sample.path.read_bytes()
        else:
            import pyzipper
            with pyzipper.AESZipFile(sample.archive) as zf:
                zf.setpassword(b"infected")
                apk_bytes = zf.read(sample.member)
        if not apk_bytes.startswith(APK_MAGIC):
            return []
        out: list[tuple[str, bytes]] = []
        with zipfile.ZipFile(__import__("io").BytesIO(apk_bytes)) as zf:
            for name in zf.namelist():
                if name.startswith("classes") and name.endswith(".dex"):
                    try:
                        out.extend(_dex_class_buffers(zf.read(name)))
                    except Exception:  # noqa: BLE001
                        continue
        return out
    except Exception:  # noqa: BLE001
        return []
    finally:
        if tmp:
            tmp.cleanup()


def rule_tokens(rule_name: str) -> list[str]:
    """Literal strings a rule declares, so an existing rule can be re-mined.

    Only the ``strings:`` section, and only ``$ident = "literal"`` forms. A
    naive scan for every quoted value in the rule block picks up the meta as
    well, and mining ``severity = "High"`` or ``scope = "both"`` produces
    confident-looking rows about tokens the rule never matches on — which it
    did, on the first run of this function.
    """
    for path in sorted((REPO_ROOT / "L1" / "yara_templates").rglob("*.yar")):
        text = path.read_text(errors="replace")
        m = re.search(rf"rule\s+{re.escape(rule_name)}\b.*?\n\}}", text, re.S)
        if not m:
            continue
        block = m.group()
        strings_section = re.search(r"strings:(.*?)condition:", block, re.S)
        if not strings_section:
            return []
        out: list[str] = []
        for ident, value in re.findall(r'(\$[A-Za-z0-9_]*)\s*=\s*"((?:[^"\\]|\\.)*)"',
                                       strings_section.group(1)):
            if value:
                out.append(value)
        return out
    raise SystemExit(f"rule {rule_name!r} not found")


def mine(tokens: list[str], samples: Iterable[Sample], max_k: int = 2
         ) -> tuple[dict[tuple[str, ...], list[int]], int, int]:
    """For each token combination, how many samples have it co-located in one class."""
    encoded = [(t, t.encode()) for t in tokens]
    hits: dict[tuple[str, ...], list[int]] = defaultdict(lambda: [0, 0])
    n_mal = n_ben = 0

    for s in samples:
        bufs = class_buffers(s)
        if not bufs:
            continue
        if s.label:
            n_mal += 1
        else:
            n_ben += 1

        present: set[tuple[str, ...]] = set()
        for _cls, buf in bufs:
            here = tuple(t for t, b in encoded if b in buf)
            if not here:
                continue
            for k in range(1, min(max_k, len(here)) + 1):
                present.update(combinations(here, k))
        for combo in present:
            hits[combo][0 if s.label else 1] += 1
    return hits, n_mal, n_ben


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--rule", help="re-mine the tokens of an existing rule")
    ap.add_argument("--tokens", help="comma-separated literals to mine instead")
    ap.add_argument("--limit", type=int, default=150, help="samples per class")
    ap.add_argument("--max-k", type=int, default=2, help="largest combination size")
    ap.add_argument("--out", default=None)
    args = ap.parse_args(argv)

    try:
        from loguru import logger
        logger.remove()
    except Exception:  # noqa: BLE001
        pass

    if args.rule:
        tokens = rule_tokens(args.rule)
    elif args.tokens:
        tokens = [t.strip() for t in args.tokens.split(",") if t.strip()]
    else:
        ap.error("give --rule or --tokens")

    print(f"mining {len(tokens)} tokens over {args.limit} malware + "
          f"{args.limit} benign, co-located within one dex class\n")
    hits, n_mal, n_ben = mine(tokens, iter_samples(args.limit, args.limit),
                              max_k=args.max_k)
    if not n_mal or not n_ben:
        print("no usable samples", file=sys.stderr)
        return 1

    rows = []
    for combo, (m, b) in hits.items():
        rows.append({"tokens": list(combo), "k": len(combo),
                     "mal": m, "ben": b,
                     "mal_rate": m / n_mal, "ben_rate": b / n_ben,
                     "discrimination": m / n_mal - b / n_ben})
    rows.sort(key=lambda r: -r["discrimination"])

    print(f"corpus: {n_mal} malware, {n_ben} benign\n")
    print(f"  {'discrim':>8s} {'mal':>10s} {'ben':>10s}  tokens")
    for r in rows[:25]:
        print(f"  {r['discrimination']:+8.3f} {r['mal']:4d} ({r['mal_rate']:.3f}) "
              f"{r['ben']:4d} ({r['ben_rate']:.3f})  {' + '.join(r['tokens'])[:70]}")

    useless = [r for r in rows if r["discrimination"] <= 0]
    if useless:
        print(f"\n  {len(useless)} of {len(rows)} combinations are non-discriminative "
              f"(fire at least as often on benign):")
        for r in useless[:6]:
            print(f"    {r['discrimination']:+.3f}  {' + '.join(r['tokens'])[:66]}")

    out = Path(args.out) if args.out else (
        REPO_ROOT / "docs" / "reports" /
        f"cooccurrence_{args.rule or 'tokens'}.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"tokens": tokens, "n_malware": n_mal,
                               "n_benign": n_ben, "combinations": rows}, indent=2))
    print(f"\nwrote {out.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
