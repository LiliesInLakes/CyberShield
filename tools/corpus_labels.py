"""Build ``corpus/labels.json`` — the class label for every analysed sample.

    source source_env.sh
    $SENTINEL_PYTHON tools/corpus_labels.py build
    $SENTINEL_PYTHON tools/corpus_labels.py build --benign-root /path/to/fdroid --benign-id fdroid_2026-08
    $SENTINEL_PYTHON tools/corpus_labels.py show

Spines are keyed by SHA-256 and carry **no class**. A4 cannot compute a benign
rate without one, and L5 cannot be validated without one. This builds that
mapping from the files that already assert it, and refuses to invent anything.

Four rules, each of which is a real failure mode rather than a hypothetical:

**A conflict is a loud failure, never a silent resolution.** If two sources
claim different classes for one SHA-256, the entry becomes ``conflicted``, it is
excluded from every statistic, and this tool exits non-zero. A repackaged
open-source app appearing in both the benign and malware corpora is entirely
plausible, and quietly picking one would corrupt the denominator that the whole
report rests on.

**Duplicate provenance inside one class is normal.** 12 SHA-256s in this corpus
have more than one ``run_index`` key — the same sample present both loose and
zipped, or shared between two archives. Every provenance is recorded and the
sample is counted once.

**Nothing is labelled by assumption.** Every entry names the file that asserted
its class. There is no "everything not known to be benign is malware" default,
because that default is how a corpus silently acquires the labels you wanted.

**``vuln`` is excluded, not benign.** InsecureBankv2, PIVAA and the UnCrackable
levels are deliberately-vulnerable training apps. They are neither malicious nor
representative of benign software; folding them into B would corrupt the benign
denominator. They are negative controls, and they get their own class.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

CORPUS = REPO_ROOT / "corpus"
LABELS_PATH = CORPUS / "labels.json"
RUN_INDEX = CORPUS / "run_index.json"
PRE_B1_MANIFEST = REPO_ROOT / "tests" / "baseline" / "pre_B1" / "manifest.json"

SCHEMA_VERSION = "corpus-labels-1"

APK_MAGIC = b"PK\x03\x04"

# Classes that participate in A4's statistics, and what they mean.
CLASS_MALWARE = "malware"
CLASS_BENIGN = "benign"
CLASS_EXCLUDED = "excluded"
CLASS_CONFLICTED = "conflicted"

MALWARE_CAVEATS = [
    "vintage_2020_2022",
    "github_sourced_not_vt_verified",
]
FDROID_CAVEATS = [
    "open_source_only",
    "no_bfsi_apps",
    "fdroid_or_dev_signed",
    "no_ad_sdks",
    "vintage_2024_2026",
]


@dataclass
class Claim:
    """One source asserting one class for one sha256."""

    sha256: str
    cls: str
    source_id: str
    provenance: str
    subclass: str | None = None


@dataclass
class Source:
    id: str
    cls: str
    evidence: str
    root: str = ""
    caveats: list[str] = field(default_factory=list)
    reason: str = ""
    n: int = 0


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def claims_from_run_index(path: Path = RUN_INDEX) -> tuple[list[Claim], Source]:
    """Everything the corpus runner processed out of ``corpus/malware_raw``.

    The runner only ever pointed at the malware corpus, so its class is known
    from where it ran rather than assumed from what it found.
    """
    src = Source(id="malware_raw", cls=CLASS_MALWARE,
                 evidence=str(path.relative_to(REPO_ROOT)),
                 root="corpus/malware_raw", caveats=list(MALWARE_CAVEATS))
    if not path.is_file():
        return [], src
    index = json.loads(path.read_text())
    claims = [
        Claim(sha256=rec["sha256"], cls=CLASS_MALWARE, source_id=src.id, provenance=key)
        for key, rec in sorted(index.items())
        if rec.get("sha256") and rec.get("status") == "ok"
    ]
    src.n = len({c.sha256 for c in claims})
    return claims, src


def claims_from_pre_b1(path: Path = PRE_B1_MANIFEST) -> tuple[list[Claim], list[Source]]:
    """The 22 hand-labelled samples frozen before the B1 detection work.

    This is the only source that distinguishes ``india_malware`` and the only
    one that names the ``vuln`` apps, so it wins on subclass but must still
    agree on class.
    """
    good = Source(id="testing_apps_good", cls=CLASS_BENIGN,
                  evidence=str(path.relative_to(REPO_ROOT)),
                  root="testing_apps/good_apps",
                  caveats=["n=4_not_a_denominator"])
    vuln = Source(id="testing_apps_vuln", cls=CLASS_EXCLUDED,
                  evidence=str(path.relative_to(REPO_ROOT)),
                  root="testing_apps/vuln",
                  reason=("intentionally-vulnerable training apps: neither malicious "
                          "nor benign-representative"))
    india = Source(id="pre_B1_india", cls=CLASS_MALWARE,
                   evidence=str(path.relative_to(REPO_ROOT)),
                   caveats=list(MALWARE_CAVEATS))

    if not path.is_file():
        return [], [good, vuln, india]

    manifest = json.loads(path.read_text())
    claims: list[Claim] = []
    for sha, rec in sorted(manifest.items()):
        raw = rec.get("class")
        provenance = rec.get("source") or "(unrecorded)"
        if raw == "benign":
            claims.append(Claim(sha, CLASS_BENIGN, good.id, provenance))
        elif raw == "vuln":
            claims.append(Claim(sha, CLASS_EXCLUDED, vuln.id, provenance))
        elif raw == "india_malware":
            claims.append(Claim(sha, CLASS_MALWARE, india.id, provenance,
                                subclass="india_malware"))
        else:
            # Never guess. An unrecognised class is reported, not mapped.
            print(f"  ! unrecognised class {raw!r} for {sha[:16]} — skipped",
                  file=sys.stderr)
    for s in (good, vuln, india):
        s.n = len({c.sha256 for c in claims if c.source_id == s.id})
    return claims, [good, vuln, india]


def claims_from_benign_root(root: Path, source_id: str) -> tuple[list[Claim], Source]:
    """Loose APKs in a directory known to be benign (e.g. the F-Droid pull).

    Hashes each file, so the label is bound to content rather than a filename.
    Detects APKs by magic, matching ``corpus_run.classify`` — extension proves
    nothing in either direction.
    """
    src = Source(id=source_id, cls=CLASS_BENIGN, evidence=f"directory listing of {root}",
                 root=str(root), caveats=list(FDROID_CAVEATS))
    claims: list[Claim] = []
    if not root.is_dir():
        return claims, src
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        try:
            with path.open("rb") as fh:
                if fh.read(4) != APK_MAGIC:
                    continue
        except OSError:
            continue
        claims.append(Claim(_sha256_file(path), CLASS_BENIGN, source_id,
                            str(path.relative_to(root))))
    src.n = len({c.sha256 for c in claims})
    return claims, src


def claims_from_labelled_root(root: Path, source_id: str, cls: str,
                              subclass: str | None = None,
                              caveats: list[str] | None = None
                              ) -> tuple[list[Claim], Source]:
    """Loose APKs in a directory whose class is known from its provenance.

    Used for acquired corpora that arrive pre-labelled — CICMalDroid's banking
    split, an AndroZoo pull filtered by AVClass family — where the label comes
    from the source's own curation rather than from anything we inferred.

    ``subclass`` is what makes these worth acquiring: ``banking`` lets A4 and
    the evaluation split malware into "after a bank" and "not", which is the
    distinction the whole project turns on and which our own corpus can only
    make for 14 samples.
    """
    src = Source(id=source_id, cls=cls, evidence=f"directory listing of {root}",
                 root=str(root), caveats=list(caveats or []))
    claims: list[Claim] = []
    if not root.is_dir():
        return claims, src
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        try:
            with path.open("rb") as fh:
                if fh.read(4) != APK_MAGIC:
                    continue
        except OSError:
            continue
        claims.append(Claim(_sha256_file(path), cls, source_id,
                            str(path.relative_to(root)), subclass=subclass))
    src.n = len({c.sha256 for c in claims})
    return claims, src


def merge(claims: list[Claim]) -> tuple[dict[str, dict[str, Any]], list[str]]:
    """Fold claims into one entry per sha256. Disagreement becomes ``conflicted``."""
    by_sha: dict[str, list[Claim]] = {}
    for c in claims:
        by_sha.setdefault(c.sha256, []).append(c)

    labels: dict[str, dict[str, Any]] = {}
    conflicts: list[str] = []
    for sha, group in sorted(by_sha.items()):
        classes = {c.cls for c in group}
        subclasses = {c.subclass for c in group if c.subclass}
        provenance = sorted({f"{c.source_id}:{c.provenance}" for c in group})

        if len(classes) > 1:
            conflicts.append(sha)
            labels[sha] = {
                "class": CLASS_CONFLICTED,
                "source_id": sorted({c.source_id for c in group}),
                "provenance": provenance,
                "conflicting_classes": sorted(classes),
            }
            continue

        entry: dict[str, Any] = {
            "class": classes.pop(),
            "source_id": sorted({c.source_id for c in group})[0]
            if len({c.source_id for c in group}) == 1
            else sorted({c.source_id for c in group}),
            "provenance": provenance,
        }
        if subclasses:
            entry["subclass"] = sorted(subclasses)[0]
        labels[sha] = entry
    return labels, conflicts


def build(benign_roots: list[tuple[Path, str]] | None = None,
          labelled_roots: list[tuple[Path, str, str, str | None]] | None = None,
          out: Path = LABELS_PATH) -> int:
    all_claims: list[Claim] = []
    sources: list[Source] = []

    mal_claims, mal_src = claims_from_run_index()
    all_claims += mal_claims
    sources.append(mal_src)

    b1_claims, b1_sources = claims_from_pre_b1()
    all_claims += b1_claims
    sources += b1_sources

    for root, source_id in benign_roots or []:
        c, s = claims_from_benign_root(root, source_id)
        all_claims += c
        sources.append(s)

    for root, source_id, cls, subclass in labelled_roots or []:
        c, s = claims_from_labelled_root(root, source_id, cls, subclass)
        all_claims += c
        sources.append(s)

    labels, conflicts = merge(all_claims)
    counts = Counter(v["class"] for v in labels.values())

    doc = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "generator": "tools/corpus_labels.py",
        "counts": dict(sorted(counts.items())),
        "sources": [
            {k: v for k, v in
             {"id": s.id, "class": s.cls, "n": s.n, "root": s.root,
              "evidence": s.evidence, "caveats": s.caveats, "reason": s.reason}.items()
             if v}
            for s in sources
        ],
        "labels": labels,
    }
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(doc, indent=2, sort_keys=True))

    print(f"wrote {out.relative_to(REPO_ROOT)}  ({len(labels)} samples)")
    for cls, n in sorted(counts.items()):
        print(f"  {cls:12s} {n:5d}")
    for s in sources:
        print(f"    source {s.id:20s} class={s.cls:10s} n={s.n}")

    if conflicts:
        print(f"\n!! {len(conflicts)} sha256 have conflicting class claims:",
              file=sys.stderr)
        for sha in conflicts[:10]:
            print(f"     {sha}  {labels[sha]['conflicting_classes']}", file=sys.stderr)
        print("   These are excluded from all statistics. Resolve before trusting "
              "any rate computed from this file.", file=sys.stderr)
        return 1
    return 0


def load(path: Path = LABELS_PATH) -> dict[str, Any]:
    if not path.is_file():
        raise SystemExit(
            f"{path} not found. Build it first:\n"
            f"    $SENTINEL_PYTHON tools/corpus_labels.py build"
        )
    doc = json.loads(path.read_text())
    if doc.get("schema_version") != SCHEMA_VERSION:
        raise SystemExit(
            f"{path} is schema {doc.get('schema_version')!r}, expected "
            f"{SCHEMA_VERSION!r}. Rebuild it."
        )
    return doc


# Subclasses that have been *acquired and registered* (so a dedicated tool
# like L3b can find them) but not *folded into* the general malware
# population A4/L5/evaluate measure against. Registering a corpus with a
# subclass answers "can something find these samples", not "should the
# headline numbers include them" -- those are different, human decisions
# (CLAUDE.md's CICMalDroid section is exactly this: acquired and audited,
# deliberately not folded in). "banking" landed here the moment
# tools/corpus_labels.py build --malware-subclass banking is run for
# CICMalDroid/L3b, which happens independently of that decision ever being
# made -- so every consumer of the general population must exclude it
# explicitly, or it leaks in silently the next time weights are regenerated.
GENERAL_POPULATION_EXCLUDED_SUBCLASSES = frozenset({"banking"})


def general_population(labels: dict[str, Any]) -> dict[str, Any]:
    """``labels``, minus every entry whose subclass has been kept out of the
    general population. Call this once, right after ``load()``, in anything
    that computes A4 weights, L5 gate rates, or headline evaluation metrics --
    not in tools (like L3b/dataset.py) that exist specifically to consume an
    acquired-but-separate subclass.
    """
    return {sha: entry for sha, entry in labels.items()
           if entry.get("subclass") not in GENERAL_POPULATION_EXCLUDED_SUBCLASSES}


def show(path: Path = LABELS_PATH) -> int:
    doc = load(path)
    print(f"{path.name}  schema={doc['schema_version']}  generated={doc['generated_at']}")
    print(f"  counts: {doc['counts']}")
    for s in doc["sources"]:
        print(f"  source {s['id']:20s} class={s['class']:10s} n={s.get('n',0)}")
        for c in s.get("caveats", []):
            print(f"      caveat: {c}")
    subs = Counter(v.get("subclass") for v in doc["labels"].values() if v.get("subclass"))
    if subs:
        print(f"  subclasses: {dict(subs)}")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)

    b = sub.add_parser("build", help="regenerate corpus/labels.json")
    b.add_argument("--benign-root", action="append", default=[],
                   help="directory of loose benign APKs (repeatable)")
    b.add_argument("--benign-id", action="append", default=[],
                   help="source id for the matching --benign-root")
    b.add_argument("--malware-root", action="append", default=[],
                   help="directory of loose APKs known to be malware (repeatable)")
    b.add_argument("--malware-id", action="append", default=[],
                   help="source id for the matching --malware-root")
    b.add_argument("--malware-subclass", action="append", default=[],
                   help="subclass for the matching --malware-root, e.g. 'banking'")
    b.add_argument("--out", default=str(LABELS_PATH))

    sub.add_parser("show", help="summarise the current labels file")

    args = ap.parse_args(argv)
    if args.cmd == "show":
        return show()

    if len(args.benign_root) != len(args.benign_id):
        ap.error("--benign-root and --benign-id must be given in matching pairs")
    if len(args.malware_root) != len(args.malware_id):
        ap.error("--malware-root and --malware-id must be given in matching pairs")
    if args.malware_subclass and len(args.malware_subclass) != len(args.malware_root):
        ap.error("--malware-subclass must match --malware-root one for one")

    roots = [(Path(r), i) for r, i in zip(args.benign_root, args.benign_id)]
    subclasses = args.malware_subclass or [None] * len(args.malware_root)
    labelled = [(Path(r), i, CLASS_MALWARE, s)
                for r, i, s in zip(args.malware_root, args.malware_id, subclasses)]
    return build(roots, labelled, Path(args.out))


if __name__ == "__main__":
    raise SystemExit(main())
