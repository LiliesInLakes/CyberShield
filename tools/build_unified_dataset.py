"""Build the unified, pipeline-extracted L3 dataset from the labelled corpus.

    source source_env.sh
    $SENTINEL_PYTHON tools/build_unified_dataset.py extract   # slow, resumable
    $SENTINEL_PYTHON tools/build_unified_dataset.py build      # fast, re-tunable

Two stages, deliberately separate:

* **extract** runs ``L3.features.extract_from_apk`` over every labelled sample
  whose APK is still on disk and appends its token set to a jsonl cache. This
  is the expensive pass (it parses every dex), so it is resumable and never
  redone when only the vocabulary thresholds change.
* **build** turns the cache into a frozen corpus vocabulary
  (``L3/model/unified_vocab.json``) and a feature matrix
  (``L3/model/unified_dataset.npz``). Re-run freely to tune ``--min-df`` etc.

Malware safety (CLAUDE.md section 4): only samples whose ``source_apk`` is a
real file on disk are read, one at a time, via androguard. Zip-member malware
whose temp APK was already disposed is skip-counted, never bulk-extracted.

The label population is ``corpus/labels.json``: class in {malware, benign}
(``excluded`` dropped). Grouping for a leakage-free split is the malware family
when the provenance path reveals one (``android-malware/<family>/...``),
otherwise the sample's own sha (a singleton group, free to fall on either side).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

import numpy as np

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import spine  # noqa: E402
from L3.features import extract_from_apk  # noqa: E402
from L3.unified_features import (  # noqa: E402
    augment_with_capabilities, build_vocabulary, meaningful_tokens, vectorise_unified,
)
from tools import corpus_labels  # noqa: E402

MODEL_DIR = REPO_ROOT / "L3" / "model"
# The token cache can be several hundred MB; keep it off the repo filesystem,
# which runs a 2 GB floor (T31). Vocabulary and matrix are small and stay in
# the model dir with the trained model.
DATA_ROOT = Path(os.environ.get("SENTINEL_DATA_ROOT", REPO_ROOT))
TOKENS_CACHE = DATA_ROOT / "l3_unified" / "unified_tokens.jsonl"
VOCAB_PATH = MODEL_DIR / "unified_vocab.json"
DATASET_PATH = MODEL_DIR / "unified_dataset.npz"
SKIPS_PATH = MODEL_DIR / "unified_dataset_skips.json"


def _silence_loguru() -> None:
    try:
        from loguru import logger
        logger.remove()
    except Exception:  # noqa: BLE001
        pass


def _family_group(entry: dict[str, Any], sha: str) -> tuple[str, str]:
    """(family, group) for one sample.

    family is a human label ('' when unknown); group is what the split keeps
    together — the family if known, else the sha so it may fall either side.
    Derived from the malware_raw provenance folder: 'android-malware/<fam>/..'.
    """
    for prov in entry.get("provenance", []) or []:
        marker = "android-malware/"
        if marker in prov:
            tail = prov.split(marker, 1)[1]
            folder = tail.split("/", 1)[0]
            if folder and folder not in ("unclassified_apks", "loose"):
                return folder, folder
    return "", sha


def stage_extract() -> None:
    _silence_loguru()
    labels = corpus_labels.load()["labels"]
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    TOKENS_CACHE.parent.mkdir(parents=True, exist_ok=True)

    done: set[str] = set()
    if TOKENS_CACHE.is_file():
        for line in TOKENS_CACHE.read_text().splitlines():
            if line.strip():
                done.add(json.loads(line)["sha256"])
        print(f"resuming: {len(done)} samples already cached")

    skips = {"no_spine": 0, "no_source_apk": 0, "apk_missing_on_disk": 0,
             "extract_error": 0}
    written = 0
    todo = [(sha, e) for sha, e in labels.items()
            if e.get("class") in ("malware", "benign") and sha not in done]
    print(f"to extract: {len(todo)} samples")

    with TOKENS_CACHE.open("a") as fh:
        for i, (sha, entry) in enumerate(todo, 1):
            doc = spine.load_spine(sha)
            if not doc.get("layers"):
                skips["no_spine"] += 1
                continue
            apk_path = (doc.get("identity") or {}).get("source_apk")
            if not apk_path:
                skips["no_source_apk"] += 1
                continue
            if not Path(apk_path).is_file():
                skips["apk_missing_on_disk"] += 1
                continue
            try:
                extraction = extract_from_apk(apk_path)
            except Exception:  # noqa: BLE001 — a malformed APK is anti-analysis, not fatal
                skips["extract_error"] += 1
                continue
            family, group = _family_group(entry, sha)
            fh.write(json.dumps({
                "sha256": sha,
                "label": 1 if entry.get("class") == "malware" else 0,
                "source_id": entry.get("source_id"),
                "subclass": entry.get("subclass"),
                "family": family,
                "group": group,
                # only the meaningful tokens are cached — the library-signature
                # noise is dropped here so the cache stays small and prediction
                # applies the identical filter (L3.unified_features)
                "tokens": sorted(meaningful_tokens(extraction.tokens)),
            }) + "\n")
            written += 1
            if i % 100 == 0:
                fh.flush()
                print(f"  {i}/{len(todo)}  written={written}  skips={skips}",
                      flush=True)

    print(f"extract done: +{written} rows, skips={skips}")
    print(f"cache: {TOKENS_CACHE}")


def stage_build(min_df: int, max_df_ratio: float, max_features: int | None) -> int:
    if not TOKENS_CACHE.is_file():
        print("no token cache — run the 'extract' stage first", file=sys.stderr)
        return 1

    records = [json.loads(l) for l in TOKENS_CACHE.read_text().splitlines() if l.strip()]
    print(f"loaded {len(records)} cached samples")

    # Augment each cached (already meaningful-filtered) token set with its
    # capability aggregates — the absence-as-signal columns. Done from the cache,
    # so no re-extraction is needed; predict applies the identical augmentation.
    for r in records:
        r["tokens"] = sorted(augment_with_capabilities(r["tokens"]))

    vocab = build_vocabulary((r["tokens"] for r in records),
                             min_df=min_df, max_df_ratio=max_df_ratio)
    if max_features and vocab.size > max_features:
        # names are already ordered by descending document frequency
        from L3.unified_features import CorpusVocabulary
        names = vocab.names[:max_features]
        vocab = CorpusVocabulary(
            index={n: i for i, n in enumerate(names)}, names=names,
            document_frequency={n: vocab.document_frequency[n] for n in names},
            n_documents=vocab.n_documents)
    vocab.save(VOCAB_PATH)
    print(f"vocabulary: {vocab.size} columns "
          f"(min_df={min_df}, max_df_ratio={max_df_ratio}, cap={max_features})")

    rows, skipped_implausible = [], 0
    for r in records:
        vec, diag = vectorise_unified(r["tokens"], vocab)
        r["_plausible"] = diag["plausible"]
        if not diag["plausible"]:
            skipped_implausible += 1
        rows.append(vec)

    X = np.stack(rows).astype(np.int8) if rows else np.empty((0, vocab.size), np.int8)
    y = np.array([r["label"] for r in records], dtype=np.int8)
    np.savez_compressed(
        DATASET_PATH, X=X, y=y,
        sha256=np.array([r["sha256"] for r in records], dtype=object),
        source_id=np.array([str(r.get("source_id")) for r in records], dtype=object),
        subclass=np.array([r.get("subclass") or "" for r in records], dtype=object),
        family=np.array([r.get("family") or "" for r in records], dtype=object),
        group=np.array([r.get("group") for r in records], dtype=object),
        plausible=np.array([r["_plausible"] for r in records], dtype=bool),
        vocab_path=str(VOCAB_PATH),
    )
    SKIPS_PATH.write_text(json.dumps(
        {"n_rows": len(records), "n_malware": int(y.sum()),
         "n_benign": int((y == 0).sum()), "vocab_size": vocab.size,
         "implausible_density_rows": skipped_implausible}, indent=2))
    print(f"wrote {DATASET_PATH} — X {X.shape}, "
          f"{int(y.sum())} malware / {int((y == 0).sum())} benign, "
          f"{skipped_implausible} rows below the density floor")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="stage", required=True)
    sub.add_parser("extract", help="run extract_from_apk over the corpus (slow, resumable)")
    b = sub.add_parser("build", help="build vocabulary + matrix from the cache (fast)")
    b.add_argument("--min-df", type=int, default=5)
    b.add_argument("--max-df-ratio", type=float, default=0.98)
    b.add_argument("--max-features", type=int, default=20000,
                   help="cap columns to the top-N by document frequency (0 = no cap)")
    args = ap.parse_args(argv)

    if args.stage == "extract":
        stage_extract()
        return 0
    return stage_build(args.min_df, args.max_df_ratio, args.max_features or None)


if __name__ == "__main__":
    raise SystemExit(main())
