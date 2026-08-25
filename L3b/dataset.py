"""Build the L3b training matrix from the labelled corpus.

    source source_env.sh
    $SENTINEL_PYTHON L3b/dataset.py --out L3b/model/dataset.npz

Population: malware = every ``corpus/labels.json`` entry with
``class == "malware"`` and ``subclass == "banking"`` (CICMalDroid's banking
split, plus any future targeted AndroZoo/MalRadar pull registered the same
way); benign = every entry with ``class == "benign"`` (today, entirely
``benign_fdroid`` — see T27: this inherits the "zero commercial banking apps"
gap and cannot validate a banking false-positive rate).

Each sample needs two things already on disk: a spine at
``artifacts/<sha256>/evidence.json`` (from ``tools/corpus_run.py``, so L0's
impersonation block exists for ``L3b/features_ext.py``) and the raw APK at
``identity.source_apk`` (for ``L3/features.py``'s LAMDA bridge, which reads
the APK directly). A sample missing either is skipped and counted, not
silently dropped — the counts are what tells you whether the corpus_run step
actually finished.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import spine  # noqa: E402
from L3.features import Vocabulary, extract_from_apk, vectorise  # noqa: E402
from L3b.features_ext import FEATURE_NAMES, concatenate, extract_from_spine  # noqa: E402
from L3b.family_labels import (  # noqa: E402
    FamilyLabel, attach_family, load_l0_dataset_families, load_malradar_families,
)
from tools import corpus_labels  # noqa: E402


@dataclass
class SkipCounts:
    no_spine: int = 0
    l0_incomplete: int = 0
    no_source_apk: int = 0
    apk_missing_on_disk: int = 0
    implausible_density: int = 0

    def as_dict(self) -> dict[str, int]:
        return {k: v for k, v in self.__dict__.items()}


def select_population(labels: dict[str, dict[str, Any]]) -> tuple[list[str], list[str]]:
    """(malware_shas, benign_shas) — the two populations L3b trains on."""
    malware = [sha for sha, e in labels.items()
              if e.get("class") == "malware" and e.get("subclass") == "banking"]
    benign = [sha for sha, e in labels.items() if e.get("class") == "benign"]
    return sorted(malware), sorted(benign)


def build(*, vocab: Vocabulary | None = None,
         verbose: bool = True) -> tuple[np.ndarray, np.ndarray, list[FamilyLabel], SkipCounts]:
    """Returns (X, y, family_labels, skip_counts). X rows align with y and family_labels."""
    vocab = vocab or Vocabulary.load()
    labels = corpus_labels.load()["labels"]
    malware_shas, benign_shas = select_population(labels)

    verified = {**load_l0_dataset_families(), **load_malradar_families()}

    rows: list[np.ndarray] = []
    ys: list[int] = []
    fam_labels: list[FamilyLabel] = []
    skips = SkipCounts()

    for sha_list, y_value, source in ((malware_shas, 1, "malware_banking"),
                                      (benign_shas, 0, "benign")):
        for sha in sha_list:
            doc = spine.load_spine(sha)
            if not doc.get("layers"):
                skips.no_spine += 1
                continue
            impersonation = extract_from_spine(doc)
            if not impersonation.available:
                skips.l0_incomplete += 1
                continue

            apk_path = (doc.get("identity") or {}).get("source_apk")
            if not apk_path:
                skips.no_source_apk += 1
                continue
            apk_path = Path(apk_path)
            if not apk_path.is_file():
                skips.apk_missing_on_disk += 1
                continue

            extraction = extract_from_apk(apk_path)
            lamda_vec, diag = vectorise(extraction, vocab)
            if not diag["plausible"]:
                skips.implausible_density += 1
                continue

            rows.append(concatenate(lamda_vec, impersonation.vector))
            ys.append(y_value)
            fam_labels.append(attach_family(sha, source=source, verified_map=verified))

    if verbose:
        print(f"malware candidates: {len(malware_shas)}  "
              f"benign candidates: {len(benign_shas)}")
        print(f"usable rows: {len(rows)}   skipped: {skips.as_dict()}")

    if not rows:
        X = np.empty((0, vocab.size + len(FEATURE_NAMES)), dtype=np.float32)
    else:
        X = np.stack(rows).astype(np.float32)
    return X, np.array(ys, dtype=np.int8), fam_labels, skips


def main(argv: list[str] | None = None) -> int:
    import argparse

    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", default=str(REPO_ROOT / "L3b" / "model" / "dataset.npz"))
    args = ap.parse_args(argv)

    try:
        from loguru import logger
        logger.remove()
    except Exception:  # noqa: BLE001
        pass

    X, y, fam_labels, skips = build()
    if X.shape[0] == 0:
        print("no usable rows — has tools/corpus_run.py been run over the "
              "banking corpus yet? see CLAUDE.md section on CICMalDroid "
              "registration", file=sys.stderr)
        return 1

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    np.savez_compressed(
        out, X=X, y=y,
        sha256=np.array([f.sha256 for f in fam_labels], dtype=object),
        family=np.array([f.family or "" for f in fam_labels], dtype=object),
        tier=np.array([f.tier for f in fam_labels], dtype=object),
    )
    (out.parent / "dataset_skips.json").write_text(json.dumps(skips.as_dict(), indent=2))
    print(f"wrote {out} — X {X.shape}, {int(y.sum())} malware / "
          f"{int((y == 0).sum())} benign")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
