"""Attach a family label, and an honest confidence tier, to each L3b sample.

B37's own finding is the reason this module exists: "banking families are
small and tightly clustered, so a random split trains and tests on variants of
one family and reports an AUROC that means nothing." A family-disjoint split
needs a real family per sample — and today, most of what feeds L3b does not
have one. Only some of it does:

* **verified** — a sha256 that matches a hand-labelled family, either the 56
  samples under ``L0/dataset/<family>/<sha256>/`` or (once Zenodo access
  lands) a row in MalRadar's expert-verified CSV. This is the only tier
  trustworthy enough to compute the headline family-disjoint metric from.
* **weak_hint** — reserved for a per-sample family assumption baked into how a
  sample was *selected* rather than verified against the sample itself (the
  ``corpus_labels.py`` docstring's own example is "an AndroZoo pull filtered
  by AVClass family"). Currently unpopulated: AndroZoo's index exposes only a
  VirusTotal detection *count*, not per-vendor label strings, so there is no
  live source to run AVClass against, and this project has no verified source
  of current banking-trojan package-name prefixes to filter on instead (real
  ones are typically randomised/short-lived per campaign — see
  ``tools/androzoo_banking_targets.py``, which fetches a cited family
  *taxonomy* for documentation but deliberately does not guess prefixes). The
  tier stays defined so a future source can slot in without a schema change.
* **unknown** — everything else. CICMalDroid's banking split ships five coarse
  classes and no family field at all.

``unknown``-tier samples still train the model — excluding them would throw
away most of the malware-side data — but they must never be the numerator or
denominator of the reported held-out metric, or the metric silently becomes
the random split B37 already ruled out.
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

DATA_ROOT = Path(os.environ.get("SENTINEL_DATA_ROOT", REPO_ROOT))
L0_DATASET_DIR = REPO_ROOT / "L0" / "dataset"
MALRADAR_CSV = DATA_ROOT / "malradar" / "sample-info.csv"

Tier = Literal["verified", "weak_hint", "unknown"]


@dataclass(frozen=True)
class FamilyLabel:
    sha256: str
    family: str | None
    tier: Tier
    source: str


def load_l0_dataset_families(root: Path = L0_DATASET_DIR) -> dict[str, str]:
    """sha256 -> family, from the hand-labelled samples already in the repo.

    Directory name is the family; sha256 is the per-sample subdirectory name.
    This is metadata-only (icon + meta.json) — no APK bytes live here — so
    reading it is cheap and needs no corpus_run.
    """
    out: dict[str, str] = {}
    if not root.is_dir():
        return out
    for family_dir in sorted(root.iterdir()):
        if not family_dir.is_dir():
            continue
        family = family_dir.name
        for sample_dir in family_dir.iterdir():
            if not sample_dir.is_dir():
                continue
            sha = sample_dir.name.lower()
            if len(sha) >= 64 and all(c in "0123456789abcdef" for c in sha[:64]):
                out[sha[:64]] = family
    return out


def load_malradar_families(path: Path = MALRADAR_CSV) -> dict[str, str]:
    """sha256 -> family, from MalRadar's expert-verified CSV.

    Returns empty until Zenodo access lands and the CSV is placed at
    ``$SENTINEL_DATA_ROOT/malradar/sample-info.csv`` — this function does not
    fail when it is absent, because "not yet available" is a normal state, not
    an error, for every population upstream of it.
    """
    import csv

    out: dict[str, str] = {}
    if not path.is_file():
        return out
    with path.open(newline="") as fh:
        for row in csv.DictReader(fh):
            sha = (row.get("sha256") or row.get("hash") or "").lower()
            family = row.get("family") or row.get("malware_family")
            if sha and family:
                out[sha] = family
    return out


def attach_family(sha256: str, *, source: str,
                  verified_map: dict[str, str] | None = None,
                  weak_hint_map: dict[str, str] | None = None) -> FamilyLabel:
    """One sample -> its best-available family label and confidence tier.

    ``verified_map`` is the union of the L0/dataset and MalRadar lookups.
    ``weak_hint_map`` is keyed the same way but sourced from the AndroZoo
    package-prefix bucket a sample was selected through (see
    ``tools/androzoo_banking_targets.py``); a sha256 present in both is
    reported at its higher (verified) tier.
    """
    sha256 = sha256.lower()
    verified_map = verified_map or {}
    weak_hint_map = weak_hint_map or {}

    if sha256 in verified_map:
        return FamilyLabel(sha256=sha256, family=verified_map[sha256],
                           tier="verified", source=source)
    if sha256 in weak_hint_map:
        return FamilyLabel(sha256=sha256, family=weak_hint_map[sha256],
                           tier="weak_hint", source=source)
    return FamilyLabel(sha256=sha256, family=None, tier="unknown", source=source)


@dataclass(frozen=True)
class FamilySplit:
    train_ids: tuple[str, ...]
    test_ids: tuple[str, ...]
    status: Literal["verified", "unverified_pending_malradar"]
    held_out_families: tuple[str, ...]


def split_family_disjoint(labels: list[FamilyLabel], *, seed: int = 20260818,
                          test_fraction: float = 0.25,
                          min_families_for_split: int = 4) -> FamilySplit:
    """Hold out whole families, never individual samples within one.

    Only ``verified``-tier families are eligible to be held out — the metric
    computed against the resulting ``test_ids`` is the one that can honestly
    be called family-disjoint. ``weak_hint`` and ``unknown`` samples always go
    to train: they reinforce the model but must never appear in the
    metric-computing partition, or an unverified assumption would be reported
    as a measured result.

    If fewer than ``min_families_for_split`` verified families exist (each
    needing >=2 samples to make holding one out meaningful), there is no
    honest split to report: everything goes to train and ``status`` says so
    plainly rather than fabricating a split from weak or unknown labels.
    """
    import random

    by_family: dict[str, list[str]] = {}
    always_train: list[str] = []
    for lab in labels:
        if lab.tier == "verified" and lab.family:
            by_family.setdefault(lab.family, []).append(lab.sha256)
        else:
            always_train.append(lab.sha256)

    eligible = {fam: ids for fam, ids in by_family.items() if len(ids) >= 2}
    if len(eligible) < min_families_for_split:
        all_ids = tuple(always_train + [s for ids in by_family.values() for s in ids])
        return FamilySplit(train_ids=all_ids, test_ids=(),
                           status="unverified_pending_malradar",
                           held_out_families=())

    rng = random.Random(seed)
    families = sorted(eligible)
    rng.shuffle(families)
    n_hold_out = max(1, round(len(families) * test_fraction))
    held_out = families[:n_hold_out]
    kept = families[n_hold_out:]

    test_ids = [s for fam in held_out for s in eligible[fam]]
    train_ids = (always_train
                + [s for fam in kept for s in eligible[fam]]
                # families with a single verified sample can't be held out
                # meaningfully, so they train too
                + [s for fam, ids in by_family.items()
                   if fam not in eligible for s in ids])
    return FamilySplit(train_ids=tuple(train_ids), test_ids=tuple(test_ids),
                       status="verified", held_out_families=tuple(held_out))
