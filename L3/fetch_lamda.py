"""Fetch the LAMDA subset L3 trains on.

    source source_env.sh
    $SENTINEL_PYTHON L3/fetch_lamda.py

Pulls only ``Baseline/`` (341 MB) rather than the full 3.23 GB repository. The
NPZ and variance-thresholded variants are alternate encodings of the same
samples; ``Baseline/`` is the one that ships ``feature_mapping.csv``, and that
file is what makes the whole layer possible — without it the parquet columns
are opaque indices and a model trained on them could never be applied to one of
our APKs.

Goes to ``$SENTINEL_DATA_ROOT`` (the 276 GB shared partition), not the repo.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DATA_ROOT = Path(os.environ.get("SENTINEL_DATA_ROOT", REPO_ROOT))
DEST = DATA_ROOT / "lamda"

REPO_ID = "IQSeC-Lab/LAMDA"
PATTERNS = ["Baseline/*", "metadata.csv", "README.md"]


def fetch(dest: Path = DEST, workers: int = 4) -> Path:
    try:
        from huggingface_hub import snapshot_download
    except ImportError:
        raise SystemExit("pip install huggingface_hub")

    print(f"fetching {REPO_ID} ({', '.join(PATTERNS)}) -> {dest}")
    path = snapshot_download(REPO_ID, repo_type="dataset",
                             allow_patterns=PATTERNS,
                             local_dir=str(dest), max_workers=workers)
    mapping = Path(path) / "Baseline" / "feature_mapping.csv"
    if not mapping.is_file():
        raise SystemExit(
            f"{mapping} is missing — without the vocabulary the parquet "
            "columns are opaque and L3 cannot be applied to our samples.")
    years = sorted(p.name for p in (Path(path) / "Baseline").iterdir() if p.is_dir())
    print(f"  years: {', '.join(years)}")
    print(f"  vocabulary: {sum(1 for _ in mapping.open()) - 1} features")
    return Path(path)


if __name__ == "__main__":
    fetch()
