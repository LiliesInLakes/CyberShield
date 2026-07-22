from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path
from typing import Any, Callable

_log = logging.getLogger(__name__)


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def cached_analysis(artifacts_root: Path, sha256: str, layer: str) -> dict | None:
    evidence_path = artifacts_root / sha256 / "evidence.json"
    if not evidence_path.exists():
        return None
    try:
        evidence = json.loads(evidence_path.read_text())
        layer_data = evidence.get(layer, {})
        if layer_data.get("status") == "complete":
            _log.info("Cache HIT for %s/%s (%s)", sha256[:12], layer)
            return layer_data
    except (json.JSONDecodeError, KeyError):
        pass
    return None


def cached_l1_analysis(artifacts_root: Path, sha256: str) -> dict | None:
    analysis_path = artifacts_root / sha256 / "analysis.json"
    if analysis_path.exists():
        try:
            _log.info("Cache HIT for L1 analysis (%s)", sha256[:12])
            return json.loads(analysis_path.read_text())
        except (json.JSONDecodeError, IOError):
            pass
    return None
