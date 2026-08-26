"""The L1 artifacts root has two definitions, and they must not drift.

``L1/l1.py`` decides where L1 writes; ``tools/reclaim_disk.py`` decides where to
look for the regenerable trees to delete. The second duplicates the first rather
than importing it, deliberately — reclaiming disk has to work when L1's own
dependencies do not, which is precisely the moment you are out of space.

The failure mode is silent in the worst direction: if the two disagree,
``reclaim_disk`` walks an empty path, prints "nothing to reclaim", and the
gigabytes it was written to find sit untouched somewhere else. Nothing errors.

Run:  ./env/bin/python -m pytest tests/test_artifacts_root.py -q
"""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "L1"))
sys.path.insert(0, str(REPO_ROOT / "tools"))

ENV_VAR = "SENTINEL_L1_ARTIFACTS"


def _roots(monkeypatch, value: str | None) -> tuple[Path, Path]:
    """Both definitions, re-resolved under the given environment."""
    if value is None:
        monkeypatch.delenv(ENV_VAR, raising=False)
    else:
        monkeypatch.setenv(ENV_VAR, value)
    import l1
    import reclaim_disk
    importlib.reload(l1)
    importlib.reload(reclaim_disk)
    return l1.ARTIFACTS, reclaim_disk.L1_ARTIFACTS


def test_roots_agree_by_default(monkeypatch):
    l1_root, reclaim_root = _roots(monkeypatch, None)
    assert l1_root == reclaim_root == REPO_ROOT / "L1" / "artifacts"


def test_roots_agree_when_redirected(monkeypatch, tmp_path):
    target = tmp_path / "elsewhere" / "l1_artifacts"
    l1_root, reclaim_root = _roots(monkeypatch, str(target))
    assert l1_root == reclaim_root == target


def test_reclaimable_follows_the_redirect(monkeypatch, tmp_path):
    """The tuple reclaim_disk actually walks, not just the constant."""
    target = tmp_path / "l1_artifacts"
    monkeypatch.setenv(ENV_VAR, str(target))
    import reclaim_disk
    importlib.reload(reclaim_disk)
    assert {root for root, _ in reclaim_disk.RECLAIMABLE} == {target}
    assert {name for _, name in reclaim_disk.RECLAIMABLE} == {
        "jadx_src", "ghidra_out", "native_libs",
    }


def test_redirect_does_not_move_the_spine(monkeypatch, tmp_path):
    """Everything downstream of L1 reads the spine, which must stay put.

    If a redirect ever dragged the spine onto a scratch filesystem with it, the
    corpus would appear to lose every sample already measured.
    """
    monkeypatch.setenv(ENV_VAR, str(tmp_path / "l1_artifacts"))
    import spine
    importlib.reload(spine)
    assert spine.SPINE_ROOT == REPO_ROOT / "artifacts"
