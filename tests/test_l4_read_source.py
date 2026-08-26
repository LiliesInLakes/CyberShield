"""L4 read_source must resolve L1 dex-scan locations to jadx source files.

Regression guard for the bug where every `classesN.dex!com/foo/Bar` finding
location read as "source not available", so L4 analysed zero classes.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from L4.deobfuscate import _dex_location_to_source_rel, read_source  # noqa: E402


def _make_jadx_tree(tmp_path: Path) -> Path:
    src = tmp_path / "jadx_src"
    (src / "sources" / "com" / "foo").mkdir(parents=True)
    (src / "sources" / "com" / "foo" / "Bar.java").write_text("class Bar { void x(){} }")
    return src


def test_dex_location_maps_to_outer_source_file():
    assert _dex_location_to_source_rel("classes.dex!com/foo/Bar") == "com/foo/Bar.java"
    assert _dex_location_to_source_rel("classes2.dex!com/foo/Bar$Inner$1") == "com/foo/Bar.java"
    assert _dex_location_to_source_rel("com.foo.Bar") == "com/foo/Bar.java"       # dotted
    assert _dex_location_to_source_rel("sources/com/foo/Bar.java") is None        # already a file
    assert _dex_location_to_source_rel("classes.dex") is None                     # not class-shaped


def test_read_source_resolves_dex_location(tmp_path):
    src = _make_jadx_tree(tmp_path)
    # the exact format L1 emits, including a nested-class suffix
    assert read_source(src, "classes.dex!com/foo/Bar$Inner") == "class Bar { void x(){} }"
    assert read_source(src, "classes2.dex!com/foo/Bar") is not None


def test_read_source_still_handles_plain_paths(tmp_path):
    src = _make_jadx_tree(tmp_path)
    assert read_source(src, "sources/com/foo/Bar.java") is not None
    assert read_source(src, "com/foo/Bar.java") is not None
    assert read_source(src, "com/foo/DoesNotExist") is None
