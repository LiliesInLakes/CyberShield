"""Reclaim decompiler output that no layer needs any more.

    source source_env.sh
    $SENTINEL_PYTHON tools/reclaim_disk.py --dry-run
    $SENTINEL_PYTHON tools/reclaim_disk.py

Why this exists, given ``corpus_run.py`` already disposes of ``jadx_src``:

``corpus_run.py --keep-decompiled none`` reclaims correctly, and did — the
corpus run left no residue. The leak comes from the *other* entry point.
Running ``L1/l1.py <apk>`` directly has no disposal policy at all, because a
single manual run is usually one you want the sources for. Eight such runs on
the test apps had accumulated 904 MB, three of them 411 / 294 / 143 MB, against
13.8 GB free on ``/``.

So the fix is not to make ``l1.py`` delete its own output — that would sabotage
the debugging workflow the output exists for. It is to make the residue easy to
find and drop on purpose. That is this file.

**What is safe to delete.** ``jadx_src`` is a pure function of the APK and the
jadx version: re-running L1 regenerates it. Nothing reads it back — the
findings were extracted at scan time and live in ``analysis.json`` and the
spine. ``analysis.json`` records its path in ``artifacts.decompiled_src``, which
becomes a dangling reference; that is why ``--dry-run`` reports the count.

Deleting the *findings* is never in scope here. This tool touches only
regenerable intermediate output, never ``analysis.json``, never a spine, and
never a sample.
"""

from __future__ import annotations

import argparse
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# Regenerable intermediate output, keyed by the layer directory that holds it.
# Each entry is (artifacts root, directory name produced per sample).
RECLAIMABLE: tuple[tuple[Path, str], ...] = (
    (REPO_ROOT / "L1" / "artifacts", "jadx_src"),
    (REPO_ROOT / "L1" / "artifacts", "ghidra_out"),
    (REPO_ROOT / "L1" / "artifacts", "native_libs"),
)


@dataclass
class Target:
    path: Path
    bytes: int

    @property
    def sha256(self) -> str:
        return self.path.parent.name

    @property
    def kind(self) -> str:
        return self.path.name


def tree_bytes(path: Path) -> int:
    """Bytes on disk under ``path``, following no symlinks."""
    total = 0
    for entry in path.rglob("*"):
        try:
            if entry.is_file() and not entry.is_symlink():
                total += entry.stat().st_size
        except OSError:
            continue
    return total


def find_targets() -> list[Target]:
    targets: list[Target] = []
    for root, name in RECLAIMABLE:
        if not root.is_dir():
            continue
        for sample_dir in sorted(root.iterdir()):
            candidate = sample_dir / name
            if candidate.is_dir() and not candidate.is_symlink():
                targets.append(Target(candidate, tree_bytes(candidate)))
    return targets


def human(n: float) -> str:
    for unit in ("B", "KB", "MB"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024.0
    return f"{n:.1f} GB"


def free_gb(path: Path = REPO_ROOT) -> float:
    usage = shutil.disk_usage(path)
    return usage.free / (1 << 30)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--dry-run", action="store_true",
                        help="report what would be reclaimed, delete nothing")
    parser.add_argument("--min-bytes", type=int, default=0,
                        help="ignore trees smaller than this (default: all)")
    args = parser.parse_args(argv)

    targets = [t for t in find_targets() if t.bytes >= args.min_bytes]
    if not targets:
        print(f"Nothing to reclaim. {free_gb():.1f} GB free.")
        return 0

    total = sum(t.bytes for t in targets)
    verb = "Would reclaim" if args.dry_run else "Reclaiming"
    print(f"{verb} {len(targets)} tree(s), {human(total)}:\n")
    for t in sorted(targets, key=lambda t: -t.bytes):
        print(f"  {human(t.bytes):>10}  {t.kind}  {t.sha256[:16]}…")

    if args.dry_run:
        print(f"\n{free_gb():.1f} GB free now; {free_gb() + total / (1 << 30):.1f} GB after.")
        print("Re-run without --dry-run to reclaim. L1 regenerates these on demand.")
        return 0

    reclaimed = 0
    failed = 0
    for t in targets:
        try:
            shutil.rmtree(t.path)
            reclaimed += t.bytes
        except OSError as exc:
            print(f"  ! failed {t.path}: {exc}", file=sys.stderr)
            failed += 1

    print(f"\nReclaimed {human(reclaimed)}. {free_gb():.1f} GB free.")
    if failed:
        print(f"{failed} tree(s) could not be removed.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
