"""Debug utility: Inspect raw pipeline artifacts for a given APK.

Walks all layer directories (L0, L1, L2) for a SHA256 and dumps a
quick structural overview of every JSON artifact found. Useful for
verifying that each layer actually produced output and eyeballing
field-level data without opening files manually.

Usage:
    python -m tools.debug.inspect_evidence <sha256_or_apk_path>
    python tools/debug/inspect_evidence.py <sha256_or_apk_path>
"""

import json
import sys
import hashlib
from pathlib import Path

_REPO = Path(__file__).resolve().parent.parent.parent

LAYERS = [
    # The merged spine first — it is the record downstream layers actually read.
    # The per-layer files below it are the raw output it was built from.
    ("SPINE", _REPO / "artifacts"),
    ("L0", _REPO / "L0" / "artifacts"),
    ("L1", _REPO / "L1" / "artifacts"),
    ("L2", _REPO / "L2" / "artifacts"),
]


def _sha_if_file(arg: str) -> str:
    """If `arg` is a file path, compute its SHA256; otherwise treat it as a hash."""
    p = Path(arg)
    if p.exists() and p.is_file():
        h = hashlib.sha256()
        with p.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()
    return arg


def _json_overview(data, depth: int = 0, max_depth: int = 2) -> str:
    """Return a compact structural representation of a JSON value."""
    indent = "  " * depth
    if isinstance(data, dict):
        if depth >= max_depth:
            return f"{{{len(data)} keys}}"
        lines = []
        for k, v in list(data.items())[:15]:
            lines.append(f"{indent}  {k}: {_json_overview(v, depth + 1, max_depth)}")
        if len(data) > 15:
            lines.append(f"{indent}  ... ({len(data) - 15} more keys)")
        return "{\n" + "\n".join(lines) + f"\n{indent}" + "}"
    elif isinstance(data, list):
        if not data:
            return "[]"
        return f"[{len(data)} items, first={_json_overview(data[0], depth + 1, max_depth)}]"
    elif isinstance(data, str):
        if len(data) > 60:
            return f'"{data[:57]}..."'
        return f'"{data}"'
    else:
        return str(data)


def inspect(sha256: str):
    print(f"\n🔍 Inspecting artifacts for: {sha256[:16]}...\n")
    found_any = False

    for layer_name, base_dir in LAYERS:
        layer_dir = base_dir / sha256
        if not layer_dir.exists():
            print(f"  [{layer_name}] ❌  No artifacts directory")
            continue

        json_files = sorted(layer_dir.glob("*.json"))
        if not json_files:
            print(f"  [{layer_name}] ⚠️   Directory exists but no JSON files")
            continue

        found_any = True
        for jf in json_files:
            size_kb = jf.stat().st_size / 1024
            print(f"  [{layer_name}] ✅  {jf.name} ({size_kb:.1f} KB)")
            try:
                data = json.loads(jf.read_text())
                print(f"         {_json_overview(data)}")
            except json.JSONDecodeError:
                print(f"         ⚠️  Invalid JSON!")
            print()

    if not found_any:
        print("  No artifacts found for this SHA256 in any layer.")
        print(f"  Searched: {', '.join(l[0] for l in LAYERS)}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python tools/debug/inspect_evidence.py <sha256_or_apk_path>")
        sys.exit(1)

    sha = _sha_if_file(sys.argv[1])
    inspect(sha)
