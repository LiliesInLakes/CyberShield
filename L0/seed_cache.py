from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ingest  # noqa: E402


def seed_from_repo(repo_apk_dir: Path, cache_path: Path) -> dict:
    """Seed threat_cache.json from a MalwareDatabase-style repo.

    The repo stores samples as <sha256>.zip under per-family folders.
    Filenames are the sample sha256, so we tag reputation offline without
    ever unpacking live malware.
    """
    if not repo_apk_dir.exists():
        raise SystemExit(f"Repo APK dir not found: {repo_apk_dir}")

    cache = ingest.load_threat_cache()
    hashes = cache.setdefault("hashes", {})

    added = 0
    for zip_path in sorted(repo_apk_dir.rglob("*.zip")):
        sha = zip_path.stem.lower()
        if len(sha) != 64:
            continue
        family = zip_path.parent.name
        if sha in hashes:
            # Merge family tag if missing.
            if "families" not in hashes[sha]:
                hashes[sha]["families"] = []
            if family not in hashes[sha]["families"]:
                hashes[sha]["families"].append(family)
            continue
        hashes[sha] = {
            "verdict": "known_malware",
            "families": [family],
            "note": f"MalwareDatabase family: {family}",
            "tags": ["malware", family.lower()],
        }
        added += 1

    cache["description"] = (
        "Local offline threat cache for L0 reputation lookups. Maps sha256 -> record. "
        "On-prem safe: no data leaves the perimeter. Seeded from MalwareDatabase repo "
        "(filenames are sample sha256). Optional VirusTotal/MalwareBazaar enrichment runs "
        "only when respective key is set."
    )
    with cache_path.open("w") as fh:
        json.dump(cache, fh, indent=2)
    return {"added": added, "total": len(hashes)}


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description="Seed L0 threat_cache.json from MalwareDatabase-style repo (sha256 filenames).")
    p.add_argument("--repo", default=str(Path(ingest.L0_DIR).parent / "datasets" / "MalwareDatabase" / ".apk"),
                   help="Path to .apk dir of the cloned repo.")
    p.add_argument("--cache", default=str(ingest.CACHE_PATH), help="threat_cache.json to write.")
    args = p.parse_args(argv[1:])

    result = seed_from_repo(Path(args.repo), Path(args.cache))
    print(f"Seeded threat_cache.json: +{result['added']} new, {result['total']} total hashes.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
