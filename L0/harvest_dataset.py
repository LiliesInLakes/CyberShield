from __future__ import annotations

import argparse
import json
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ingest  # noqa: E402

from androguard.core.apk import APK  # noqa: E402

ZIP_PASSWORD = b"infected"


def open_encrypted(zip_path: Path, password: bytes = ZIP_PASSWORD):
    """Open a corpus archive, whatever it was zipped with.

    ~40% of corpus members are WinZip-AES (`compress_type 99`), which the stdlib
    cannot read at all; the rest are ZipCrypto or unencrypted. pyzipper handles
    every case, so it leads and stdlib is only the fallback for an archive
    pyzipper rejects outright.

    The caller gets an open archive and reads members **one at a time**. This
    function deliberately does not extract anything — `extractall` on a corpus
    archive puts live malware on disk in bulk, which the safety rules forbid.
    """
    import pyzipper

    try:
        zf = pyzipper.AESZipFile(str(zip_path))
    except Exception:  # noqa: BLE001 — fall back to the stdlib reader
        zf = zipfile.ZipFile(str(zip_path))
    zf.setpassword(password)
    return zf


def harvest_apk(apk_path: Path, out_root: Path, family: str | None = None) -> dict:
    apk_path = Path(apk_path)
    apk = APK(str(apk_path))

    hashes = ingest.compute_hashes(apk_path)
    manifest = ingest.harvest_manifest(apk)
    artifacts = out_root / (family or "unknown") / hashes["sha256"]
    artifacts.mkdir(parents=True, exist_ok=True)

    icon = ingest.extract_icon_phash(apk, artifacts)
    routing = ingest.track_routing(apk_path)

    meta = {
        "family": family,
        "source_file": str(apk_path),
        "fingerprint": hashes,
        "manifest": manifest,
        "icon": icon,
        "routing": routing,
    }
    (artifacts / "meta.json").write_text(json.dumps(meta, indent=2))
    return meta


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description="Harvest icon + metadata from APKs (or malware zip archives) into a local dataset.")
    p.add_argument("input", help="Folder of APKs/zips (or a single file). Subfolders = malware family labels.")
    p.add_argument("--out", default=str(ingest.L0_DIR / "dataset"), help="Output dataset root.")
    p.add_argument("--no-recurse", action="store_true", help="Do not descend into subfolders for family labels.")
    args = p.parse_args(argv[1:])

    in_root = Path(args.input)
    out_root = Path(args.out)

    items: list[tuple[Path, str | None]] = []
    if in_root.is_file():
        if in_root.suffix.lower() == ".apk":
            items.append((in_root, None))
    else:
        pattern = "**/*.apk" if not args.no_recurse else "*.apk"
        for f in sorted(in_root.glob(pattern)):
            family = f.parent.name if (not args.no_recurse and f.parent != in_root) else None
            items.append((f, family))

    if not items:
        print(f"No matching files found under {in_root}")
        return 1

    print(f"Harvesting {len(items)} item(s) -> {out_root}")
    ok = 0
    for f, family in items:
        try:
            meta = harvest_apk(f, out_root, family)
            ok += 1
            has_icon = "Y" if meta["icon"].get("present") else "N"
            print(f"  [ok] {family or '-':20} {f.name:40} icon={has_icon} sha={meta['fingerprint']['sha256'][:12]}")
        except Exception as exc:  # noqa: BLE001
            print(f"  [fail] {f.name}: {exc}")
    print(f"Done. {ok}/{len(items)} harvested.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
