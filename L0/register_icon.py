from __future__ import annotations

import argparse
import io
import json
import sys
from pathlib import Path

from androguard.core.apk import APK
from PIL import Image
import imagehash

L0_DIR = Path(__file__).resolve().parent
WHITELIST_PATH = L0_DIR / "bank_whitelist.json"


def phash_from_apk(apk_path: Path) -> str:
    apk = APK(str(apk_path))
    icon_path = apk.get_app_icon()
    if not icon_path:
        raise SystemExit(f"No application icon found in {apk_path}")
    data = apk.get_file(icon_path)
    if not data:
        raise SystemExit(f"Icon resource missing: {icon_path}")
    img = Image.open(io.BytesIO(data)).convert("RGB")
    return str(imagehash.phash(img))


def phash_from_image(img_path: Path) -> str:
    img = Image.open(img_path).convert("RGB")
    return str(imagehash.phash(img))


def register(bank_name: str, source: Path) -> None:
    source = Path(source)
    if source.suffix.lower() == ".apk":
        phash = phash_from_apk(source)
    else:
        phash = phash_from_image(source)

    if not WHITELIST_PATH.exists():
        raise SystemExit(f"Whitelist not found at {WHITELIST_PATH}")
    with WHITELIST_PATH.open() as fh:
        wl = json.load(fh)

    matched = False
    for bank in wl.get("banks", []):
        if bank.get("bank_name", "").lower() == bank_name.lower():
            bank["icon_phash"] = phash
            matched = True
            break
    if not matched:
        raise SystemExit(f"Bank '{bank_name}' not found in whitelist. Add it first.")

    with WHITELIST_PATH.open("w") as fh:
        json.dump(wl, fh, indent=2)
    print(f"Registered icon_phash={phash} for {bank_name}")


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description="Register trusted bank icon pHash into L0 whitelist.")
    p.add_argument("bank_name", help="Exact bank_name as listed in bank_whitelist.json")
    p.add_argument("source", help="Official APK file or icon PNG/JPG")
    args = p.parse_args(argv[1:])
    register(args.bank_name, Path(args.source))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
