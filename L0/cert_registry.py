"""Cert registry — append-only trusted certificate store.

Analysts use this to mark signing certificates as verified/authentic.
The whitelist grows over time. Never shrinks automatically.

Usage:
    python cert_registry.py allow <apk_path> --bank "Bank of India"
    python cert_registry.py allow <apk_path> --bank "Bank of India" --note "Play Store Jul 2026"
    python cert_registry.py allow <icon.png> --bank "Bank of India"  # icon-only registration
    python cert_registry.py list                                      # show all verified certs
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from androguard.core.apk import APK

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ingest  # noqa: E402

L0_DIR = Path(__file__).resolve().parent
WHITELIST_PATH = L0_DIR / "bank_whitelist.json"


def _load_whitelist() -> dict:
    if not WHITELIST_PATH.exists():
        raise SystemExit(f"Whitelist not found at {WHITELIST_PATH}")
    with WHITELIST_PATH.open() as fh:
        return json.load(fh)


def _save_whitelist(wl: dict) -> None:
    with WHITELIST_PATH.open("w") as fh:
        json.dump(wl, fh, indent=2, ensure_ascii=False)


def allow(apk_path: Path, bank_name: str, note: str = "") -> dict[str, Any]:
    """Extract cert (and optionally icon pHash) from APK and register in whitelist.

    If bank_name already exists in the whitelist, updates cert_sha256 + icon_phash.
    If bank_name does not exist, appends a new entry.
    """
    apk_path = Path(apk_path)
    apk = APK(str(apk_path))

    cert_info = ingest.extract_cert_info(apk)
    if not cert_info.get("sha256_fingerprint"):
        raise SystemExit("Cannot extract certificate fingerprint from APK")

    # Also grab icon pHash while we have the APK open
    icon_info = ingest.extract_icon_phash(apk, L0_DIR / "artifacts" / "registry_tmp")
    icon_phash = icon_info.get("phash")

    wl = _load_whitelist()
    now = datetime.now(timezone.utc).isoformat()

    matched = False
    for bank in wl.get("banks", []):
        if bank.get("bank_name", "").lower() == bank_name.lower():
            bank["cert_sha256"] = cert_info["sha256_fingerprint"]
            bank["cert_verified_at"] = now
            bank["cert_note"] = note
            if icon_phash:
                bank["icon_phash"] = icon_phash
            # Also update package_name and app_label from the actual APK
            bank["package_name"] = apk.get_package() or bank.get("package_name")
            bank["app_label"] = apk.get_app_name() or bank.get("app_label")
            matched = True
            break

    if not matched:
        # Bank not in list — add new entry
        wl.setdefault("banks", []).append({
            "bank_name": bank_name,
            "package_name": apk.get_package(),
            "app_label": apk.get_app_name(),
            "alt_labels": [],
            "icon_phash": icon_phash,
            "cert_sha256": cert_info["sha256_fingerprint"],
            "cert_verified_at": now,
            "cert_note": note,
        })

    _save_whitelist(wl)

    result = {
        "bank": bank_name,
        "cert_sha256": cert_info["sha256_fingerprint"],
        "icon_phash": icon_phash,
        "package_name": apk.get_package(),
        "app_label": apk.get_app_name(),
        "action": "updated" if matched else "added",
    }
    print(f"[{'updated' if matched else 'added'}] {bank_name}")
    print(f"  cert_sha256 = {cert_info['sha256_fingerprint']}")
    print(f"  icon_phash  = {icon_phash}")
    print(f"  package     = {apk.get_package()}")
    return result


def list_verified() -> None:
    """Show all banks with verified cert fingerprints."""
    wl = _load_whitelist()
    banks = wl.get("banks", [])
    verified = [b for b in banks if b.get("cert_sha256")]
    unverified = [b for b in banks if not b.get("cert_sha256")]

    print(f"=== Verified certs: {len(verified)} / {len(banks)} banks ===\n")
    for b in verified:
        print(f"  ✓ {b.get('bank_name', '?'):30s}  cert={b['cert_sha256'][:16]}…  "
              f"pkg={b.get('package_name', '?')}")
    if unverified:
        print(f"\n--- Unverified ({len(unverified)}): ---")
        for b in unverified:
            print(f"  ✗ {b.get('bank_name', '?'):30s}  pkg={b.get('package_name', '?')}")


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(
        description="Manage the trusted certificate registry for impersonation detection.",
    )
    sub = p.add_subparsers(dest="command")

    allow_p = sub.add_parser("allow", help="Register an APK's cert as trusted for a bank.")
    allow_p.add_argument("apk", help="Path to the official bank APK")
    allow_p.add_argument("--bank", required=True, help="Exact bank_name (or new name to add)")
    allow_p.add_argument("--note", default="", help="Verification note (e.g. 'Play Store Jul 2026')")

    sub.add_parser("list", help="Show all verified and unverified banks.")

    args = p.parse_args(argv[1:])

    if args.command == "allow":
        allow(Path(args.apk), args.bank, args.note)
    elif args.command == "list":
        list_verified()
    else:
        p.print_help()
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
