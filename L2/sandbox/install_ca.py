"""L2 Sandbox: mitmproxy CA installation into the Android system trust store.

Standalone helper (kept separate from orchestrator.py, which another agent
is modifying).  Converts the mitmproxy CA certificate to the Android
system-cert format (PEM body + OpenSSL-style subject-hash filename) and
pushes it into ``/system/etc/security/cacerts/`` on the attached emulator.

System-store installation (vs. user-store) is required so apps built with
Network Security Config `<certificates src="system"/>` -- the Android
default for API 24+ -- also trust the mitm CA.  This only works on an
emulator image with a writable /system (the AVD must be started with
``-writable-system``, and the run must call ``adb root`` + ``adb remount``
first).

Idempotent: re-running skips the push if the cert is already installed.

Usage:
    python install_ca.py [--serial SERIAL] [--ca-cert PATH]
"""

from __future__ import annotations

import argparse
import logging
import shutil
import subprocess
from pathlib import Path

log = logging.getLogger(__name__)

_DEFAULT_CA_CERT = Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem"
_SYSTEM_CACERTS_DIR = "/system/etc/security/cacerts"


class CAInstallError(Exception):
    """Raised when the CA cannot be installed on the device."""


def _adb(serial: str | None, *args: str, timeout: int = 30) -> subprocess.CompletedProcess[str]:
    cmd = ["adb"]
    if serial:
        cmd.extend(["-s", serial])
    cmd.extend(args)
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def _subject_hash(cert_path: Path) -> str:
    """Return the OpenSSL subject_hash_old for *cert_path* (Android's cert filename key)."""
    result = subprocess.run(
        ["openssl", "x509", "-inform", "PEM", "-subject_hash_old", "-in", str(cert_path), "-noout"],
        capture_output=True, text=True, timeout=15,
    )
    if result.returncode != 0:
        raise CAInstallError(f"openssl subject_hash_old failed: {result.stderr.strip()}")
    return result.stdout.strip().splitlines()[0]


def _cert_body(cert_path: Path) -> str:
    result = subprocess.run(
        ["openssl", "x509", "-inform", "PEM", "-in", str(cert_path)],
        capture_output=True, text=True, timeout=15,
    )
    if result.returncode != 0:
        raise CAInstallError(f"openssl x509 re-encode failed: {result.stderr.strip()}")
    return result.stdout


def is_installed(serial: str | None, cert_hash: str) -> bool:
    """Check whether ``<cert_hash>.0`` already exists in the system cacerts dir."""
    res = _adb(serial, "shell", "ls", f"{_SYSTEM_CACERTS_DIR}/{cert_hash}.0")
    return res.returncode == 0 and "No such file" not in res.stderr and "No such file" not in res.stdout


def install_ca(ca_cert: Path | None = None, serial: str | None = None) -> bool:
    """Install the mitmproxy CA into the device system trust store.

    Returns True if the CA is installed (either already present or newly
    pushed), False if installation failed.  Raises ``CAInstallError`` only
    for missing prerequisites (no adb, no openssl, no cert file).
    """
    ca_cert = ca_cert or _DEFAULT_CA_CERT

    if not shutil.which("adb"):
        raise CAInstallError("adb not found on PATH")
    if not shutil.which("openssl"):
        raise CAInstallError("openssl not found on PATH")
    if not ca_cert.exists():
        raise CAInstallError(
            f"mitmproxy CA cert not found at {ca_cert} -- run mitmproxy once "
            "to generate it (it writes ~/.mitmproxy/mitmproxy-ca-cert.pem on first start)"
        )

    cert_hash = _subject_hash(ca_cert)
    log.info("mitmproxy CA subject hash: %s", cert_hash)

    if is_installed(serial, cert_hash):
        log.info("CA already installed at %s/%s.0 -- skipping", _SYSTEM_CACERTS_DIR, cert_hash)
        return True

    android_cert = _cert_body(ca_cert)

    # adb root + remount are required for a writable /system.
    _adb(serial, "root", timeout=15)
    remount = _adb(serial, "remount", timeout=30)
    if remount.returncode != 0 and "remount succeeded" not in remount.stdout.lower():
        log.warning(
            "adb remount reported: %s -- the AVD may need to be started "
            "with -writable-system for this to succeed", remount.stdout.strip() or remount.stderr.strip(),
        )

    local_tmp = Path(f"/tmp/{cert_hash}.0")
    local_tmp.write_text(android_cert)

    push = _adb(serial, "push", str(local_tmp), f"{_SYSTEM_CACERTS_DIR}/{cert_hash}.0", timeout=30)
    local_tmp.unlink(missing_ok=True)
    if push.returncode != 0:
        log.error("failed to push CA cert: %s", push.stderr.strip())
        return False

    _adb(serial, "shell", "chmod", "644", f"{_SYSTEM_CACERTS_DIR}/{cert_hash}.0")

    if is_installed(serial, cert_hash):
        log.info("CA installed successfully at %s/%s.0", _SYSTEM_CACERTS_DIR, cert_hash)
        return True

    log.error("CA push reported success but file is not present -- check /system is writable")
    return False


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    parser = argparse.ArgumentParser(description="Install mitmproxy CA into Android system trust store")
    parser.add_argument("--serial", default=None, help="ADB device serial (default: first attached device)")
    parser.add_argument("--ca-cert", default=None, help="Path to mitmproxy-ca-cert.pem")
    args = parser.parse_args()

    try:
        ok = install_ca(
            ca_cert=Path(args.ca_cert) if args.ca_cert else None,
            serial=args.serial,
        )
    except CAInstallError as exc:
        log.error("CA install failed: %s", exc)
        return 1
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
