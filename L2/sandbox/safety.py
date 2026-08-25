"""L2 Sandbox: detonation safety gate.

Pre-detonation checks that block a run before the sample ever touches the
emulator, and post-detonation restoration of network/proxy state so the
next run starts clean. Kept separate from orchestrator.py so the go/no-go
gate is a single, auditable decision point.

Network isolation strategy (all rules applied INSIDE the emulator via adb):
  - NAT redirects TCP 80/443 to mitmproxy on the host (10.0.2.2)
  - OUTPUT allows: loopback, host subnet (10.0.2.0/24 — proxy + DNS + adb)
  - OUTPUT drops everything else
  - Result: malware thinks it has internet, HTTP/HTTPS goes to our proxy,
    all other outbound (C2 on weird ports, raw sockets) is silently dropped
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger(__name__)

_MIN_FREE_DISK_GB = 2.0
_ISOLATION_CHECK_HOST = "8.8.8.8"
_EMU_HOST_GW = "10.0.2.2"
_EMU_SUBNET = "10.0.2.0/24"
_PROXY_PORT = 8080


def _find_adb() -> str | None:
    found = shutil.which("adb")
    if found:
        return found
    sdk = os.environ.get("ANDROID_SDK_ROOT") or os.environ.get("ANDROID_HOME")
    if sdk:
        candidate = Path(sdk) / "platform-tools" / "adb"
        if candidate.is_file():
            return str(candidate)
    return None


class DetonationSafetyError(Exception):
    """Raised when pre-detonation safety checks fail."""

    def __init__(self, issues: list[str]) -> None:
        self.issues = issues
        super().__init__("; ".join(issues))


@dataclass
class DetonationSafety:
    """Pre/post detonation safety checks for the sandbox emulator."""

    device_serial: str | None = None
    proxy_port: int = _PROXY_PORT

    def _adb(self, *args: str) -> subprocess.CompletedProcess[str]:
        adb_bin = _find_adb()
        if not adb_bin:
            raise DetonationSafetyError(["adb not found on PATH or in ANDROID_SDK_ROOT"])
        cmd = [adb_bin]
        if self.device_serial:
            cmd.extend(["-s", self.device_serial])
        cmd.extend(args)
        return subprocess.run(cmd, capture_output=True, text=True, timeout=30)

    def _ipt(self, *args: str) -> subprocess.CompletedProcess[str]:
        return self._adb("shell", "su", "0", "iptables", *args)

    def enforce_isolation(self) -> None:
        """Apply iptables rules inside the emulator to block real internet.

        After this, the emulator can only reach:
          - loopback (127.0.0.1)
          - host subnet (10.0.2.0/24) — covers mitmproxy, DNS relay, adb
        HTTP/HTTPS is transparently redirected to mitmproxy.
        Everything else is dropped.
        """
        if not _find_adb():
            raise DetonationSafetyError(["adb not found — cannot enforce isolation"])

        proxy_dest = f"{_EMU_HOST_GW}:{self.proxy_port}"

        self._ipt("-t", "nat", "-F", "OUTPUT")
        self._ipt("-t", "nat", "-A", "OUTPUT", "-p", "tcp", "--dport", "80",
                  "-j", "DNAT", "--to-destination", proxy_dest)
        self._ipt("-t", "nat", "-A", "OUTPUT", "-p", "tcp", "--dport", "443",
                  "-j", "DNAT", "--to-destination", proxy_dest)

        # Chain creation + jump wiring is idempotent: `-N` on an existing
        # chain and `-D` on an absent rule both return non-zero, which
        # `_ipt()` does not treat as fatal. The `-D` before `-I` prevents
        # duplicate jump rules accumulating across repeated calls (one per
        # detonation run).
        self._ipt("-N", "st_OUTPUT")
        self._ipt("-D", "OUTPUT", "-j", "st_OUTPUT")
        self._ipt("-I", "OUTPUT", "-j", "st_OUTPUT")

        self._ipt("-F", "st_OUTPUT")

        self._ipt("-A", "st_OUTPUT", "-o", "lo", "-j", "RETURN")
        self._ipt("-A", "st_OUTPUT", "-d", _EMU_SUBNET, "-j", "RETURN")
        self._ipt("-A", "st_OUTPUT", "-j", "DROP")

        log.info("network isolation enforced — only host subnet + proxy reachable")

    def pre_check(self) -> list[str]:
        """Return a list of blocking structural issues, checked before any
        isolation is attempted. Empty list means safe to proceed to
        ``enforce_isolation()``.

        Deliberately does NOT check network reachability -- that can only
        ever be "not yet isolated" at this point, since isolation hasn't
        been enforced yet. See ``verify_isolation()`` for the post-enforce
        check.
        """
        issues: list[str] = []

        if self.device_serial and not self.device_serial.startswith("emulator-"):
            issues.append(
                f"device {self.device_serial!r} does not appear to be an "
                "emulator (missing 'emulator-' prefix) -- refusing to detonate "
                "on what may be a physical device"
            )

        try:
            usage = shutil.disk_usage("/")
            free_gb = usage.free / (1024 ** 3)
            if free_gb < _MIN_FREE_DISK_GB:
                issues.append(
                    f"only {free_gb:.2f}GB free on host disk (need "
                    f">= {_MIN_FREE_DISK_GB}GB for detonation artifacts)"
                )
        except OSError as exc:
            log.warning("disk space check failed: %s", exc)

        return issues

    def verify_isolation(self) -> list[str]:
        """Verify isolation is actually in effect. Call AFTER
        ``enforce_isolation()`` and ``ProxyManager.up()`` have run.

        Two checks, both fail-closed:
          - negative: ping to a real-internet host must NOT succeed.
          - positive: the guest must be able to reach the proxy path, so a
            "block everything including the proxy" misconfiguration isn't
            mistaken for successful isolation.

        Empty list means isolation verified. A ping that fails or times out
        is the *safe* outcome and is not an issue.
        """
        issues: list[str] = []

        if not _find_adb():
            issues.append("adb not found -- cannot verify network isolation")
            return issues

        try:
            ping = self._adb(
                "shell", "ping", "-c", "1", "-W", "2", _ISOLATION_CHECK_HOST,
            )
            if ping.returncode == 0:
                issues.append(
                    "emulator still has live internet access (ping to "
                    f"{_ISOLATION_CHECK_HOST} succeeded) -- isolation is not "
                    "in effect"
                )
        except (subprocess.TimeoutExpired, OSError) as exc:
            log.warning("isolation ping check could not run: %s", exc)

        try:
            # AOSP/toybox images ship no `curl` -- `adb shell which curl` is
            # empty even on API 30+, so a curl-based check fails closed with
            # exit 127 ("not found") on every device, not just misconfigured
            # ones. `nc` (toybox netcat) is present everywhere `sh` is; a TCP
            # connect through it (fed empty stdin so it doesn't block waiting
            # for input) is enough to prove the proxy path is open.
            probe = self._adb(
                "shell",
                f"echo | nc -w 2 -q 1 {_EMU_HOST_GW} {self.proxy_port}",
            )
            if probe.returncode != 0:
                issues.append(
                    f"proxy path unreachable -- nc to {_EMU_HOST_GW}:"
                    f"{self.proxy_port} through the guest failed "
                    f"(exit {probe.returncode}): {probe.stderr.strip()}"
                )
        except (subprocess.TimeoutExpired, OSError) as exc:
            issues.append(f"proxy path check could not run: {exc}")

        return issues

    def post_restore(self) -> None:
        """Restore the emulator's network state after a detonation run."""
        if not _find_adb():
            log.warning("adb not found -- skipping post-detonation restore")
            return

        self._ipt("-t", "nat", "-F", "OUTPUT")
        self._ipt("-F", "st_OUTPUT")
        self._ipt("-D", "OUTPUT", "-j", "st_OUTPUT")

        self._adb("shell", "settings", "put", "global", "http_proxy", ":0")
        self._adb("shell", "settings", "delete", "global", "global_http_proxy_host")
        self._adb("shell", "settings", "delete", "global", "global_http_proxy_port")

        log.info("detonation safety restoration complete")
