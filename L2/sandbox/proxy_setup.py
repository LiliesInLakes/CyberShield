"""L2 Sandbox: System proxy setting and DNS redirection for the emulator.

Non-fail-closed extras layered on top of ``safety.py``'s DROP-all +
DNAT, which is the security-critical piece and owns the ``nat`` table's
``OUTPUT`` chain. This module deliberately does NOT touch iptables --
it used to install its own NAT REDIRECT rules for the same ports, which
duplicated ``safety.enforce_isolation()``'s DNAT rules in the same table
(order-dependent, two owners of one firewall table). That's gone; what's
left here is:

  1. System HTTP proxy setting -- belt-and-suspenders for apps that honour
     the global proxy setting and so don't even need the NAT rule.
  2. DNS redirection -- static /etc/hosts overrides for known C2
     platforms, so lookups resolve locally instead of leaking to the
     real internet even before a connection is attempted.

10.0.2.2 is the emulator's alias for the host loopback (Android
emulator NAT), which is where mitmproxy listens on port 8080.

Usage:
    python proxy_setup.py up
    python proxy_setup.py verify
    python proxy_setup.py down
"""

from __future__ import annotations

import argparse
import logging
import shutil
import subprocess
from dataclasses import dataclass

log = logging.getLogger(__name__)

HOST_PROXY_ADDR = "10.0.2.2"
HOST_PROXY_PORT = 8080

# Known C2 / telemetry hosts to blackhole or redirect to localhost.
# mtalk.google.com carries FCM's binary protobuf protocol on port 5228,
# not HTTP -- mitmproxy cannot intercept it, so it is blackholed rather
# than proxied (see mitm_addon.py header comment / CLAUDE.md T-notes).
_HOSTS_REDIRECTS: dict[str, str] = {
    "firebaseio.com": "127.0.0.1",
    "fcm.googleapis.com": "127.0.0.1",
    "api.telegram.org": "127.0.0.1",
    "mtalk.google.com": "0.0.0.0",
}

_HOSTS_MARKER_BEGIN = "# BEGIN sentinel-l2-dns-redirect"
_HOSTS_MARKER_END = "# END sentinel-l2-dns-redirect"


class ProxySetupError(Exception):
    """Raised when a proxy/DNS setup step fails outright (missing adb, etc)."""


@dataclass
class ProxyManager:
    """Manage transparent proxy + DNS redirection on an attached emulator."""

    device_serial: str | None = None

    def _adb(self, *args: str, timeout: int = 30) -> subprocess.CompletedProcess[str]:
        if not shutil.which("adb"):
            raise ProxySetupError("adb not found on PATH")
        cmd = ["adb"]
        if self.device_serial:
            cmd.extend(["-s", self.device_serial])
        cmd.extend(args)
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

    # ------------------------------------------------------------------
    # System HTTP proxy setting
    # ------------------------------------------------------------------

    def set_system_proxy(self) -> bool:
        res = self._adb(
            "shell", "settings", "put", "global", "http_proxy",
            f"{HOST_PROXY_ADDR}:{HOST_PROXY_PORT}",
        )
        if res.returncode != 0:
            log.error("failed to set global http_proxy: %s", res.stderr.strip())
            return False
        log.info("system proxy set to %s:%d", HOST_PROXY_ADDR, HOST_PROXY_PORT)
        return True

    def clear_system_proxy(self) -> bool:
        res = self._adb("shell", "settings", "put", "global", "http_proxy", ":0")
        if res.returncode != 0:
            log.error("failed to clear global http_proxy: %s", res.stderr.strip())
            return False
        log.info("system proxy cleared")
        return True

    # ------------------------------------------------------------------
    # DNS redirection via /etc/hosts
    # ------------------------------------------------------------------

    def apply_dns_redirects(self, redirects: dict[str, str] | None = None) -> bool:
        """Append blackhole/localhost entries for known C2 hosts to /etc/hosts.

        Idempotent: strips any prior sentinel block before writing.
        Requires root + a remounted (or at least writable) /system —
        /etc/hosts on Android is typically a symlink into /system/etc.
        """
        redirects = redirects or _HOSTS_REDIRECTS
        current = self._read_hosts()
        base = self._strip_marker_block(current)

        block_lines = [_HOSTS_MARKER_BEGIN]
        block_lines += [f"{ip}\t{host}" for host, ip in redirects.items()]
        block_lines.append(_HOSTS_MARKER_END)
        new_content = base.rstrip("\n") + "\n" + "\n".join(block_lines) + "\n"

        return self._write_hosts(new_content)

    def remove_dns_redirects(self) -> bool:
        current = self._read_hosts()
        stripped = self._strip_marker_block(current)
        if stripped == current:
            log.info("no sentinel DNS redirect block present -- nothing to remove")
            return True
        return self._write_hosts(stripped)

    def _read_hosts(self) -> str:
        res = self._adb("shell", "cat", "/etc/hosts")
        return res.stdout if res.returncode == 0 else ""

    def _write_hosts(self, content: str) -> bool:
        self._adb("root", timeout=15)
        self._adb("remount", timeout=30)
        res = self._adb("shell", f"echo '{content}' > /etc/hosts")
        if res.returncode != 0:
            log.error("failed to write /etc/hosts: %s", res.stderr.strip())
            return False
        log.info("/etc/hosts updated")
        return True

    @staticmethod
    def _strip_marker_block(content: str) -> str:
        if _HOSTS_MARKER_BEGIN not in content:
            return content
        lines = content.splitlines()
        out: list[str] = []
        inside = False
        for line in lines:
            if line.strip() == _HOSTS_MARKER_BEGIN:
                inside = True
                continue
            if line.strip() == _HOSTS_MARKER_END:
                inside = False
                continue
            if not inside:
                out.append(line)
        return "\n".join(out) + "\n"

    # ------------------------------------------------------------------
    # Verification
    # ------------------------------------------------------------------

    def verify(self) -> dict[str, object]:
        """Report current proxy/DNS state for diagnostics."""
        proxy_res = self._adb("shell", "settings", "get", "global", "http_proxy")
        hosts_res = self._adb("shell", "cat", "/etc/hosts")

        return {
            "system_proxy": proxy_res.stdout.strip(),
            "system_proxy_active": f"{HOST_PROXY_ADDR}:{HOST_PROXY_PORT}" in proxy_res.stdout,
            "dns_redirect_active": _HOSTS_MARKER_BEGIN in hosts_res.stdout,
        }

    # ------------------------------------------------------------------
    # Convenience: full up/down
    # ------------------------------------------------------------------

    def up(self) -> dict[str, bool]:
        return {
            "system_proxy": self.set_system_proxy(),
            "dns_redirect": self.apply_dns_redirects(),
        }

    def down(self) -> None:
        self.clear_system_proxy()
        self.remove_dns_redirects()


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    parser = argparse.ArgumentParser(description="L2 transparent proxy + DNS redirect setup")
    parser.add_argument("action", choices=("up", "down", "verify"))
    parser.add_argument("--serial", default=None, help="ADB device serial")
    args = parser.parse_args()

    mgr = ProxyManager(device_serial=args.serial)
    try:
        if args.action == "up":
            result = mgr.up()
            log.info("proxy up: %s", result)
        elif args.action == "down":
            mgr.down()
            log.info("proxy torn down")
        else:
            log.info("verify: %s", mgr.verify())
    except ProxySetupError as exc:
        log.error("proxy setup failed: %s", exc)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
