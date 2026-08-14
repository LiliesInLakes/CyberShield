"""L2 Sandbox: Transparent proxy and DNS redirection for the emulator.

Standalone helper (kept separate from orchestrator.py, which another agent
is modifying).  Two independent concerns live here because both are
"make the emulator's network go where we want before detonation":

  1. Transparent proxying -- global HTTP proxy setting plus iptables
     REDIRECT rules so traffic that ignores the system proxy setting
     (many bankers hardcode sockets) still lands on mitmproxy.
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

_IPTABLES_COMMENT = "sentinel-l2-transparent-proxy"


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
    # iptables transparent redirect (requires root)
    # ------------------------------------------------------------------

    def _iptables(self, action: str, port: int) -> subprocess.CompletedProcess[str]:
        # -A to add, -D to delete; both use the identical rule spec so
        # teardown is a mechanical replay of setup.
        return self._adb(
            "shell", "su", "0", "iptables", "-t", "nat", action, "OUTPUT",
            "-p", "tcp", "--dport", str(port),
            "-m", "comment", "--comment", _IPTABLES_COMMENT,
            "-j", "REDIRECT", "--to-port", str(HOST_PROXY_PORT),
        )

    def add_transparent_redirect(self, ports: tuple[int, ...] = (80, 443)) -> bool:
        """Add iptables REDIRECT rules for *ports* -> mitmproxy.

        Best-effort: not every emulator image ships iptables or grants
        root via ``su 0``. Failures are logged and do not raise -- the
        system proxy setting alone still covers apps that honour it.
        """
        ok = True
        for port in ports:
            res = self._iptables("-A", port)
            if res.returncode != 0:
                log.warning(
                    "iptables redirect for port %d failed (root/iptables may be "
                    "unavailable on this image): %s", port, res.stderr.strip(),
                )
                ok = False
            else:
                log.info("iptables: redirecting tcp/%d -> %d", port, HOST_PROXY_PORT)
        return ok

    def remove_transparent_redirect(self, ports: tuple[int, ...] = (80, 443)) -> None:
        for port in ports:
            res = self._iptables("-D", port)
            if res.returncode != 0:
                log.debug("iptables rule for port %d already absent: %s", port, res.stderr.strip())

    def list_iptables_rules(self) -> str:
        res = self._adb("shell", "su", "0", "iptables", "-t", "nat", "-L", "OUTPUT", "-n", "--line-numbers")
        return res.stdout

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
        """Report current proxy/DNS/iptables state for diagnostics."""
        proxy_res = self._adb("shell", "settings", "get", "global", "http_proxy")
        hosts_res = self._adb("shell", "cat", "/etc/hosts")
        iptables_rules = self.list_iptables_rules()

        return {
            "system_proxy": proxy_res.stdout.strip(),
            "system_proxy_active": f"{HOST_PROXY_ADDR}:{HOST_PROXY_PORT}" in proxy_res.stdout,
            "dns_redirect_active": _HOSTS_MARKER_BEGIN in hosts_res.stdout,
            "iptables_redirect_active": _IPTABLES_COMMENT in iptables_rules,
        }

    # ------------------------------------------------------------------
    # Convenience: full up/down
    # ------------------------------------------------------------------

    def up(self) -> dict[str, bool]:
        return {
            "system_proxy": self.set_system_proxy(),
            "transparent_redirect": self.add_transparent_redirect(),
            "dns_redirect": self.apply_dns_redirects(),
        }

    def down(self) -> None:
        self.clear_system_proxy()
        self.remove_transparent_redirect()
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
