"""L2 Sandbox: tcpdump PCAP capture for a detonation window.

Standalone helper (kept separate from orchestrator.py, which another agent
is modifying) so it can be wired into the detonation flow independently:
call ``start()`` right before spawning the target APK, ``stop_and_pull()``
after the detonation window ends, to land ``capture.pcap`` in the sample's
artifact directory alongside frida_hooks.jsonl and network_evidence.json.

Requires a `tcpdump` binary on the emulator image (present on most AVD
system images under /system/bin or /system/xbin).
"""

from __future__ import annotations

import logging
import shutil
import subprocess
from pathlib import Path

log = logging.getLogger(__name__)

_DEVICE_PCAP_PATH = "/sdcard/capture.pcap"


class PcapCaptureError(Exception):
    """Raised when tcpdump cannot be started or the capture cannot be pulled."""


class PcapCapture:
    """Start/stop a background `tcpdump` capture on the emulator via adb."""

    def __init__(self, device_serial: str | None = None) -> None:
        self.device_serial = device_serial
        self._proc: subprocess.Popen[bytes] | None = None

    def _adb_args(self, *args: str) -> list[str]:
        cmd = ["adb"]
        if self.device_serial:
            cmd.extend(["-s", self.device_serial])
        cmd.extend(args)
        return cmd

    def start(self, device_pcap_path: str = _DEVICE_PCAP_PATH) -> None:
        """Start `tcpdump -i any -w <device_pcap_path>` in the background.

        The adb shell process is kept open for the duration of the capture;
        ``stop_and_pull`` terminates it with SIGINT (tcpdump's clean-flush
        signal) before pulling the file.
        """
        if not shutil.which("adb"):
            raise PcapCaptureError("adb not found on PATH")

        # Clear any stale capture from a previous run.
        subprocess.run(self._adb_args("shell", "rm", "-f", device_pcap_path),
                        capture_output=True, timeout=15)

        log.info("starting tcpdump capture -> %s", device_pcap_path)
        self._proc = subprocess.Popen(
            self._adb_args("shell", "su", "0", "tcpdump", "-i", "any", "-w", device_pcap_path),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        self._device_pcap_path = device_pcap_path

    def stop_and_pull(self, dest_dir: Path) -> Path | None:
        """Stop the capture and pull the pcap into *dest_dir*/capture.pcap.

        Returns the local path, or None if capture was never started or
        the pull failed.
        """
        if self._proc is None:
            log.warning("pcap capture was never started -- nothing to pull")
            return None

        subprocess.run(
            self._adb_args("shell", "su", "0", "pkill", "-SIGINT", "tcpdump"),
            capture_output=True, timeout=10,
        )
        try:
            self._proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self._proc.kill()
            self._proc.wait(timeout=5)

        dest_dir.mkdir(parents=True, exist_ok=True)
        dest_path = dest_dir / "capture.pcap"

        result = subprocess.run(
            self._adb_args("pull", self._device_pcap_path, str(dest_path)),
            capture_output=True, text=True, timeout=60,
        )
        if result.returncode != 0:
            log.error("failed to pull pcap: %s", result.stderr.strip())
            return None

        log.info("pcap saved to %s", dest_path)
        return dest_path
