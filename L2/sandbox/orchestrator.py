"""L2 Sandbox: Master Orchestrator.

Orchestrates the entire L2 dynamic analysis flow:
1. Verifies an emulator is attached via ADB.
2. Installs the APK, grants dangerous permissions, enables its
   accessibility service (if declared), and seeds honeypot data.
3. Starts the mitmproxy process.
4. Launches DroidBot as the interaction engine (UI exploration + UTG
   capture) while Frida attaches to the running process for hooks.
5. Injects scheduled fake-OTP SMS during the detonation window.
6. Captures output for a defined detonation window.

Graceful degradation: when ADB, Frida, DroidBot or mitmproxy are
unavailable the orchestrator raises ``EmulatorUnavailableError`` or logs
a warning and skips that stage, rather than an opaque subprocess crash.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from L2.sandbox.honeypot import EmulatorUnavailableError, HoneypotSeeder, render_otp
from L2.sandbox.pcap_capture import PcapCapture
from L2.sandbox.safety import DetonationSafety, DetonationSafetyError

log = logging.getLogger(__name__)

_SANDBOX_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _SANDBOX_DIR.parent.parent

ANDROID_NS = "http://schemas.android.com/apk/res/android"
BIND_ACCESSIBILITY_PERMISSION = "android.permission.BIND_ACCESSIBILITY_SERVICE"

# Dangerous / high-value permissions pre-granted before detonation so the
# malware runs its data-theft logic instead of stalling on a permission
# prompt DroidBot may not reliably click through.
DANGEROUS_PERMISSIONS = [
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_CONTACTS",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.READ_PHONE_STATE",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_BOOT_COMPLETED",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
]

# T+seconds -> bank template for runtime OTP SMS injection.
OTP_INJECTION_SCHEDULE = [(10, "sbi"), (20, "hdfc"), (30, "icici")]


@dataclass
class L2Orchestrator:
    """Drive an L2 sandbox detonation run."""

    apk_path: Path
    package_name: str
    detonation_time_s: int = 60
    droidbot_duration_s: int = 120
    sha256: str = ""
    device_serial: str = field(default="", init=False)
    artifacts_dir: Path = field(default=Path(), init=False)
    frida_log_path: Path = field(default=Path(), init=False)
    droidbot_dir: Path = field(default=Path(), init=False)
    _mitm_proc: subprocess.Popen[bytes] | None = field(
        default=None, init=False, repr=False,
    )
    _sms_timers: list[threading.Timer] = field(
        default_factory=list, init=False, repr=False,
    )
    _pcap: PcapCapture | None = field(default=None, init=False, repr=False)
    _frida_attached: bool = field(default=False, init=False, repr=False)

    def __post_init__(self) -> None:
        self.apk_path = Path(self.apk_path)
        if not self.sha256:
            self.sha256 = self._compute_sha256(self.apk_path)
        self.device_serial = self._get_device()
        self.artifacts_dir = _SANDBOX_DIR / "artifacts" / self.package_name
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)
        self.frida_log_path = self.artifacts_dir / "frida_hooks.jsonl"
        self.droidbot_dir = self.artifacts_dir / "droidbot_utg"

    @staticmethod
    def _compute_sha256(apk_path: Path) -> str:
        if not apk_path.exists():
            return ""
        digest = hashlib.sha256()
        with apk_path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                digest.update(chunk)
        return digest.hexdigest()

    # ------------------------------------------------------------------
    # Device discovery
    # ------------------------------------------------------------------

    @staticmethod
    def _get_device() -> str:
        """Find the first attached ADB device.

        Raises ``EmulatorUnavailableError`` with a human-readable message
        when no device is reachable.
        """
        if not shutil.which("adb"):
            raise EmulatorUnavailableError(
                "adb binary not found on PATH -- install the Android SDK "
                "platform-tools or set ANDROID_SDK_ROOT"
            )

        try:
            result = subprocess.run(
                ["adb", "devices"],
                capture_output=True, text=True, timeout=10,
            )
        except subprocess.TimeoutExpired as exc:
            raise EmulatorUnavailableError(
                "adb devices timed out -- is the ADB server responsive?"
            ) from exc

        lines = result.stdout.strip().split("\n")[1:]
        devices = [
            line.split("\t")[0]
            for line in lines
            if "\tdevice" in line
        ]
        if not devices:
            raise EmulatorUnavailableError(
                "no ADB devices attached -- start an emulator first "
                "(the sentinel AVD currently core-dumps on boot, see T14)"
            )
        log.info("found ADB device: %s", devices[0])
        return devices[0]

    # ------------------------------------------------------------------
    # ADB helper
    # ------------------------------------------------------------------

    def _adb(self, *args: str) -> subprocess.CompletedProcess[str]:
        cmd = ["adb", "-s", self.device_serial, *args]
        return subprocess.run(cmd, capture_output=True, text=True, timeout=30)

    # ------------------------------------------------------------------
    # Network interception
    # ------------------------------------------------------------------

    def start_network_interception(self) -> None:
        """Start mitmproxy in the background and begin the PCAP capture."""
        if not shutil.which("mitmproxy"):
            log.warning("mitmproxy not found on PATH -- network capture disabled")
        else:
            log.info("starting mitmproxy on port 8080")
            mitm_script = _SANDBOX_DIR / "mitm_addon.py"

            self._mitm_proc = subprocess.Popen(
                [
                    "mitmproxy", "-s", str(mitm_script),
                    "--listen-port", "8080", "--ssl-insecure",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                preexec_fn=os.setsid,
            )
            time.sleep(3)  # wait for proxy to bind

        self._pcap = PcapCapture(device_serial=self.device_serial)
        try:
            self._pcap.start()
        except Exception as exc:  # noqa: BLE001
            log.warning("failed to start pcap capture: %s", exc)

    # ------------------------------------------------------------------
    # Permissions / accessibility
    # ------------------------------------------------------------------

    def grant_permissions(self) -> None:
        """Pre-grant dangerous permissions via ``pm grant`` before launch.

        Best-effort: install-time-only permissions (``RECEIVE_BOOT_COMPLETED``)
        and system/signature permissions (``BIND_ACCESSIBILITY_SERVICE``)
        cannot actually be handed out by ``pm grant`` -- the attempt is kept
        so a manifest that *does* declare them as runtime-requestable still
        gets granted, and failures are logged rather than raised.
        """
        log.info("pre-granting dangerous permissions to %s", self.package_name)
        for perm in DANGEROUS_PERMISSIONS:
            res = self._adb("shell", "pm", "grant", self.package_name, perm)
            if res.returncode != 0:
                log.debug("pm grant %s failed (expected for some perms): %s",
                          perm, res.stderr.strip())

        # SYSTEM_ALERT_WINDOW (overlay attacks) is an appop, not a runtime
        # permission -- pm grant alone does not enable it.
        self._adb("shell", "appops", "set", self.package_name,
                   "SYSTEM_ALERT_WINDOW", "allow")

    def enable_accessibility_service(self) -> None:
        """Enable the target's accessibility service, if it declares one.

        Reads the AndroidManifest via androguard (never executes the
        sample) to find a ``<service>`` requiring
        ``BIND_ACCESSIBILITY_SERVICE``, then flips the two secure settings
        the platform checks: ``enabled_accessibility_services`` and
        ``accessibility_enabled``.
        """
        service = self._find_accessibility_service()
        if not service:
            log.info("no accessibility service declared -- skipping")
            return

        component = f"{self.package_name}/{service}"
        log.info("enabling accessibility service %s", component)
        self._adb("shell", "settings", "put", "secure",
                   "enabled_accessibility_services", component)
        self._adb("shell", "settings", "put", "secure",
                   "accessibility_enabled", "1")

    def _find_accessibility_service(self) -> str | None:
        try:
            from androguard.core.apk import APK
        except ImportError:
            log.warning("androguard not available -- cannot inspect manifest")
            return None

        try:
            apk = APK(str(self.apk_path))
            root = apk.get_android_manifest_xml()
            for svc in root.iter("service"):
                perm = svc.get(f"{{{ANDROID_NS}}}permission")
                if perm != BIND_ACCESSIBILITY_PERMISSION:
                    continue
                name = svc.get(f"{{{ANDROID_NS}}}name")
                if not name:
                    continue
                if name.startswith("."):
                    return apk.get_package() + name
                if "." not in name:
                    return f"{apk.get_package()}.{name}"
                return name
        except Exception as exc:  # noqa: BLE001
            log.warning("failed to parse manifest for accessibility service: %s", exc)
        return None

    # ------------------------------------------------------------------
    # Environment prep
    # ------------------------------------------------------------------

    def prepare_environment(self) -> None:
        """Install, grant permissions/accessibility, and seed honeypot data."""
        log.info("installing %s", self.apk_path.name)
        res = self._adb("install", "-t", "-r", str(self.apk_path))
        if "Success" not in res.stdout:
            log.warning("install may have failed: %s", res.stdout.strip())

        self.grant_permissions()
        self.enable_accessibility_service()

        log.info("seeding honeypot data")
        seeder = HoneypotSeeder(device_serial=self.device_serial)
        warnings = seeder.run_all()
        for w in warnings:
            log.warning("honeypot: %s", w)

    # ------------------------------------------------------------------
    # Runtime SMS injection
    # ------------------------------------------------------------------

    def schedule_sms_injection(self) -> None:
        """Fire fake bank-OTP SMS at T+10s, T+20s, T+30s during detonation."""
        seeder = HoneypotSeeder(device_serial=self.device_serial)
        for delay, bank in OTP_INJECTION_SCHEDULE:
            sender, body = render_otp(bank)

            def _fire(sender: str = sender, body: str = body) -> None:
                seeder.send_emu_sms(sender, body)

            timer = threading.Timer(delay, _fire)
            timer.daemon = True
            self._sms_timers.append(timer)
            timer.start()

    def _cancel_sms_injection(self) -> None:
        for timer in self._sms_timers:
            timer.cancel()
        self._sms_timers.clear()

    # ------------------------------------------------------------------
    # DroidBot interaction engine
    # ------------------------------------------------------------------

    def _run_droidbot(self) -> subprocess.Popen[bytes] | None:
        """Launch DroidBot to install/interact with/explore the app.

        DroidBot owns install + launch for this run (it force-installs via
        ``-a``); it explores via a greedy DFS UI-transition-graph policy
        and writes ``utg.js`` plus state screenshots to ``droidbot_dir``.
        """
        droidbot_python = sys.executable
        cmd = [
            droidbot_python, "-m", "droidbot.start",
            "-d", self.device_serial,
            "-a", str(self.apk_path),
            "-o", str(self.droidbot_dir),
            "-policy", "dfs_greedy",
            "-timeout", str(self.droidbot_duration_s),
            "-grant_perm",
            "-is_emulator",
            "-keep_app",
        ]
        log.info("starting DroidBot exploration for %ds", self.droidbot_duration_s)
        try:
            return subprocess.Popen(
                cmd,
                stdout=open(self.artifacts_dir / "droidbot.log", "w"),
                stderr=subprocess.STDOUT,
                cwd=str(_REPO_ROOT),
            )
        except OSError as exc:
            log.error("failed to launch DroidBot: %s", exc)
            return None

    def _wait_for_process(self, timeout_s: float = 20.0) -> bool:
        """Poll ``frida-ps -U`` until the target package appears."""
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            try:
                res = subprocess.run(
                    ["frida-ps", "-U"], capture_output=True, text=True, timeout=10,
                )
                if self.package_name in res.stdout:
                    return True
            except (subprocess.TimeoutExpired, OSError):
                pass
            time.sleep(1)
        return False

    # ------------------------------------------------------------------
    # Detonation
    # ------------------------------------------------------------------

    def detonate(self) -> None:
        """Drive the app with DroidBot while Frida attaches for hooks."""
        script_dir = _SANDBOX_DIR / "frida_scripts"
        stealth_path = script_dir / "stealth_init.js"
        hooks_path = script_dir / "dynamic_hooks.js"
        auth_fill_path = script_dir / "auth_fill.js"
        auth_bypass_path = script_dir / "auth_bypass.js"
        accessibility_path = script_dir / "accessibility_hooks.js"

        required_scripts = (stealth_path, hooks_path, auth_fill_path, auth_bypass_path, accessibility_path)
        if not all(p.exists() for p in required_scripts):
            log.error("Frida scripts missing from %s", script_dir)
            return

        droidbot_proc = self._run_droidbot()

        self.schedule_sms_injection()

        combined_script = script_dir / "combined_runner.js"
        frida_proc: subprocess.Popen[bytes] | None = None
        if shutil.which("frida") and shutil.which("frida-ps"):
            combined_script.write_text(
                "\n\n".join(p.read_text() for p in required_scripts)
            )
            if self._wait_for_process():
                log.info("attaching Frida to running %s", self.package_name)
                frida_proc = subprocess.Popen(
                    ["frida", "-U", self.package_name, "-l", str(combined_script)],
                    stdout=open(self.frida_log_path, "w"),
                    stderr=subprocess.STDOUT,
                )
                self._frida_attached = True
            else:
                log.warning("%s never appeared in frida-ps -U -- no hooks attached",
                            self.package_name)
        else:
            log.warning("frida/frida-ps not found on PATH -- hooking skipped")

        wait_s = max(self.detonation_time_s, self.droidbot_duration_s)
        log.info("monitoring detonation for %ds", wait_s)
        try:
            if droidbot_proc:
                try:
                    droidbot_proc.wait(timeout=wait_s)
                except subprocess.TimeoutExpired:
                    droidbot_proc.terminate()
            else:
                time.sleep(wait_s)
        finally:
            self._cancel_sms_injection()
            if frida_proc:
                frida_proc.terminate()
                try:
                    frida_proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    frida_proc.kill()
            combined_script.unlink(missing_ok=True)

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    def cleanup(self) -> None:
        """Kill proxy, cancel pending SMS injections, and uninstall app."""
        log.info("cleaning up")
        self._cancel_sms_injection()
        if self._mitm_proc:
            try:
                os.killpg(os.getpgid(self._mitm_proc.pid), signal.SIGTERM)
            except (OSError, ProcessLookupError) as exc:
                log.warning("failed to kill mitmproxy: %s", exc)

        self._copy_network_evidence()

        self._adb("uninstall", self.package_name)

        try:
            DetonationSafety(device_serial=self.device_serial).post_restore()
        except Exception as exc:  # noqa: BLE001
            log.warning("post-detonation safety restore failed: %s", exc)

        log.info("sandbox execution complete, artifacts in %s", self.artifacts_dir)

    def _copy_network_evidence(self) -> None:
        """Copy mitmproxy's network_evidence.json into the package artifacts dir."""
        src = _SANDBOX_DIR / "artifacts" / "network_evidence.json"
        try:
            shutil.copy2(src, self.artifacts_dir / "network_evidence.json")
        except (OSError, shutil.SameFileError) as exc:
            log.debug("no network_evidence.json to copy (%s): %s", src, exc)

    # ------------------------------------------------------------------
    # Full run
    # ------------------------------------------------------------------

    def run(self) -> Path:
        """Execute the full detonation pipeline, returning the artifacts dir.

        On any non-fatal error the orchestrator still attempts cleanup.
        """
        issues = DetonationSafety(device_serial=self.device_serial).pre_check()
        if issues:
            raise DetonationSafetyError(issues)

        elapsed_s = 0.0
        try:
            self.start_network_interception()
            self.prepare_environment()
            start = time.monotonic()
            self.detonate()
            elapsed_s = time.monotonic() - start
        except EmulatorUnavailableError:
            raise
        except Exception as exc:
            log.error("sandbox error: %s", exc, exc_info=True)
        finally:
            if self._pcap is not None:
                try:
                    self._pcap.stop_and_pull(self.artifacts_dir)
                except Exception as exc:  # noqa: BLE001
                    log.warning("failed to stop/pull pcap capture: %s", exc)
            if self._mitm_proc:
                try:
                    os.killpg(os.getpgid(self._mitm_proc.pid), signal.SIGTERM)
                except (OSError, ProcessLookupError) as exc:
                    log.warning("failed to kill mitmproxy: %s", exc)
                self._mitm_proc = None
            self._copy_network_evidence()
            self._generate_dynamic_json(elapsed_s)
            self.cleanup()
        return self.artifacts_dir

    # ------------------------------------------------------------------
    # dynamic.json generation
    # ------------------------------------------------------------------

    def _generate_dynamic_json(self, elapsed_s: float) -> None:
        """Summarise frida_hooks.jsonl + network_evidence.json into dynamic.json.

        Written in the schema ``l2_engine._parse_dynamic_json`` expects, so
        the L2 engine can turn this run's raw artifacts into L1Findings and
        fold them into the spine.
        """
        stealth_bypassed = 0
        sms_intercepted = False
        overlay_displayed = False
        clipboard_hijacked = False
        files_dropped = 0

        if self.frida_log_path.exists():
            for line in self.frida_log_path.read_text(errors="replace").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    raw = json.loads(line)
                except json.JSONDecodeError:
                    continue

                # Frida CLI wraps send() payloads: {"type": "send", "payload": {...}}
                if raw.get("type") == "send":
                    payload = raw.get("payload")
                    if not isinstance(payload, dict):
                        continue
                    raw = payload

                rtype = raw.get("type")
                if rtype == "stealth":
                    stealth_bypassed += 1
                    continue

                category = str(raw.get("category", raw.get("action", ""))).lower()
                if rtype == "finding":
                    if category in ("sms_exfiltration", "send_sms", "sms_intercept"):
                        sms_intercepted = True
                    elif category in ("overlay", "overlay_attack", "add_overlay"):
                        overlay_displayed = True
                    elif category in ("clipboard_hijack", "set_clipboard"):
                        clipboard_hijacked = True
                    elif category in ("load_dex", "native_payload", "file_drop"):
                        files_dropped += 1

        network_path = self.artifacts_dir / "network_evidence.json"
        total_requests = 0
        c2_endpoints: list[str] = []
        exfiltration_detected = False
        data_exfiltrated: list[str] = []
        network_captured = False
        if network_path.exists():
            network_captured = True
            try:
                entries = json.loads(network_path.read_text())
            except (json.JSONDecodeError, OSError):
                entries = []
            if isinstance(entries, list):
                total_requests = len(entries)
                for entry in entries:
                    if not isinstance(entry, dict):
                        continue
                    if entry.get("alert") == "CREDENTIAL_EXFILTRATION":
                        exfiltration_detected = True
                        host = entry.get("host", "unknown")
                        if host not in data_exfiltrated:
                            data_exfiltrated.append(host)
                    if entry.get("hijacked"):
                        url = entry.get("url", "")
                        if url and url not in c2_endpoints:
                            c2_endpoints.append(url)

        if self._frida_attached and network_captured and elapsed_s >= self.detonation_time_s:
            confidence_level = "high"
        elif not self._frida_attached:
            confidence_level = "low"
        else:
            confidence_level = "medium"

        dynamic = {
            "package": self.package_name,
            "sha256": self.sha256,
            "sandbox": {
                "type": "droidbot+frida",
                "detonation_duration_s": round(elapsed_s, 2),
                "evasion_checks_bypassed": stealth_bypassed,
                "android_version": "11",
                "api_level": 30,
            },
            "runtime_behaviors": {
                "sms_intercepted": sms_intercepted,
                "overlay_displayed": overlay_displayed,
                "clipboard_hijacked": clipboard_hijacked,
                "files_dropped": files_dropped,
            },
            "network": {
                "total_requests": total_requests,
                "c2_endpoints": c2_endpoints,
                "exfiltration_detected": exfiltration_detected,
                "data_exfiltrated": data_exfiltrated,
            },
            "findings": [],
            "confidence": {
                "confidence_level": confidence_level,
            },
        }

        out_path = self.artifacts_dir / "dynamic.json"
        out_path.write_text(json.dumps(dynamic, indent=2))
        log.info("wrote %s", out_path)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    import argparse

    logging.basicConfig(
        level=logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
    )

    parser = argparse.ArgumentParser(description="L2 Sandbox Orchestrator")
    parser.add_argument("apk", help="Path to APK")
    parser.add_argument("package", help="Package name of the APK")
    parser.add_argument(
        "--time", type=int, default=60, help="Frida monitoring window in seconds",
    )
    parser.add_argument(
        "--droidbot-time", type=int, default=120,
        help="DroidBot exploration duration in seconds",
    )
    args = parser.parse_args()

    try:
        orch = L2Orchestrator(
            apk_path=Path(args.apk),
            package_name=args.package,
            detonation_time_s=args.time,
            droidbot_duration_s=args.droidbot_time,
        )
        orch.run()
    except EmulatorUnavailableError as exc:
        log.error("emulator unavailable: %s", exc)
        return 1
    except Exception as exc:
        log.error("orchestrator failed: %s", exc, exc_info=True)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
