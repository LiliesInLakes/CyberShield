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

import ast
import hashlib
import json
import logging
import os
import random
import re
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
from L2.sandbox.proxy_setup import ProxyManager
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

_LAUNCH_EMULATOR_SH = _REPO_ROOT / "tools" / "launch_emulator.sh"
_EMULATOR_BOOT_TIMEOUT_S = 180


@dataclass
class L2Orchestrator:
    """Drive an L2 sandbox detonation run."""

    apk_path: Path
    package_name: str
    detonation_time_s: int = 60
    droidbot_duration_s: int = 120
    sha256: str = ""
    auto_launch_emulator: bool = True
    device_serial: str = field(default="", init=False)
    artifacts_dir: Path = field(default=Path(), init=False)
    frida_log_path: Path = field(default=Path(), init=False)
    droidbot_dir: Path = field(default=Path(), init=False)
    otp_file_path: Path = field(default=Path(), init=False)
    _mitm_proc: subprocess.Popen[bytes] | None = field(
        default=None, init=False, repr=False,
    )
    _sms_timers: list[threading.Timer] = field(
        default_factory=list, init=False, repr=False,
    )
    _pcap: PcapCapture | None = field(default=None, init=False, repr=False)
    _frida_attached: bool = field(default=False, init=False, repr=False)
    _frida_hook_thread: threading.Thread | None = field(
        default=None, init=False, repr=False,
    )
    _frida_stop_event: threading.Event = field(
        default_factory=threading.Event, init=False, repr=False,
    )

    def __post_init__(self) -> None:
        self.apk_path = Path(self.apk_path)
        if not self.sha256:
            self.sha256 = self._compute_sha256(self.apk_path)
        self.device_serial = self._ensure_device()
        self.artifacts_dir = _SANDBOX_DIR / "artifacts" / self.package_name
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)
        self.frida_log_path = self.artifacts_dir / "frida_hooks.jsonl"
        self.droidbot_dir = self.artifacts_dir / "droidbot_utg"
        self.otp_file_path = self.artifacts_dir / "latest_injected_otp.txt"

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
    def _list_devices() -> list[str]:
        """ADB serials currently in ``device`` state (booted, not ``offline``).

        Raises ``EmulatorUnavailableError`` if adb itself is unreachable —
        that is a setup problem no amount of waiting fixes. Returns an empty
        list (not an error) when adb works but nothing is attached yet, so
        callers can poll it during boot.
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
        return [line.split("\t")[0] for line in lines if "\tdevice" in line]

    def _launch_emulator_and_wait(self) -> str | None:
        """Best-effort: fire `tools/launch_emulator.sh` and wait for boot.

        Returns the new device serial on success, ``None`` on any failure —
        callers treat ``None`` the same as "no device", which surfaces as the
        existing ``EmulatorUnavailableError`` rather than a new failure mode.
        """
        if not _LAUNCH_EMULATOR_SH.is_file():
            log.warning("auto-launch requested but %s is missing", _LAUNCH_EMULATOR_SH)
            return None

        log.info("no emulator attached -- launching sentinel30 via %s", _LAUNCH_EMULATOR_SH)
        try:
            # start_new_session so the emulator outlives this process (and
            # this orchestrator run) -- it is infrastructure to leave
            # running for the next detonation, not part of this call's
            # child-process tree that cleanup() should ever touch.
            subprocess.Popen(
                ["bash", str(_LAUNCH_EMULATOR_SH)],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
        except OSError as exc:
            log.error("failed to launch emulator: %s", exc)
            return None

        deadline = time.monotonic() + _EMULATOR_BOOT_TIMEOUT_S
        serial: str | None = None
        while time.monotonic() < deadline:
            try:
                devices = self._list_devices()
            except EmulatorUnavailableError:
                devices = []
            if devices:
                serial = devices[0]
                boot = subprocess.run(
                    ["adb", "-s", serial, "shell", "getprop", "sys.boot_completed"],
                    capture_output=True, text=True, timeout=10,
                )
                if boot.stdout.strip() == "1":
                    log.info("emulator %s finished booting", serial)
                    return serial
            time.sleep(3)

        log.error("emulator did not finish booting within %ds", _EMULATOR_BOOT_TIMEOUT_S)
        return None

    def _ensure_device(self) -> str:
        """Find an attached device, auto-launching the sandbox AVD if none
        is attached and ``auto_launch_emulator`` is set (the default).

        Raises ``EmulatorUnavailableError`` if no device is attached and
        either auto-launch is disabled or auto-launch itself fails --
        same failure surface as before this method existed, just reached
        one attempt later.
        """
        devices = self._list_devices()
        if devices:
            log.info("found ADB device: %s", devices[0])
            return devices[0]

        if self.auto_launch_emulator:
            serial = self._launch_emulator_and_wait()
            if serial:
                return serial

        raise EmulatorUnavailableError(
            "no ADB devices attached, and " +
            ("auto-launch failed" if self.auto_launch_emulator
             else "auto-launch is disabled") +
            " -- start an emulator manually with tools/launch_emulator.sh"
        )

    def _ensure_frida_server(self) -> None:
        """Push and start ``tools/frida-server`` on the device if it isn't
        already running.

        This was the actual root cause of every "Frida never captured a
        hook" run: nothing in this module ever deployed frida-server, so
        every attach attempt (CLI or Python bindings) failed --
        `frida-ps`/`pidof` enumeration doesn't need it (that goes over
        plain adb), which is why the process-liveness checks kept
        "succeeding" while attachment kept failing with opaque errors like
        "Failed to spawn: unable to find process" or "unable to connect to
        remote frida-server: closed". A previous session must have started
        it by hand; `-wipe-data` (used for clean boots, see
        tools/launch_emulator.sh) wipes it on every fresh boot since
        `/data/local/tmp` doesn't survive that.
        """
        check = self._adb("shell", "pidof", "frida-server")
        if check.stdout.strip():
            return

        server_bin = _REPO_ROOT / "tools" / "frida-server"
        if not server_bin.exists():
            log.warning("tools/frida-server not found -- Frida hooking will fail to attach")
            return

        log.info("frida-server not running on device -- deploying it")
        push = self._adb("push", str(server_bin), "/data/local/tmp/frida-server")
        if push.returncode != 0:
            log.warning("failed to push frida-server: %s", push.stderr.strip())
            return
        self._adb("shell", "chmod", "755", "/data/local/tmp/frida-server")
        # Backgrounded on-device with nohup; adb shell itself returns once
        # the command is launched rather than blocking on the server.
        subprocess.run(
            ["adb", "-s", self.device_serial, "shell",
             "nohup /data/local/tmp/frida-server >/data/local/tmp/frida-server.log 2>&1 &"],
            capture_output=True, text=True, timeout=15,
        )
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if self._adb("shell", "pidof", "frida-server").stdout.strip():
                log.info("frida-server is up")
                return
            time.sleep(0.5)
        log.warning("frida-server did not come up within 10s of being started")

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
        if not shutil.which("mitmdump"):
            log.warning("mitmdump not found on PATH -- network capture disabled")
        else:
            log.info("starting mitmdump on port 8080")
            mitm_script = _SANDBOX_DIR / "mitm_addon.py"

            # mitmdump, not mitmproxy: the latter is the interactive TUI and
            # exits immediately with SystemExit(1) when stdout/stderr aren't
            # a tty (which Popen never gives it) -- it never binds the port,
            # so every downstream reachability check failed closed.
            self._mitm_proc = subprocess.Popen(
                [
                    "mitmdump", "-s", str(mitm_script),
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

    def _dismiss_permission_review(self, timeout_s: float = 20.0) -> None:
        """Tap through Android's legacy "review permissions" screen.

        Apps with ``targetSdkVersion`` below the runtime-permission cutoff
        (23) get their permissions granted at install time, but the OS
        still shows a one-time ``ReviewPermissionsActivity`` confirmation
        screen on first launch -- `pm grant` in ``grant_permissions()``
        does not suppress it. DroidBot has no semantic understanding of
        button text (same root issue as the "Hello World" field-filling
        problem) and was observed tapping "Cancel"/"Deny anyway" on this
        screen at random, permanently blocking the app's real launch
        activity from ever running -- confirmed live: `mResumedActivity`
        stayed pinned on `ReviewPermissionsActivity` for the whole
        detonation window regardless of how long DroidBot kept trying.
        Tapping the actual "Continue" button once is enough; the OS does
        not show it again on subsequent launches of the same app.
        """
        self._adb("shell", "am", "start", "-n",
                   f"{self.package_name}/{self._find_launcher_activity() or '.MainActivity'}")
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            focus = self._adb("shell", "dumpsys", "activity", "activities").stdout
            if "ReviewPermissionsActivity" not in focus and "GrantPermissionsActivity" not in focus:
                return
            self._adb("shell", "uiautomator", "dump", "/sdcard/window_dump.xml")
            xml = self._adb("shell", "cat", "/sdcard/window_dump.xml").stdout
            if self._tap_affirmative_button(xml):
                time.sleep(2)
                continue
            time.sleep(1)
        log.debug("permission-review screen still present after %.0fs -- "
                   "leaving it for DroidBot", timeout_s)

    def _tap_affirmative_button(self, uiautomator_xml: str) -> bool:
        """Find and tap a clickable "Continue"/"Allow"/"OK"-style button in a
        uiautomator XML dump. Never taps "Cancel"/"Deny"/"Skip"/"Not now".
        Returns whether a tap was made.
        """
        node_re = re.compile(
            r'<node[^>]*text="([^"]*)"[^>]*clickable="true"[^>]*bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"'
        )
        deny_words = re.compile(r"cancel|deny|skip|not now|no thanks|later", re.I)
        allow_words = re.compile(r"continue|allow|^ok$|accept|grant|got it|agree", re.I)
        for text, x1, y1, x2, y2 in node_re.findall(uiautomator_xml):
            if not text or deny_words.search(text):
                continue
            if allow_words.search(text):
                cx, cy = (int(x1) + int(x2)) // 2, (int(y1) + int(y2)) // 2
                self._adb("shell", "input", "tap", str(cx), str(cy))
                log.info("permission-review: tapped %r", text)
                return True
        return False

    def _find_launcher_activity(self) -> str | None:
        try:
            from androguard.core.apk import APK
            return APK(str(self.apk_path)).get_main_activity()
        except Exception as exc:  # noqa: BLE001
            log.debug("failed to resolve launcher activity: %s", exc)
            return None

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
        self._dismiss_permission_review()

        log.info("seeding honeypot data")
        seeder = HoneypotSeeder(device_serial=self.device_serial)
        warnings = seeder.run_all()
        for w in warnings:
            log.warning("honeypot: %s", w)

    # ------------------------------------------------------------------
    # Runtime SMS injection
    # ------------------------------------------------------------------

    def schedule_sms_injection(self) -> None:
        """Fire fake bank-OTP SMS at T+10s, T+20s, T+30s during detonation.

        Each OTP is generated up front (not at fire time) and written to
        ``otp_file_path`` immediately, so DroidBot's field-filling heuristic
        (patched into the installed droidbot package -- see
        ``env/lib/*/site-packages/droidbot/device_state.py``) can type the
        *actual* value that's about to arrive by SMS into an OTP-looking
        field, instead of a disconnected random guess.
        """
        seeder = HoneypotSeeder(device_serial=self.device_serial)
        for delay, bank in OTP_INJECTION_SCHEDULE:
            otp = str(random.randint(100000, 999999))
            sender, body = render_otp(bank, otp=otp)
            try:
                self.otp_file_path.write_text(otp)
            except OSError as exc:
                log.warning("failed to write OTP hint file: %s", exc)

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
            # DroidBot internally spawns its own `adb logcat`/`adb getevent`
            # children; it doesn't always reap them when its own process
            # exits (observed: both still running well after droidbot.start
            # had finished). preexec_fn=os.setsid puts the whole tree in one
            # process group so cleanup() can killpg it instead of just the
            # one pid.
            child_env = dict(os.environ)
            child_env["DROIDBOT_OTP_FILE"] = str(self.otp_file_path)
            return subprocess.Popen(
                cmd,
                stdout=open(self.artifacts_dir / "droidbot.log", "w"),
                stderr=subprocess.STDOUT,
                cwd=str(_REPO_ROOT),
                preexec_fn=os.setsid,
                env=child_env,
            )
        except OSError as exc:
            log.error("failed to launch DroidBot: %s", exc)
            return None

    def _wait_for_pid(self, timeout_s: float = 60.0) -> int | None:
        """Poll ``adb shell pidof`` until the target package has a live PID.

        DroidBot doesn't launch the target immediately -- it explores from
        the home screen first. Measured: on this AVD the SBI sample didn't
        appear until well after the old 20s deadline, so 60s covers a cold
        DroidBot start.

        Historical note: this used to poll ``frida-ps -U``, whose *Name*
        column is the app's display label ("SBI Quick Support"), not its
        package identifier -- matching ``package_name`` against that could
        never succeed. ``-Uai`` (identifier column) fixed the match, but
        frida-tools 17.17.0 still fails to *attach* by name/identifier on
        this Android target (``Failed to spawn: unable to find process with
        name '...'``, even though the identifier is right there in
        ``frida-ps -Uai``'s own output). Attaching by PID works reliably, so
        this resolves a PID directly via ``pidof`` -- one adb round trip,
        no frida-tools name-resolution involved at all.
        """
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            try:
                res = self._adb("shell", "pidof", self.package_name)
                pid_str = res.stdout.strip().split()[0] if res.stdout.strip() else ""
                if pid_str.isdigit():
                    return int(pid_str)
            except (subprocess.TimeoutExpired, OSError):
                pass
            time.sleep(1)
        return None

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
        ssl_unpin_path = script_dir / "ssl_unpin.js"

        required_scripts = (stealth_path, hooks_path, auth_fill_path, auth_bypass_path,
                            accessibility_path, ssl_unpin_path)
        if not all(p.exists() for p in required_scripts):
            log.error("Frida scripts missing from %s", script_dir)
            return

        droidbot_proc = self._run_droidbot()

        self.schedule_sms_injection()

        combined_script = script_dir / "combined_runner.js"
        combined_js_text = "\n\n".join(p.read_text() for p in required_scripts)
        # Every send() in the hook scripts is conditional on the target app
        # actually calling a hooked API -- a benign app (or a malware
        # sample stuck on a splash screen) that never does so produces zero
        # send() traffic even when the attach and hook install succeeded
        # perfectly. Without an unconditional signal, `_frida_hook_loop`
        # has no way to distinguish "attached fine, nothing suspicious
        # happened" from "never attached at all" -- confidence would always
        # read `low` regardless of which actually occurred. `type:
        # "diagnostic"` doesn't match any of `_generate_dynamic_json`'s
        # finding categories, so it's a pure attach signal with no effect
        # on the parsed findings.
        combined_js_text += (
            '\n\nJava.perform(function() {\n'
            '    send({type: "diagnostic", note: "frida_attached"});\n'
            '});\n'
        )
        combined_script.write_text(combined_js_text)

        # install_ca.py is deliberately not called here: /system is
        # read-only on this AVD build, so a system CA install would fail on
        # every run (see decision_l2_setup.md §0). HTTPS interception
        # instead relies on ssl_unpin.js (bundled into combined_runner.js)
        # to bypass TrustManager pinning at the app level, which does not
        # need a system CA.
        wait_s = max(self.detonation_time_s, self.droidbot_duration_s)
        if shutil.which("frida"):
            self._frida_stop_event.clear()
            self._frida_hook_thread = threading.Thread(
                target=self._frida_hook_loop,
                args=(combined_script, wait_s),
                daemon=True,
            )
            self._frida_hook_thread.start()
        else:
            log.warning("frida not found on PATH -- hooking skipped")

        log.info("monitoring detonation for %ds", wait_s)
        try:
            if droidbot_proc:
                try:
                    droidbot_proc.wait(timeout=wait_s)
                except subprocess.TimeoutExpired:
                    pass
            else:
                time.sleep(wait_s)
        finally:
            self._cancel_sms_injection()
            self._frida_stop_event.set()
            if self._frida_hook_thread:
                self._frida_hook_thread.join(timeout=15)
            if droidbot_proc:
                # killpg, not .terminate()/.kill() on the single pid: those
                # leave orphaned `adb logcat`/`adb getevent` children behind
                # even when droidbot_proc itself exited cleanly.
                try:
                    os.killpg(os.getpgid(droidbot_proc.pid), signal.SIGTERM)
                except (OSError, ProcessLookupError):
                    pass
            combined_script.unlink(missing_ok=True)

    def _frida_hook_loop(self, combined_script: Path, wait_s: float) -> None:
        """Keep Frida attached to ``package_name`` for the whole detonation window.

        Shells out to the ``frida`` CLI rather than the raw Python bindings.
        The bindings looked more robust on paper but ``Java.perform`` needs
        ``frida-java-bridge``, which the CLI loads lazily via its own
        message-driven bridge protocol (`frida_tools.application
        .try_handle_bridge_request` / `frida_tools/repl.py`'s
        `_create_repl_script()` machinery) -- replicating that faithfully
        from scratch was out of scope, and every attempt to call
        `session.create_script()` directly on a script using `Java.*`
        failed with ``ReferenceError: Java is not defined`` even after
        manually answering the ``frida:load-bridge`` handshake, since the
        REPL's lazy-global proxy is wired into its own agent wrapper, not
        exposed by plain ``create_script``. The CLI already gets this
        right; the two things it *actually* gets wrong are fixed here
        instead:

        1. **Attach target.** `frida -U <package_name> -l script` fails
           with a misleading "Failed to spawn: unable to find process with
           name '...'" on this frida-tools/Android combination, even when
           `frida-ps -Uai` lists the exact identifier. `frida -U <pid> -l
           script` (resolved via `adb shell pidof`, see `_wait_for_pid`)
           attaches reliably -- confirmed against both test samples.
        2. **Output format.** The CLI's non-interactive REPL output for a
           `send()` call is a Python-repr-style line such as
           ``[Android Emulator 5554::PID::21717 ]-> message: {'type':
           'send', 'payload': {...}} data: None`` -- not JSON. The old
           code did `json.loads()` on every stdout line, so every hook
           that *did* fire was silently discarded (`_generate_dynamic_json`
           would just skip the `JSONDecodeError`). ``_parse_frida_cli_line``
           extracts the dict with bracket/string-aware scanning (not naive
           string splitting -- this is a malware sandbox, the payload text
           is adversarial) and re-emits it as real JSON.

        DroidBot can force-stop/restart the target (observed as tight as
        every 2-3s on a splash-loop sample), which kills the frida
        subprocess along with it. Rather than treating that as terminal,
        this loop re-resolves the PID and relaunches `frida` for as long as
        the detonation window lasts, so a flaky target still gets hooked
        during whatever windows it's up -- confirmed on the SBI sample:
        7 separate (re)attachments across one 90s run.
        """
        deadline = time.monotonic() + wait_s
        log_f = open(self.frida_log_path, "a")
        try:
            while not self._frida_stop_event.is_set() and time.monotonic() < deadline:
                pid = self._wait_for_pid(
                    timeout_s=min(60.0, max(1.0, deadline - time.monotonic()))
                )
                if pid is None:
                    break  # target never came up again before the window closed

                proc = subprocess.Popen(
                    ["frida", "-U", str(pid), "-l", str(combined_script)],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                )
                remaining = max(1.0, deadline - time.monotonic())
                killer = threading.Timer(remaining, proc.terminate)
                killer.start()
                try:
                    saw_attach = False
                    for line in proc.stdout:  # blocks until proc exits/closes stdout
                        if self._frida_stop_event.is_set():
                            proc.terminate()
                            break
                        parsed = self._parse_frida_cli_line(line)
                        if parsed is None:
                            continue
                        if parsed.get("type") == "send":
                            if not saw_attach:
                                saw_attach = True
                                self._frida_attached = True
                                log.info("attached Frida + loaded hooks on %s (pid %d)",
                                          self.package_name, pid)
                            log_f.write(json.dumps(
                                {"type": "send", "payload": parsed.get("payload")}
                            ) + "\n")
                            log_f.flush()
                        elif parsed.get("type") == "error":
                            log.debug("frida script error for %s (pid %d): %s",
                                      self.package_name, pid, parsed.get("stack") or parsed)
                finally:
                    killer.cancel()
                    proc.stdout.close()
                    try:
                        proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                # Loop back around: if the target died (DroidBot restart)
                # and time remains, _wait_for_pid picks it back up.
        finally:
            log_f.close()

    @staticmethod
    def _parse_frida_cli_line(line: str) -> dict | None:
        """Extract the ``{'type': ..., 'payload': {...}}`` dict from one line
        of `frida` CLI REPL output, e.g.::

            [Android Emulator 5554::PID::21717 ]-> message: {'type': 'send', 'payload': {...}} data: None

        Bracket- and string-aware (tracks quotes so a payload string
        containing ``}`` or the literal text `` data: `` -- plausible in
        adversarial malware output -- can't truncate the match early), then
        parsed with ``ast.literal_eval`` (safe for dict/str/int/etc.
        literals; never ``eval``, since this is untrusted sandboxed output).
        """
        marker = "message:"
        idx = line.find(marker)
        if idx == -1:
            return None
        rest = line[idx + len(marker):]
        start = rest.find("{")
        if start == -1:
            return None

        depth = 0
        in_str = False
        str_ch = ""
        escape = False
        end = None
        for i in range(start, len(rest)):
            ch = rest[i]
            if in_str:
                if escape:
                    escape = False
                elif ch == "\\":
                    escape = True
                elif ch == str_ch:
                    in_str = False
                continue
            if ch in ("'", '"'):
                in_str = True
                str_ch = ch
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    end = i
                    break
        if end is None:
            return None
        try:
            parsed = ast.literal_eval(rest[start:end + 1])
        except (ValueError, SyntaxError):
            return None
        return parsed if isinstance(parsed, dict) else None

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    def cleanup(self, safety: DetonationSafety | None = None) -> None:
        """Kill proxy, cancel pending SMS injections, and uninstall app.

        *safety* is the same ``DetonationSafety`` instance used to enforce
        isolation in ``run()``, so teardown (``post_restore()``) mirrors the
        exact enforcement that was applied. Falls back to a fresh instance
        for standalone/manual cleanup calls.
        """
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
            (safety or DetonationSafety(device_serial=self.device_serial)).post_restore()
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
        safety = DetonationSafety(device_serial=self.device_serial)
        issues = safety.pre_check()
        if issues:
            raise DetonationSafetyError(issues)

        elapsed_s = 0.0
        try:
            safety.enforce_isolation()
            ProxyManager(device_serial=self.device_serial).up()  # DNS blackhole + system proxy
            self.start_network_interception()  # must be listening before the reachability check below

            verify_issues = safety.verify_isolation()
            if verify_issues:
                raise DetonationSafetyError(verify_issues)

            self._ensure_frida_server()
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
            self.cleanup(safety)
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
    parser.add_argument(
        "--no-auto-launch-emulator", action="store_true",
        help="Do not auto-launch tools/launch_emulator.sh if no ADB device "
             "is attached -- fail immediately instead (default: auto-launch)",
    )
    args = parser.parse_args()

    try:
        orch = L2Orchestrator(
            apk_path=Path(args.apk),
            package_name=args.package,
            detonation_time_s=args.time,
            droidbot_duration_s=args.droidbot_time,
            auto_launch_emulator=not args.no_auto_launch_emulator,
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
