"""Unit tests for L2Orchestrator's device discovery / auto-launch and the
ssl_unpin.js wiring, mocked -- no real adb/emulator in this environment.

Instances are built with ``L2Orchestrator.__new__`` to bypass
``__post_init__`` (which itself calls ``_ensure_device`` and needs a real
apk file on disk) -- these tests exercise the device-discovery methods
directly instead.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import pytest  # noqa: E402

from L2.sandbox import orchestrator as orch_mod  # noqa: E402
from L2.sandbox.honeypot import EmulatorUnavailableError  # noqa: E402
from L2.sandbox.orchestrator import L2Orchestrator  # noqa: E402


def _bare_orchestrator(**attrs) -> L2Orchestrator:
    orch = L2Orchestrator.__new__(L2Orchestrator)
    orch.auto_launch_emulator = attrs.get("auto_launch_emulator", True)
    return orch


def test_ssl_unpin_is_in_required_scripts():
    """The bug found while implementing N5 of the network-isolation plan:
    ssl_unpin.js existed on disk but was never bundled into combined_runner.js,
    so HTTPS pinning bypass was never actually active. Guard against it
    silently regressing again."""
    import inspect
    src = inspect.getsource(L2Orchestrator.detonate)
    assert "ssl_unpin_path" in src
    assert "ssl_unpin_path" in src[src.index("required_scripts"):src.index("required_scripts") + 300]


def test_list_devices_returns_booted_serials(monkeypatch):
    monkeypatch.setattr(orch_mod.shutil, "which", lambda name: "/usr/bin/adb")
    monkeypatch.setattr(
        orch_mod.subprocess, "run",
        lambda *a, **k: subprocess.CompletedProcess(
            a[0], 0, stdout="List of devices attached\nemulator-5554\tdevice\n", stderr=""),
    )
    devices = L2Orchestrator._list_devices()
    assert devices == ["emulator-5554"]


def test_list_devices_ignores_offline(monkeypatch):
    monkeypatch.setattr(orch_mod.shutil, "which", lambda name: "/usr/bin/adb")
    monkeypatch.setattr(
        orch_mod.subprocess, "run",
        lambda *a, **k: subprocess.CompletedProcess(
            a[0], 0, stdout="List of devices attached\nemulator-5554\toffline\n", stderr=""),
    )
    assert L2Orchestrator._list_devices() == []


def test_list_devices_raises_when_adb_missing(monkeypatch):
    monkeypatch.setattr(orch_mod.shutil, "which", lambda name: None)
    with pytest.raises(EmulatorUnavailableError):
        L2Orchestrator._list_devices()


def test_ensure_device_returns_existing_device_without_launching(monkeypatch):
    orch = _bare_orchestrator()
    monkeypatch.setattr(L2Orchestrator, "_list_devices", staticmethod(lambda: ["emulator-5554"]))
    launched = {"called": False}
    monkeypatch.setattr(orch, "_launch_emulator_and_wait",
                        lambda: launched.__setitem__("called", True) or "emulator-5554")
    assert orch._ensure_device() == "emulator-5554"
    assert launched["called"] is False


def test_ensure_device_auto_launches_when_no_device(monkeypatch):
    orch = _bare_orchestrator(auto_launch_emulator=True)
    monkeypatch.setattr(L2Orchestrator, "_list_devices", staticmethod(lambda: []))
    monkeypatch.setattr(orch, "_launch_emulator_and_wait", lambda: "emulator-5554")
    assert orch._ensure_device() == "emulator-5554"


def test_ensure_device_raises_when_auto_launch_disabled(monkeypatch):
    orch = _bare_orchestrator(auto_launch_emulator=False)
    monkeypatch.setattr(L2Orchestrator, "_list_devices", staticmethod(lambda: []))
    with pytest.raises(EmulatorUnavailableError, match="auto-launch is disabled"):
        orch._ensure_device()


def test_ensure_device_raises_when_auto_launch_fails(monkeypatch):
    orch = _bare_orchestrator(auto_launch_emulator=True)
    monkeypatch.setattr(L2Orchestrator, "_list_devices", staticmethod(lambda: []))
    monkeypatch.setattr(orch, "_launch_emulator_and_wait", lambda: None)
    with pytest.raises(EmulatorUnavailableError, match="auto-launch failed"):
        orch._ensure_device()


def test_launch_emulator_and_wait_returns_none_if_script_missing(monkeypatch):
    orch = _bare_orchestrator()
    monkeypatch.setattr(orch_mod, "_LAUNCH_EMULATOR_SH", Path("/nonexistent/launch_emulator.sh"))
    assert orch._launch_emulator_and_wait() is None


def test_launch_emulator_and_wait_polls_until_boot_completed(monkeypatch, tmp_path):
    fake_script = tmp_path / "launch_emulator.sh"
    fake_script.write_text("#!/bin/bash\n")
    monkeypatch.setattr(orch_mod, "_LAUNCH_EMULATOR_SH", fake_script)
    monkeypatch.setattr(orch_mod, "_EMULATOR_BOOT_TIMEOUT_S", 30)
    monkeypatch.setattr(orch_mod.time, "sleep", lambda s: None)

    popen_calls = []
    monkeypatch.setattr(orch_mod.subprocess, "Popen",
                        lambda *a, **k: popen_calls.append((a, k)))

    # First poll: no devices yet. Second poll: device attached but not booted.
    # Third poll: booted.
    poll_state = {"n": 0}

    def fake_list_devices():
        poll_state["n"] += 1
        return ["emulator-5554"] if poll_state["n"] >= 2 else []

    def fake_run(cmd, **kwargs):
        boot_value = "1" if poll_state["n"] >= 3 else "0"
        return subprocess.CompletedProcess(cmd, 0, stdout=boot_value, stderr="")

    orch = _bare_orchestrator()
    monkeypatch.setattr(L2Orchestrator, "_list_devices", staticmethod(fake_list_devices))
    monkeypatch.setattr(orch_mod.subprocess, "run", fake_run)

    serial = orch._launch_emulator_and_wait()
    assert serial == "emulator-5554"
    assert popen_calls, "emulator launch subprocess was started"
    assert popen_calls[0][1].get("start_new_session") is True


def test_launch_emulator_and_wait_times_out(monkeypatch, tmp_path):
    fake_script = tmp_path / "launch_emulator.sh"
    fake_script.write_text("#!/bin/bash\n")
    monkeypatch.setattr(orch_mod, "_LAUNCH_EMULATOR_SH", fake_script)
    monkeypatch.setattr(orch_mod, "_EMULATOR_BOOT_TIMEOUT_S", 0)
    monkeypatch.setattr(orch_mod.subprocess, "Popen", lambda *a, **k: None)
    monkeypatch.setattr(L2Orchestrator, "_list_devices", staticmethod(lambda: []))

    orch = _bare_orchestrator()
    assert orch._launch_emulator_and_wait() is None


def test_wait_for_pid_resolves_via_pidof(monkeypatch):
    """`pidof` returning a bare numeric PID is a hit -- no frida-tools
    name/identifier resolution involved (see the historical note in
    `_wait_for_pid`'s docstring: frida-tools 17.17.0 fails to attach by
    package identifier on this Android target even when `frida-ps -Uai`
    lists it correctly, so the orchestrator resolves a PID directly)."""
    orch = _bare_orchestrator()
    orch.device_serial = "emulator-5554"
    orch.package_name = "com.sbi.complaintregister"

    def fake_adb(*args):
        assert args == ("shell", "pidof", "com.sbi.complaintregister")
        return subprocess.CompletedProcess(args, 0, stdout="7126\n", stderr="")

    monkeypatch.setattr(orch, "_adb", fake_adb)
    assert orch._wait_for_pid(timeout_s=1.0) == 7126


def test_wait_for_pid_times_out_when_absent(monkeypatch):
    orch = _bare_orchestrator()
    orch.device_serial = "emulator-5554"
    orch.package_name = "com.sbi.complaintregister"

    def fake_adb(*args):
        return subprocess.CompletedProcess(args, 1, stdout="", stderr="")

    monkeypatch.setattr(orch, "_adb", fake_adb)
    monkeypatch.setattr(orch_mod.time, "sleep", lambda s: None)
    assert orch._wait_for_pid(timeout_s=0.01) is None


def test_ensure_frida_server_noop_when_already_running(monkeypatch):
    """Root cause of every silent zero-hooks run: nothing deployed
    frida-server, and `-wipe-data` boots wipe any manually-started one.
    When it's already up, don't touch anything on the device."""
    orch = _bare_orchestrator()
    orch.device_serial = "emulator-5554"

    def fake_adb(*args):
        assert args == ("shell", "pidof", "frida-server")
        return subprocess.CompletedProcess(args, 0, stdout="21882\n", stderr="")

    monkeypatch.setattr(orch, "_adb", fake_adb)
    monkeypatch.setattr(orch_mod.subprocess, "run",
                         lambda *a, **k: (_ for _ in ()).throw(
                             AssertionError("should not push/start when already running")))
    orch._ensure_frida_server()  # must not raise / must not push


def test_ensure_frida_server_pushes_and_starts_when_absent(monkeypatch, tmp_path):
    orch = _bare_orchestrator()
    orch.device_serial = "emulator-5554"

    (tmp_path / "tools").mkdir()
    (tmp_path / "tools" / "frida-server").write_bytes(b"\x00")
    monkeypatch.setattr(orch_mod, "_REPO_ROOT", tmp_path)

    calls: list[tuple] = []
    # pidof is polled twice: once up front (absent -> triggers deploy) and
    # once after start (present -> confirms it came up).
    pidof_results = iter([
        subprocess.CompletedProcess((), 1, stdout="", stderr=""),
        subprocess.CompletedProcess((), 0, stdout="9999\n", stderr=""),
    ])

    def fake_adb(*args):
        calls.append(args)
        if args[:2] == ("shell", "pidof"):
            return next(pidof_results)
        return subprocess.CompletedProcess(args, 0, stdout="", stderr="")

    monkeypatch.setattr(orch, "_adb", fake_adb)
    monkeypatch.setattr(orch_mod.subprocess, "run",
                         lambda *a, **k: subprocess.CompletedProcess(a, 0, stdout="", stderr=""))
    monkeypatch.setattr(orch_mod.time, "sleep", lambda s: None)

    orch._ensure_frida_server()

    assert any(c[0] == "push" for c in calls)


def test_parse_frida_cli_line_extracts_send_payload():
    """The `frida` CLI's non-interactive REPL output for send() is a
    Python-repr line, not JSON -- `[dev]-> message: {'type': 'send',
    'payload': {...}} data: None`. Confirmed live: json.loads() on this
    silently discarded every hook that fired (JSONDecodeError -> skipped),
    so every prior "confidence: high, 0 findings" run was actually blind."""
    line = ("[Android Emulator 5554::PID::2630 ]->  message: "
            "{'type': 'send', 'payload': {'type': 'stealth', 'note': 'hook installed'}} "
            "data: None")
    parsed = L2Orchestrator._parse_frida_cli_line(line)
    assert parsed == {"type": "send", "payload": {"type": "stealth", "note": "hook installed"}}


def test_parse_frida_cli_line_ignores_non_message_lines():
    assert L2Orchestrator._parse_frida_cli_line("Connected to Android Emulator 5554") is None
    assert L2Orchestrator._parse_frida_cli_line("Failed to spawn: unable to find process") is None


def test_parse_frida_cli_line_survives_adversarial_payload_content():
    """A malware sample's own output is not trusted input: a payload string
    containing literal `}` or ` data: ` must not truncate the match early.
    Bracket/string-aware scanning (not `str.find`/`str.rfind` on ` data: `)
    is required for this to be safe against adversarial content."""
    line = ("[x]-> message: {'type': 'error', "
            "'stack': 'boom { with brace and } data: fakeout'} data: None")
    parsed = L2Orchestrator._parse_frida_cli_line(line)
    assert parsed == {"type": "error", "stack": "boom { with brace and } data: fakeout"}
