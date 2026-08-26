"""Tests for L2/sandbox/safety.py -- iptables chain wiring and isolation
verification, per decisions/plan_l2_network_isolation.md N6.

All adb/iptables calls are mocked; no emulator is required.
"""

from __future__ import annotations

import subprocess
from unittest import mock

import pytest

from L2.sandbox.safety import DetonationSafety


def _ok(stdout: str = "", returncode: int = 0) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr="")


@pytest.fixture(autouse=True)
def _fake_adb_on_path():
    """Make _find_adb() resolve without touching the real filesystem/PATH."""
    with mock.patch("L2.sandbox.safety.shutil.which", return_value="/usr/bin/adb"):
        yield


def _ipt_calls(run_mock: mock.Mock) -> list[list[str]]:
    """Extract just the iptables argv (as passed to `adb shell su 0 iptables ...`)
    from every subprocess.run call recorded by the mock."""
    calls = []
    for call in run_mock.call_args_list:
        argv = call.args[0]
        if "iptables" in argv:
            # Trim down to the args after "iptables" for readability.
            idx = argv.index("iptables")
            calls.append(argv[idx + 1:])
    return calls


class TestEnforceIsolationChainWiring:
    def test_creates_and_jumps_chain_before_flush(self):
        """N6.1: -N st_OUTPUT, -D OUTPUT -j st_OUTPUT, -I OUTPUT -j st_OUTPUT
        must appear, in that order, before the flush/append/DROP sequence."""
        with mock.patch("subprocess.run", return_value=_ok()) as run_mock:
            safety = DetonationSafety(device_serial="emulator-5554")
            safety.enforce_isolation()

        calls = _ipt_calls(run_mock)

        create_idx = calls.index(["-N", "st_OUTPUT"])
        del_jump_idx = calls.index(["-D", "OUTPUT", "-j", "st_OUTPUT"])
        insert_jump_idx = calls.index(["-I", "OUTPUT", "-j", "st_OUTPUT"])
        flush_idx = calls.index(["-F", "st_OUTPUT"])

        assert create_idx < del_jump_idx < insert_jump_idx < flush_idx

    def test_enforce_isolation_idempotent_across_two_calls(self):
        """N6.2: calling enforce_isolation() twice does not raise, even when
        the mocked adb/iptables reports non-zero ("chain already exists")."""
        with mock.patch("subprocess.run", return_value=_ok(returncode=1)):
            safety = DetonationSafety(device_serial="emulator-5554")
            safety.enforce_isolation()
            safety.enforce_isolation()  # must not raise


class TestPostRestore:
    def test_removes_output_jump_not_just_chain_contents(self):
        """N6.3: post_restore() removes the OUTPUT -> st_OUTPUT jump, not
        just the chain's own contents."""
        with mock.patch("subprocess.run", return_value=_ok()) as run_mock:
            safety = DetonationSafety(device_serial="emulator-5554")
            safety.post_restore()

        calls = _ipt_calls(run_mock)
        assert ["-F", "st_OUTPUT"] in calls
        assert ["-D", "OUTPUT", "-j", "st_OUTPUT"] in calls


class TestVerifyIsolation:
    def test_returns_issue_when_ping_succeeds(self):
        """N6.4a: a successful ping to 8.8.8.8 means isolation failed."""

        def fake_run(argv, **kwargs):
            if "ping" in argv:
                return _ok(returncode=0)
            return _ok(returncode=0)  # curl proxy check succeeds too

        with mock.patch("subprocess.run", side_effect=fake_run):
            safety = DetonationSafety(device_serial="emulator-5554")
            issues = safety.verify_isolation()

        assert issues
        assert any("8.8.8.8" in issue or "internet" in issue for issue in issues)

    def test_empty_when_ping_fails_and_proxy_reachable(self):
        """N6.4b: ping failing is the *safe* outcome -- combined with a
        reachable proxy path, verify_isolation() returns no issues."""

        def fake_run(argv, **kwargs):
            if "ping" in argv:
                return _ok(returncode=1)  # ping failed -- safe
            return _ok(returncode=0)  # curl proxy check succeeds

        with mock.patch("subprocess.run", side_effect=fake_run):
            safety = DetonationSafety(device_serial="emulator-5554")
            issues = safety.verify_isolation()

        assert issues == []

    def test_empty_when_ping_times_out(self):
        """Ping timing out is also the safe outcome, not an error."""

        def fake_run(argv, **kwargs):
            if "ping" in argv:
                raise subprocess.TimeoutExpired(cmd=argv, timeout=2)
            return _ok(returncode=0)

        with mock.patch("subprocess.run", side_effect=fake_run):
            safety = DetonationSafety(device_serial="emulator-5554")
            issues = safety.verify_isolation()

        assert issues == []


class TestPreCheckNoLongerPingsExternal:
    def test_pre_check_does_not_call_ping(self):
        """N6.5: pre_check() no longer references the ping-to-8.8.8.8 check
        (moved to verify_isolation() per N4's split)."""
        with mock.patch("subprocess.run", return_value=_ok()) as run_mock:
            safety = DetonationSafety(device_serial="emulator-5554")
            issues = safety.pre_check()

        assert issues == []
        for call in run_mock.call_args_list:
            argv = call.args[0]
            assert "ping" not in argv, f"pre_check() unexpectedly called ping: {argv}"
