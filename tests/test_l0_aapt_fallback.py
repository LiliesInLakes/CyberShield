"""L0's aapt fallback for manifests androguard cannot parse.

The motivating real sample is the "Bank of lndia" typosquat (note the
lowercase L): its AndroidManifest.xml is deliberately corrupted to defeat
static parsers -- resource type names padded with invisible U+3164 filler,
false chunk sizes -- so androguard's `get_package()` returns None, which
would make L2 skip detonation for lack of a package to `am start`. aapt
(Android's own installer-time parser, already shipped in the bundled SDK)
tolerates the corruption and recovers the package.

These tests mock `subprocess.run` with canned aapt output so they need
neither a real aapt binary nor a real (malicious) sample on disk; a
skip-guarded live test at the end exercises the real thing when both are
available.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(REPO_ROOT / "L0") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "L0"))

import pytest  # noqa: E402

from L0 import ingest  # noqa: E402


# Real aapt output shape, captured from the actual "Bank of lndia" sample.
_AAPT_OUTPUT = (
    "package: name='com.tomo.tozy.naki' versionCode='1' versionName='1.0' "
    "platformBuildVersionName='14' compileSdkVersion='34'\n"
    "sdkVersion:'21'\n"
    "targetSdkVersion:'34'\n"
    "uses-permission: name='android.permission.INTERNET'\n"
    "uses-permission: name='android.permission.REQUEST_INSTALL_PACKAGES'\n"
    "application-label:'Bank of lndia'\n"
    "application: label='Bank of lndia' icon='res/mipmap/ic.png'\n"
)


class _FakeCompleted:
    def __init__(self, stdout, returncode=0):
        self.stdout = stdout
        self.returncode = returncode


def _patch_aapt(monkeypatch, output, returncode=0, found=True):
    monkeypatch.setattr(ingest, "_find_aapt",
                        lambda: "/fake/aapt" if found else None)
    monkeypatch.setattr(ingest.subprocess, "run",
                        lambda *a, **k: _FakeCompleted(output, returncode))


# --------------------------------------------------------------------------
# _aapt_badging parsing
# --------------------------------------------------------------------------

def test_aapt_badging_parses_package_and_fields(monkeypatch):
    _patch_aapt(monkeypatch, _AAPT_OUTPUT)
    got = ingest._aapt_badging(Path("whatever.apk"))
    assert got is not None
    assert got["package_name"] == "com.tomo.tozy.naki"
    assert got["app_label"] == "Bank of lndia"
    assert got["version_name"] == "1.0"
    assert got["min_sdk"] == "21"
    assert got["target_sdk"] == "34"
    assert "android.permission.REQUEST_INSTALL_PACKAGES" in got["permissions"]
    assert got["recovered_via"] == "aapt"


def test_aapt_badging_returns_none_when_no_package_line(monkeypatch):
    # aapt ran but recovered nothing usable -> None, never a partial dict.
    _patch_aapt(monkeypatch, "some warnings but no package line\n")
    assert ingest._aapt_badging(Path("x.apk")) is None


def test_aapt_badging_returns_none_when_aapt_absent(monkeypatch):
    _patch_aapt(monkeypatch, _AAPT_OUTPUT, found=False)
    assert ingest._aapt_badging(Path("x.apk")) is None


def test_aapt_badging_survives_subprocess_failure(monkeypatch):
    monkeypatch.setattr(ingest, "_find_aapt", lambda: "/fake/aapt")

    def _boom(*a, **k):
        raise subprocess.TimeoutExpired(cmd="aapt", timeout=60)

    monkeypatch.setattr(ingest.subprocess, "run", _boom)
    assert ingest._aapt_badging(Path("x.apk")) is None


def test_aapt_badging_parses_even_on_nonzero_exit(monkeypatch):
    # aapt exits non-zero on some malformed inputs but still prints a usable
    # package line first -- we parse stdout regardless of return code.
    _patch_aapt(monkeypatch, _AAPT_OUTPUT, returncode=1)
    got = ingest._aapt_badging(Path("x.apk"))
    assert got is not None and got["package_name"] == "com.tomo.tozy.naki"


# --------------------------------------------------------------------------
# harvest_manifest: fallback fills blanks ONLY, never overrides androguard
# --------------------------------------------------------------------------

class _FakeAPK:
    """Minimal APK stand-in exposing only what harvest_manifest reads."""
    def __init__(self, package=None, label="", perms=()):
        self._package = package
        self._label = label
        self._perms = list(perms)

    def get_permissions(self):
        return self._perms

    def get_package(self):
        return self._package

    def get_app_name(self):
        return self._label

    def get_androidversion_name(self):
        return None

    def get_androidversion_code(self):
        return None

    def get_min_sdk_version(self):
        return None

    def get_target_sdk_version(self):
        return None


def test_harvest_uses_fallback_when_androguard_has_no_package(monkeypatch):
    _patch_aapt(monkeypatch, _AAPT_OUTPUT)
    apk = _FakeAPK(package=None, label="", perms=[])
    m = ingest.harvest_manifest(apk, Path("x.apk"))
    assert m["package_name"] == "com.tomo.tozy.naki"
    assert m["app_label"] == "Bank of lndia"
    assert m["manifest_parse_fallback"] == "aapt"
    # the dropper permission recovered by aapt must be counted as high-risk
    assert "android.permission.REQUEST_INSTALL_PACKAGES" in m["high_risk_permissions"]


def test_harvest_does_not_touch_fallback_when_androguard_has_package(monkeypatch):
    # If androguard read a package, aapt must never be consulted -- guard
    # against the fallback silently overriding a good primary read.
    called = {"aapt": False}

    def _tripwire():
        called["aapt"] = True
        return "/fake/aapt"

    monkeypatch.setattr(ingest, "_find_aapt", _tripwire)
    apk = _FakeAPK(package="com.real.app", label="Real App",
                   perms=["android.permission.INTERNET"])
    m = ingest.harvest_manifest(apk, Path("x.apk"))
    assert m["package_name"] == "com.real.app"
    assert m.get("manifest_parse_fallback") is None
    assert called["aapt"] is False


def test_harvest_without_apk_path_skips_fallback(monkeypatch):
    # Old call sites that don't pass apk_path must still work (no crash),
    # just without the fallback.
    _patch_aapt(monkeypatch, _AAPT_OUTPUT)
    apk = _FakeAPK(package=None)
    m = ingest.harvest_manifest(apk)  # no apk_path
    assert m["package_name"] is None
    assert m.get("manifest_parse_fallback") is None


# --------------------------------------------------------------------------
# Live (skip-guarded): the real sample + real aapt
# --------------------------------------------------------------------------

def test_live_aapt_recovers_sabotaged_manifest():
    sample = REPO_ROOT / "testing_apps" / "unknown" / "Bank of lndia.apk"
    if not sample.is_file():
        pytest.skip("live test: sabotaged sample not present in this checkout")
    if ingest._find_aapt() is None:
        pytest.skip("live test: aapt not installed (needs the bundled Android SDK)")
    got = ingest._aapt_badging(sample)
    assert got is not None
    assert got["package_name"] == "com.tomo.tozy.naki"
