# Decision: L2 Dynamic Analysis Code Fixes

**Date:** 2026-08-13 (initial fixes), 2026-08-14 (Phase 1+2 implementation)
**Status:** Phase 1+2 implemented, Phase 3+4 pending
**Scope:** L2/l2_engine.py, L2/__init__.py, L2/sandbox/{honeypot,orchestrator,mitm_addon,__init__}.py, L2/sandbox/frida_scripts/{stealth_init,ssl_unpin,dynamic_hooks}.js, L2/sandbox/{proxy_setup,install_ca,pcap_capture}.py

## Context

L2 was the only evidence layer never wired to the spine and marked
non-functional in CLAUDE.md.  The code had several issues preventing it
from running -- even in the degraded "no emulator" mode that the rest of
the pipeline needs in order to record an honest `l2: skipped` status
instead of crashing or leaving `not_attempted`.

## Problems fixed

### 1. Broken imports (l2_engine.py)

The engine manipulated `sys.path` to add both the repo root *and* `L1/`
so it could do `from schema import ...`.  This is fragile (shadows any
other `schema` module on the path) and inconsistent with how every other
layer imports.  Replaced with `from L1.schema import ...` after adding
only the repo root to `sys.path`.

### 2. No graceful degradation (l2_engine.py)

`process()` would crash or produce confusing tracebacks when no sandbox
artifacts existed.  Now it:
- Catches `OSError` / `JSONDecodeError` when scanning candidate dirs
- Writes a valid `analysis.json` with zero findings when nothing is found
- Updates the spine with `status=skipped` (via promote.l2_status_for)
- Wraps the spine update in a try/except so a spine failure does not
  prevent the analysis artifact from being written

The CLI `main()` now prints a clear message:
`[L2] no sandbox artifacts found -- wrote skipped record`

### 3. Spine integration extracted (l2_engine.py)

The spine update was inlined at the bottom of `process()` with late
`import spine` / `from L2 import promote`.  Extracted to
`_update_spine()` -- same pattern as L0/L1: a helper that calls
`spine.update_layer()` as the single writer.

### 4. orchestrator.py rewrite

- Added `from __future__ import annotations` and type hints throughout
- Converted from bare class to `@dataclass`
- Fixed `from honeypot import HoneypotSeeder` (bare import, would fail
  when run from outside the sandbox directory) to
  `from L2.sandbox.honeypot import ...`
- `_get_device()` now checks for `adb` on PATH before calling it, and
  raises `EmulatorUnavailableError` with a message referencing T14
- Added `shutil.which()` guards for `frida` and `mitmproxy` -- missing
  tools log a warning instead of crashing
- Added timeouts to all subprocess calls
- Added a `run()` method that executes the full pipeline with cleanup
  in a `finally` block
- Hardcoded relative paths replaced with `Path(__file__).resolve().parent`

### 5. honeypot.py rewrite

- Added `from __future__ import annotations`, type hints, `@dataclass`
- `device_serial: str = None` fixed to `str | None = None`
- Added `shutil.which("adb")` guard -- returns empty string instead of
  crashing when ADB is missing
- Added `subprocess.TimeoutExpired` handling (30s timeout per command)
- `run_all()` returns a list of warnings for the caller to inspect
- Introduced `EmulatorUnavailableError` exception class (shared with
  orchestrator)

### 6. mitm_addon.py fixes

- Added `from __future__ import annotations` and type hints
- Hardcoded relative path `Path("L2/sandbox/artifacts/...")` replaced
  with `Path(__file__).resolve().parent / "artifacts" / ...` so the
  addon works regardless of mitmproxy's working directory
- Guarded `from mitmproxy import http` with try/except so the module
  can be imported for testing without mitmproxy installed
- Extracted magic strings into module-level constants
  (`_EXFIL_KEYWORDS`, `_BANK_HOSTS`)

### 7. Package init files

- `L2/__init__.py`: was empty, now has a docstring explaining the layer
  and its degradation contract
- `L2/sandbox/__init__.py`: was empty, now has a one-line docstring

## Style compliance

All files now use:
- `from __future__ import annotations`
- `dataclasses` where appropriate
- `pathlib.Path` (no string path manipulation)
- Type hints on all function signatures
- `logging` module instead of bare `print()`

## Tests

All 11 existing tests in `tests/test_l2_promote.py` pass unchanged.
The promote module (`L2/promote.py`) was already correct and required
no changes.

Verified manually:
- `process()` with no sandbox artifacts writes analysis.json + spine skipped
- `L2Orchestrator` raises `EmulatorUnavailableError` with clear message
- All L2 module imports succeed cleanly

---

## Phase 1 implementation (2026-08-14, Sonnet agent)

### 1a. DroidBot integration (`orchestrator.py`)

PyPI `droidbot` (1.0.0a2) is broken — unqualified imports and shadows stdlib
`types`. Installed from GitHub: `git+https://github.com/honeynet/droidbot.git`
(1.0.2b4), plus `setuptools<81` and `standard-telnetlib` for Python 3.14 compat.

`detonate()` now launches DroidBot (`-policy dfs_greedy -timeout <N> -grant_perm
-is_emulator -keep_app`) as the interaction engine. Frida polls `frida-ps -U`
for the process DroidBot launches, then attaches with combined
stealth+hooks script. UTG artifacts written to `artifacts/<pkg>/droidbot_utg/`.

### 1b. Permission auto-grant (`orchestrator.py`)

`grant_permissions()`: pre-grants READ_SMS, RECEIVE_SMS, SEND_SMS,
READ_PHONE_STATE, READ_CONTACTS, ACCESS_FINE_LOCATION via `pm grant`, plus
`appops set SYSTEM_ALERT_WINDOW allow`.

`enable_accessibility_service()`: reads AndroidManifest via androguard to find
services requiring BIND_ACCESSIBILITY_SERVICE, sets `enabled_accessibility_services`
+ `accessibility_enabled` via adb settings.

### 1c. Runtime SMS injection (`honeypot.py`)

`OTP_TEMPLATES` with SBI/HDFC/ICICI bank OTP formats. `send_emu_sms()` wraps
`adb emu sms send`. Orchestrator fires them at T+10/20/30s via
`threading.Timer`, cancelled in cleanup.

### 1d. Stealth extensions (`stealth_init.js`)

Five new hook blocks: sensor jitter (accelerometer/gyroscope via
`SensorEventListener.onSensorChanged`), battery spoof (73%, discharging via
`BatteryManager`), package hiding (Magisk/Xposed/SuperSU via `getPackageInfo`
throwing `NameNotFoundException`), WiFi spoof (MAC/SSID/BSSID → JioFiber-5G),
`/proc/cpuinfo` access logging via `FileInputStream.$init`.

---

## Phase 2 implementation (2026-08-14, Sonnet agent)

### 2a. SSL unpinning (`frida_scripts/ssl_unpin.js`, new)

Universal bypass: `SSLContext.init()` TrustManager hijack, OkHttp3
`CertificatePinner.check()` (both overloads), Conscrypt
`TrustManagerImpl.verifyChain()`/`checkTrusted()`, `WebViewClient.onReceivedSslError()`.
Each bypass sends `{type: "ssl_unpin", ...}` for evidence collection.

### 2b. CA installation (`install_ca.py`, new)

Converts `~/.mitmproxy/mitmproxy-ca-cert.pem` to Android system cert format via
`openssl x509 -subject_hash_old`, pushes to `/system/etc/security/cacerts/`.
Idempotent via `is_installed()`. **Currently blocked** by read-only /system.

### 2c. Proxy setup (`proxy_setup.py`, new)

`ProxyManager`: `set_system_proxy()` (10.0.2.2:8080), iptables NAT REDIRECT for
ports 80/443, `apply_dns_redirects()` / `remove_dns_redirects()` for /etc/hosts
overrides (C2 domains → localhost, mtalk.google.com → 0.0.0.0). CLI: `up`/`down`/`verify`.

### 2d. PCAP capture (`pcap_capture.py`, new)

`PcapCapture.start()` launches `adb shell su 0 tcpdump -i any -w /sdcard/capture.pcap`.
`stop_and_pull(dest_dir)` sends SIGINT to tcpdump and pulls the file.

### 2e. mitm_addon.py updates

Removed incorrect FCM HTTP interception (FCM uses binary MCS on port 5228, not HTTP).
Added fake responses for Indian banking/UPI endpoints (login, OTP verify, MPIN, balance).
Added `_is_bulk_exfil()` (POST ≥ 1KB to non-CDN host) and `_decode_base64_payload()`
for detecting encoded credential exfiltration.

## Infrastructure test results (2026-08-14)

| Component | Result |
|---|---|
| System proxy (10.0.2.2:8080) | ✅ works |
| iptables transparent redirect (80/443) | ✅ works |
| PCAP capture (tcpdump) | ✅ works (256 bytes captured from ping) |
| Frida script loading (ssl_unpin.js) | ✅ loads (needs Java process to activate hooks) |
| DNS redirect (/etc/hosts) | ❌ blocked — /system read-only |
| CA cert installation | ❌ blocked — /system read-only |
| Detonation test (SBI Quick Support) | ⏳ script ready, not yet executed |
