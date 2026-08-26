# Plan: L2 Phase 4 — dynamic.json, Spine Wiring, Detonation Safety

**Date:** 2026-08-14
**Status:** Draft
**Depends on:** Phase 1+2+3 (done), all tests passing
**Estimated effort:** ~4 hours (Sonnet agent)

---

## Context

Phase 1-3 built the sandbox machinery: DroidBot drives the app, Frida hooks
capture behaviours (stealth, auth fill/bypass, accessibility abuse, SSL unpin),
mitmproxy intercepts network traffic, and tcpdump captures packets. But the
artifacts these tools produce are raw — `frida_hooks.jsonl` is Frida's stdout,
`network_evidence.json` is mitmproxy addon output, and there's no `dynamic.json`
summary tying everything together.

`l2_engine.py` already knows how to parse `dynamic.json`, `frida_hooks.jsonl`,
and `network_evidence.json` into `L1Finding` objects and push them to the spine
via `promote.py`. But several gaps remain:

1. **No `dynamic.json` generation.** The orchestrator runs everything but doesn't
   produce the structured summary `l2_engine.py` expects.
2. **Phase 3 finding categories unmapped.** `l2_engine._CAT_MAP` doesn't know
   about `auth_fill`, `auth_bypass`, `auth_state`, `ssl_unpin`, or
   `accessibility_abuse` (the last one maps via enum value but the others don't).
3. **Frida hooks.jsonl format mismatch.** The orchestrator redirects Frida's
   stdout to `frida_hooks.jsonl`, which includes console.log lines mixed with
   JSON `send()` payloads. `_parse_frida_hooks` expects one JSON per line and
   skips non-JSON, so the `send()` output needs to be JSON-on-its-own-line.
   Actually, Frida CLI (`frida -l`) prints `send()` payloads as JSON to stdout,
   so this already works — but we need to verify the format.
4. **No PCAP pull or network evidence aggregation.** The orchestrator starts
   mitmproxy but doesn't pull PCAP or ensure `network_evidence.json` ends up
   in the right directory for `l2_engine.py`.
5. **No detonation safety checks.** Host-only networking verification, snapshot
   pre/post, and the go/no-go gate aren't wired.

---

## Tasks

### 4a. Generate `dynamic.json` in orchestrator (~1.5h)

**Where:** Edit `L2/sandbox/orchestrator.py`

**What:** After detonation completes (in `run()`, after `detonate()` returns but
before `cleanup()`), generate `dynamic.json` in `self.artifacts_dir`.

The file must match what `l2_engine._parse_dynamic_json` expects:

```json
{
  "package": "<package_name>",
  "sha256": "<sha256>",
  "sandbox": {
    "type": "droidbot+frida",
    "detonation_duration_s": <actual seconds>,
    "evasion_checks_bypassed": <count from stealth hooks>,
    "android_version": "11",
    "api_level": 30
  },
  "runtime_behaviors": {
    "sms_intercepted": <bool>,
    "overlay_displayed": <bool>,
    "clipboard_hijacked": <bool>,
    "files_dropped": <int>
  },
  "network": {
    "total_requests": <int>,
    "c2_endpoints": [],
    "exfiltration_detected": <bool>,
    "data_exfiltrated": []
  },
  "findings": [],
  "confidence": {
    "confidence_level": "medium"
  }
}
```

**How to populate it:**
- Parse `frida_hooks.jsonl` to count findings by category and extract behavioral
  flags: `sms_intercepted` = any finding with category `sms_exfiltration` or
  `send_sms`; `overlay_displayed` = category `overlay`; etc.
- Parse `network_evidence.json` (if exists) to count requests, extract C2
  endpoints and exfil flags
- `detonation_duration_s` = actual elapsed wall time (track with `time.monotonic()`)
- `evasion_checks_bypassed` = count of `type: "stealth"` entries in frida_hooks
- The `findings` array in dynamic.json should be empty (findings live in
  frida_hooks.jsonl and network_evidence.json, parsed separately by l2_engine)
- `confidence_level`: `"high"` if Frida attached + network captured + detonation
  ran full duration; `"medium"` if any one is partial; `"low"` if Frida never
  attached

Add a new method `_generate_dynamic_json(self, elapsed_s: float) -> None` that
does this parsing and writes the file.

**Also:** Add `sha256` parameter to `L2Orchestrator.__init__` (currently it only
takes `apk_path` and `package_name`). The sha256 is needed for dynamic.json and
for the l2_engine to key artifacts correctly. Compute it from the APK file if
not provided.

### 4b. Wire PCAP pull into orchestrator (~30m)

**Where:** Edit `L2/sandbox/orchestrator.py`

**What:** After detonation, before generating dynamic.json:
1. Import and use `PcapCapture` from `L2.sandbox.pcap_capture`
2. Call `pcap.start()` in `start_network_interception()`
3. Call `pcap.stop_and_pull(self.artifacts_dir)` after detonation
4. The pulled PCAP file goes to `self.artifacts_dir / "capture.pcap"`

### 4c. Copy network_evidence.json to artifacts dir (~30m)

**Where:** Edit `L2/sandbox/orchestrator.py`

**What:** The mitm_addon writes `network_evidence.json` to its own
`_DEFAULT_EVIDENCE_PATH` (`L2/sandbox/artifacts/network_evidence.json`). After
detonation, copy or move it to `self.artifacts_dir / "network_evidence.json"` so
`l2_engine.py` finds it in the package-keyed directory.

Also pass the evidence path to mitmproxy via environment variable or command-line
arg so it writes directly to the right artifacts dir. The addon reads
`_DEFAULT_EVIDENCE_PATH` — either extend the addon to accept a path arg, or
just copy the file after mitmproxy stops.

Simpler approach: after killing mitmproxy in `cleanup()`, copy
`_DEFAULT_EVIDENCE_PATH` to `self.artifacts_dir / "network_evidence.json"`.

### 4d. Add Phase 3 category mappings to l2_engine.py (~30m)

**Where:** Edit `L2/l2_engine.py`

**What:** Add to `_CAT_MAP`:
```python
"auth_fill":           Category.PHISHING_IMPERSONATION,  # credential injection
"auth_bypass":         Category.EVASION,                 # bypassing auth controls
"auth_state":          Category.EVASION,                 # forcing login state
"ssl_unpin":           Category.EVASION,                 # SSL pinning bypass
"accessibility_abuse": Category.ACCESSIBILITY_ABUSE,     # already an enum value
"bulk_exfil":          Category.DATA_EXFIL,              # large POST exfiltration
"biometric_prompt_bypass":     Category.EVASION,
"fingerprint_manager_bypass":  Category.EVASION,
"keyguard_spoof":              Category.EVASION,
"biometric_prompt_framework_bypass": Category.EVASION,
```

Also update `_parse_frida_hooks` to handle `type: "auth_state"` entries (Phase
3c sends these instead of `type: "finding"`). Add a check: if
`raw.get("type") == "auth_state"`, create a finding with
`category=Category.EVASION`, `severity=Severity.HIGH`.

### 4e. Detonation safety module (~1h)

**Where:** New file `L2/sandbox/safety.py`

**What:** Pre-detonation and post-detonation safety checks:

```python
@dataclass
class DetonationSafety:
    device_serial: str | None = None

    def pre_check(self) -> list[str]:
        """Return list of blocking issues. Empty = safe to proceed."""
        issues = []
        # 1. Verify emulator is running (not a physical device)
        # Check for 'emulator-' prefix in device serial
        if self.device_serial and not self.device_serial.startswith("emulator-"):
            issues.append("Device does not appear to be an emulator")
        # 2. Verify network isolation (no external connectivity)
        # adb shell ping -c 1 -W 2 8.8.8.8 should FAIL
        # If it succeeds, the emulator has real internet access
        # 3. Check disk space on host
        return issues

    def post_restore(self) -> None:
        """Restore emulator to clean state after detonation."""
        # Uninstall the APK (already done in orchestrator.cleanup)
        # Clear iptables rules
        # Remove proxy settings
        # Optionally: adb shell wipe data or restore snapshot
```

Wire into orchestrator: call `safety.pre_check()` at the start of `run()`,
before `start_network_interception()`. If any issues, raise
`DetonationSafetyError`. Call `safety.post_restore()` at the end of `cleanup()`.

**Important:** The pre-check verifies the emulator is isolated. The ping to
8.8.8.8 should fail (timeout) because the emulator should be on host-only
networking. If it succeeds, that means the malware could reach the internet,
which is a safety violation.

### 4f. End-to-end integration test (~30m)

**Where:** Edit or create test in `tests/`

**What:** A test that verifies the full L2 pipeline can process synthetic
sandbox artifacts:
1. Create a temp dir with fake `frida_hooks.jsonl` (JSON lines with Phase 1-3
   finding types), fake `network_evidence.json`, and a `dynamic.json`
2. Call `l2_engine.process(sha256, sandbox_dir=temp_dir)`
3. Assert: analysis.json is written, finding count > 0, categories include
   expected Phase 3 types, spine is updated with status != "not_attempted"

This tests that the full chain works without needing a live emulator.

---

## Files to modify

| File | Action |
|---|---|
| `L2/sandbox/orchestrator.py` | **Edit** — add sha256 param, dynamic.json generation, PCAP pull, network_evidence copy |
| `L2/l2_engine.py` | **Edit** — add Phase 3 category mappings, handle `auth_state` type |
| `L2/sandbox/safety.py` | **Create** — pre/post detonation safety checks |
| `tests/test_l2_engine_integration.py` | **Create** — synthetic artifact integration test |

**Do NOT modify:** `spine.py`, `L0/`, `L1/`, `L5/`, `promote.py` (already correct),
`signals.py`

---

## Verification

1. All existing tests pass: `pytest tests/test_l2_promote.py -q`
2. New integration test passes with synthetic artifacts
3. `l2_engine.process()` correctly parses Phase 3 finding types
4. `dynamic.json` schema matches what `_parse_dynamic_json` expects
5. Python imports clean: `from L2.sandbox.safety import DetonationSafety`
6. No files outside scope modified

---

## What this does NOT cover

- Live detonation test (user-approved, go/no-go checkpoint)
- L3/L5/L6 consumption of L2 findings (those layers already read from spine)
- PCAP deep analysis (future work — tshark/scapy parsing of capture.pcap)
