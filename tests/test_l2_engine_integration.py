"""End-to-end test: synthetic sandbox artifacts through l2_engine.process().

Verifies the full chain the sandbox orchestrator's raw output feeds into:
frida_hooks.jsonl + dynamic.json + network_evidence.json -> L1Findings ->
analysis.json -> spine. Covers Phase 1-3 finding types (auth_fill,
auth_bypass, auth_state, accessibility_abuse, ssl_unpin, sms_exfiltration)
so a regression in the category map or the auth_state parser shows up here
rather than only at live-detonation time.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import spine  # noqa: E402
from L2 import l2_engine  # noqa: E402

SHA = "a" * 64

FRIDA_LINES = [
    {"type": "finding", "category": "auth_fill", "field": "mobile",
     "value": "9876543210", "evidence": "Auto-filled auth field"},
    {"type": "finding", "category": "auth_bypass", "action": "biometric_prompt_bypass",
     "evidence": "Fabricated biometric auth"},
    {"type": "auth_state", "key": "is_logged_in", "original": False,
     "forced": True, "method": "putBoolean"},
    {"type": "finding", "category": "accessibility_abuse", "severity": "critical",
     "target_package": "com.sbi.upi", "evidence": "Accessibility read from banking app"},
    {"type": "finding", "category": "ssl_unpin", "action": "SSLContext.init",
     "evidence": "SSL pinning bypassed"},
    {"type": "finding", "category": "sms_exfiltration", "evidence": "SMS sent to premium number"},
]

NETWORK_EVIDENCE = [
    {"alert": "CREDENTIAL_EXFILTRATION", "host": "evil.example",
     "url": "https://evil.example/collect", "method": "POST"},
    {"hijacked": "fcm_response", "url": "https://fcm.example/gate"},
    {"host": "benign.example", "url": "https://benign.example/", "method": "GET"},
]


def _dynamic_json(package: str) -> dict:
    return {
        "package": package,
        "sha256": SHA,
        "sandbox": {
            "type": "droidbot+frida",
            "detonation_duration_s": 62.4,
            "evasion_checks_bypassed": 2,
            "android_version": "11",
            "api_level": 30,
        },
        "runtime_behaviors": {
            "sms_intercepted": False,
            "overlay_displayed": False,
            "clipboard_hijacked": False,
            "files_dropped": 0,
        },
        "network": {
            "total_requests": 3,
            "c2_endpoints": [],
            "exfiltration_detected": False,
            "data_exfiltrated": [],
        },
        "findings": [],
        "confidence": {"confidence_level": "high"},
    }


def _write_artifacts(tmp_path: Path) -> Path:
    sandbox_dir = tmp_path / "sandbox_out"
    sandbox_dir.mkdir()

    frida_path = sandbox_dir / "frida_hooks.jsonl"
    frida_path.write_text("\n".join(json.dumps(line) for line in FRIDA_LINES) + "\n")

    (sandbox_dir / "dynamic.json").write_text(json.dumps(_dynamic_json("com.fake.bank")))
    (sandbox_dir / "network_evidence.json").write_text(json.dumps(NETWORK_EVIDENCE))

    return sandbox_dir


def test_l2_engine_processes_synthetic_sandbox_run(tmp_path, monkeypatch):
    sandbox_dir = _write_artifacts(tmp_path)
    out_root = tmp_path / "l2_out"
    spine_root = tmp_path / "spine"
    monkeypatch.setattr(spine, "SPINE_ROOT", spine_root)

    report = l2_engine.process(SHA, sandbox_dir=sandbox_dir, out_root=out_root)

    analysis_path = out_root / SHA / "analysis.json"
    assert analysis_path.exists()

    assert report.summary["finding_count"] > 0

    categories = {f.category.value for f in report.findings}
    assert "phishing_impersonation" in categories   # auth_fill
    assert "evasion" in categories                  # auth_bypass / auth_state / ssl_unpin
    assert "accessibility_abuse" in categories
    assert "sms_intercept" in categories             # sms_exfiltration
    assert "data_exfiltration" in categories         # network CREDENTIAL_EXFILTRATION
    assert "c2_communication" in categories          # network hijacked entry

    auth_state_findings = [
        f for f in report.findings
        if f.detail.get("key") == "is_logged_in" and f.detail.get("method") == "putBoolean"
    ]
    assert len(auth_state_findings) == 1
    assert auth_state_findings[0].severity.value == "high"

    doc = spine.load_spine(SHA, root=spine_root)
    assert doc["layers"]["l2"]["status"] != "not_attempted"
    assert any(f["layer"] == "l2" for f in doc["findings"])


def test_l2_engine_handles_frida_cli_send_wrapper(tmp_path, monkeypatch):
    """Frida CLI (`frida -l`) wraps send() payloads as {"type":"send","payload":{...}}."""
    sandbox_dir = tmp_path / "sandbox_out"
    sandbox_dir.mkdir()

    wrapped_lines = [
        {"type": "send", "payload": {"type": "finding", "category": "ssl_unpin",
                                      "evidence": "SSL pinning bypassed"}},
        {"type": "send", "payload": {"type": "auth_state", "key": "session_token",
                                      "original": None, "forced": "abc123",
                                      "method": "putString"}},
        "console.log line that is not JSON at all",
    ]
    lines_out = []
    for line in wrapped_lines:
        lines_out.append(line if isinstance(line, str) else json.dumps(line))
    (sandbox_dir / "frida_hooks.jsonl").write_text("\n".join(lines_out) + "\n")
    (sandbox_dir / "dynamic.json").write_text(json.dumps(_dynamic_json("com.fake.bank2")))

    out_root = tmp_path / "l2_out"
    spine_root = tmp_path / "spine"
    monkeypatch.setattr(spine, "SPINE_ROOT", spine_root)

    sha = "b" * 64
    report = l2_engine.process(sha, sandbox_dir=sandbox_dir, out_root=out_root)

    categories = {f.category.value for f in report.findings}
    assert "evasion" in categories
    assert len(report.findings) == 2
