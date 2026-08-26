"""Spine contract tests.

Each test here corresponds to a property the plan committed to, and several of
them exist because the property was violated somewhere else in this codebase
first (a destructively-rewritten evidence file, a `pending` status that could
not distinguish "never ran" from "running").

Run:  ./env/bin/python -m pytest tests/test_spine.py -q
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "L0"))

import spine  # noqa: E402
import promote  # noqa: E402

SHA = "a" * 64


def _yara_finding(rule: str, severity: str = "high", category: str = "sms_intercept"):
    return {
        "engine": "yara",
        "category": category,
        "severity": severity,
        "evidence": f"[{rule}] test rule",
        "location": "com/x/Y.java",
        "mitre_techniques": ["T1636.004"],
        "observation": "inferred",
        "detail": {"yara_rule": rule},
    }


# ---------------------------------------------------------------------------
# Location and status
# ---------------------------------------------------------------------------

def test_spine_is_not_under_a_layer_directory():
    """T10: L0 rewrites its own evidence.json wholesale, so the spine cannot live there."""
    assert spine.SPINE_ROOT == REPO_ROOT / "artifacts"
    assert "L0" not in spine.SPINE_ROOT.parts
    assert "L1" not in spine.SPINE_ROOT.parts


def test_pending_is_not_a_status(tmp_path):
    """`pending` conflated 'never ran' with 'running'; both now have their own name."""
    assert "pending" not in {s.value for s in spine.LayerStatus}
    with pytest.raises(ValueError):
        spine.update_layer(SHA, "l0", status="pending", root=tmp_path)


def test_unattempted_layers_start_not_attempted(tmp_path):
    spine.update_layer(SHA, "l0", status=spine.LayerStatus.COMPLETE, root=tmp_path)
    doc = spine.load_spine(SHA, tmp_path)
    assert doc["layers"]["l3"]["status"] == "not_attempted"
    assert "pending" not in json.dumps(doc)


def test_unknown_layer_rejected(tmp_path):
    with pytest.raises(ValueError):
        spine.update_layer(SHA, "l9", status=spine.LayerStatus.COMPLETE, root=tmp_path)


# ---------------------------------------------------------------------------
# Merge semantics — the reason there is a single writer
# ---------------------------------------------------------------------------

def test_l1_update_preserves_l0_findings(tmp_path):
    spine.update_layer(SHA, "l0", status=spine.LayerStatus.COMPLETE,
                       findings=[_yara_finding("R_l0", category="phishing_impersonation")],
                       root=tmp_path)
    spine.update_layer(SHA, "l1", status=spine.LayerStatus.COMPLETE,
                       findings=[_yara_finding("R_l1")], root=tmp_path)
    doc = spine.load_spine(SHA, tmp_path)
    layers = {f["layer"] for f in doc["findings"]}
    assert layers == {"l0", "l1"}
    assert doc["counts"]["findings"] == 2


def test_rerunning_a_layer_replaces_only_its_own_findings(tmp_path):
    spine.update_layer(SHA, "l0", status=spine.LayerStatus.COMPLETE,
                       findings=[_yara_finding("R_l0")], root=tmp_path)
    spine.update_layer(SHA, "l1", status=spine.LayerStatus.COMPLETE,
                       findings=[_yara_finding("R_a"), _yara_finding("R_b")], root=tmp_path)
    spine.update_layer(SHA, "l1", status=spine.LayerStatus.COMPLETE,
                       findings=[_yara_finding("R_c")], root=tmp_path)
    doc = spine.load_spine(SHA, tmp_path)
    rules = {f["detail"]["yara_rule"] for f in doc["findings"]}
    assert rules == {"R_l0", "R_c"}


# ---------------------------------------------------------------------------
# Identity: ordinals and fingerprints
# ---------------------------------------------------------------------------

def test_ids_are_stable_across_identical_runs(tmp_path):
    findings = [_yara_finding("R_b"), _yara_finding("R_a"), _yara_finding("R_c")]
    spine.update_layer(SHA, "l1", status=spine.LayerStatus.COMPLETE,
                       findings=findings, root=tmp_path)
    first = {f["id"]: f["fingerprint"] for f in spine.load_spine(SHA, tmp_path)["findings"]}
    spine.update_layer(SHA, "l1", status=spine.LayerStatus.COMPLETE,
                       findings=list(reversed(findings)), root=tmp_path)
    second = {f["id"]: f["fingerprint"] for f in spine.load_spine(SHA, tmp_path)["findings"]}
    assert first == second, "ordinals must not depend on the order findings arrive in"


def test_fingerprints_survive_insertion_while_ordinals_shift(tmp_path):
    """The precise reason both identities exist."""
    spine.update_layer(SHA, "l1", status=spine.LayerStatus.COMPLETE,
                       findings=[_yara_finding("R_a"), _yara_finding("R_z")], root=tmp_path)
    before = {f["detail"]["yara_rule"]: (f["id"], f["fingerprint"])
              for f in spine.load_spine(SHA, tmp_path)["findings"]}

    spine.update_layer(SHA, "l1", status=spine.LayerStatus.COMPLETE,
                       findings=[_yara_finding("R_a"), _yara_finding("R_m"),
                                 _yara_finding("R_z")], root=tmp_path)
    after = {f["detail"]["yara_rule"]: (f["id"], f["fingerprint"])
             for f in spine.load_spine(SHA, tmp_path)["findings"]}

    assert before["R_z"][0] != after["R_z"][0], "an inserted finding must renumber later ordinals"
    assert before["R_z"][1] == after["R_z"][1], "fingerprints must be insertion-stable"
    assert before["R_a"] == after["R_a"]


def test_severity_orders_ordinals_within_a_layer(tmp_path):
    spine.update_layer(
        SHA, "l1", status=spine.LayerStatus.COMPLETE,
        findings=[_yara_finding("R_low", severity="low"),
                  _yara_finding("R_crit", severity="critical")],
        root=tmp_path)
    findings = spine.load_spine(SHA, tmp_path)["findings"]
    assert findings[0]["severity"] == "critical"
    assert findings[0]["id"] == "F001"


def test_l0_findings_precede_l1_findings(tmp_path):
    spine.update_layer(SHA, "l1", status=spine.LayerStatus.COMPLETE,
                       findings=[_yara_finding("R_crit", severity="critical")], root=tmp_path)
    spine.update_layer(SHA, "l0", status=spine.LayerStatus.COMPLETE,
                       findings=[_yara_finding("R_low", severity="low")], root=tmp_path)
    findings = spine.load_spine(SHA, tmp_path)["findings"]
    assert findings[0]["layer"] == "l0", "layer outranks severity in the ordinal sort"


def test_rule_rename_changes_fingerprint_but_retuning_strings_does_not(tmp_path):
    """Identity is the detector, not the matched text."""
    base = _yara_finding("R_a")
    retuned = _yara_finding("R_a")
    retuned["evidence"] = "[R_a] test rule -> a different matched string"
    assert spine.fingerprint(base | {"layer": "l1"}) == spine.fingerprint(retuned | {"layer": "l1"})
    renamed = _yara_finding("R_a_v2")
    assert spine.fingerprint(base | {"layer": "l1"}) != spine.fingerprint(renamed | {"layer": "l1"})


# ---------------------------------------------------------------------------
# Idempotency and atomicity
# ---------------------------------------------------------------------------

def test_identical_rerun_does_not_touch_the_file(tmp_path):
    path = spine.update_layer(SHA, "l1", status=spine.LayerStatus.COMPLETE,
                              findings=[_yara_finding("R_a")], root=tmp_path)
    before_bytes = path.read_bytes()
    before_mtime = path.stat().st_mtime_ns
    spine.update_layer(SHA, "l1", status=spine.LayerStatus.COMPLETE,
                       findings=[_yara_finding("R_a")], root=tmp_path)
    assert path.read_bytes() == before_bytes
    assert path.stat().st_mtime_ns == before_mtime


def test_real_change_updates_the_timestamp(tmp_path):
    path = spine.update_layer(SHA, "l1", status=spine.LayerStatus.COMPLETE,
                              findings=[_yara_finding("R_a")], root=tmp_path)
    first = json.loads(path.read_text())["updated_at"]
    spine.update_layer(SHA, "l1", status=spine.LayerStatus.COMPLETE,
                       findings=[_yara_finding("R_a"), _yara_finding("R_b")], root=tmp_path)
    assert json.loads(path.read_text())["updated_at"] != first


def test_created_at_survives_updates(tmp_path):
    path = spine.update_layer(SHA, "l0", status=spine.LayerStatus.COMPLETE,
                              findings=[_yara_finding("R_a")], root=tmp_path)
    created = json.loads(path.read_text())["created_at"]
    spine.update_layer(SHA, "l1", status=spine.LayerStatus.COMPLETE,
                       findings=[_yara_finding("R_b")], root=tmp_path)
    assert json.loads(path.read_text())["created_at"] == created


def test_kill_during_write_leaves_the_previous_spine_intact(tmp_path):
    """SIGKILL mid-write must never produce a truncated spine."""
    path = spine.update_layer(SHA, "l1", status=spine.LayerStatus.COMPLETE,
                              findings=[_yara_finding("R_a")], root=tmp_path)
    good = path.read_bytes()

    script = f"""
import json, os, signal, sys
sys.path.insert(0, {str(REPO_ROOT)!r})
import spine
real_dump = json.dump
def dump(obj, fh, **kw):
    # Write a prefix of the document, then die exactly like a SIGKILL would.
    fh.write(json.dumps(obj, indent=2)[:80])
    fh.flush()
    os.kill(os.getpid(), signal.SIGKILL)
json.dump = dump
spine.update_layer({SHA!r}, "l1", status=spine.LayerStatus.COMPLETE,
                   findings=[{{"engine": "yara", "category": "other", "severity": "low",
                              "evidence": "x", "detail": {{"yara_rule": "R_new"}}}}],
                   root={str(tmp_path)!r})
"""
    result = subprocess.run([sys.executable, "-c", script], capture_output=True)
    assert result.returncode < 0, "the child was expected to die mid-write"
    assert path.read_bytes() == good, "the spine must still be the last complete version"
    assert json.loads(path.read_text())
    leftovers = list(path.parent.glob(".evidence-*.tmp"))
    assert len(leftovers) <= 1, "at most the one temp file the killed process abandoned"


def test_corrupt_spine_is_preserved_not_silently_replaced(tmp_path):
    path = spine.spine_path(SHA, tmp_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{ this is not json")
    spine.update_layer(SHA, "l1", status=spine.LayerStatus.COMPLETE,
                       findings=[_yara_finding("R_a")], root=tmp_path)
    assert path.with_suffix(".json.corrupt").exists()
    assert json.loads(path.read_text())["counts"]["findings"] == 1


# ---------------------------------------------------------------------------
# Coverage and gaps — the confidence axis's input
# ---------------------------------------------------------------------------

def test_unrun_dynamic_layer_is_reported_as_a_gap(tmp_path):
    spine.update_layer(SHA, "l0", status=spine.LayerStatus.COMPLETE, root=tmp_path)
    spine.update_layer(SHA, "l1", status=spine.LayerStatus.COMPLETE, root=tmp_path)
    doc = spine.load_spine(SHA, tmp_path)
    assert "detonation_not_attempted" in doc["analysis_gaps"]


def test_consumer_layers_do_not_create_gaps(tmp_path):
    """L5 not having run is a pipeline state, not a hole in the evidence."""
    spine.update_layer(SHA, "l0", status=spine.LayerStatus.COMPLETE, root=tmp_path)
    doc = spine.load_spine(SHA, tmp_path)
    assert not any(g.startswith(("l3", "l4", "l5", "l6")) for g in doc["analysis_gaps"])


def test_layer_gaps_reach_the_top_level(tmp_path):
    spine.update_layer(SHA, "l1", status=spine.LayerStatus.PARTIAL,
                       gaps=["ghidra_unavailable"], root=tmp_path)
    assert "ghidra_unavailable" in spine.load_spine(SHA, tmp_path)["analysis_gaps"]


def test_failed_layer_is_recorded_with_its_error(tmp_path):
    spine.update_layer(SHA, "l1", status=spine.LayerStatus.FAILED,
                       error="RuntimeError: jadx produced no sources", root=tmp_path)
    doc = spine.load_spine(SHA, tmp_path)
    assert doc["layers"]["l1"]["status"] == "failed"
    assert "l1_failed" in doc["analysis_gaps"]
    assert "jadx" in doc["layers"]["l1"]["error"]


def test_counts_expose_the_benign_pass_criterion(tmp_path):
    spine.update_layer(
        SHA, "l1", status=spine.LayerStatus.COMPLETE,
        findings=[_yara_finding("R_sms", category="sms_intercept"),
                  _yara_finding("R_owasp", category="other")],
        root=tmp_path)
    counts = spine.load_spine(SHA, tmp_path)["counts"]
    assert counts["malware_category"] == 1
    assert counts["by_layer"] == {"l1": 2}


def test_frozen_pass_criterion_is_not_silently_widened():
    """The A2 before/after numbers are only comparable if this set is fixed."""
    assert spine.MALWARE_CATEGORIES == frozenset({
        "sms_intercept", "overlay_attack", "accessibility_abuse", "c2_communication",
        "data_exfiltration", "ransomware", "native_payload", "clipboard_hijack",
        "phishing_impersonation",
    })


def test_certificate_anomalies_are_counted_separately(tmp_path):
    """Debug-signed training apps are anomalous without being malicious."""
    spine.update_layer(
        SHA, "l0", status=spine.LayerStatus.COMPLETE,
        findings=[_yara_finding("cert", category="certificate_anomaly")],
        root=tmp_path)
    counts = spine.load_spine(SHA, tmp_path)["counts"]
    assert counts["certificate_anomaly"] == 1
    assert counts["malware_category"] == 0


# ---------------------------------------------------------------------------
# L0 promotion
# ---------------------------------------------------------------------------

_L0_FIXTURE = {
    "fingerprint": {"sha256": SHA, "md5": "b" * 32},
    "manifest": {"package_name": "com.sbi.complaintregister", "app_label": "SBI Quick Support",
                 "permission_count": 21},
    "icon": {"extraction_ok": True, "source": "res/drawable/ic_launcher.png"},
    "certificate": {"present": True, "anomalies": ["self_signed", "debug_keystore"]},
    "routing": {"track": "track1_jadx"},
    "reputation": {"local_cache_hit": False},
    "impersonation": {
        "verdict": "impersonation_likely",
        "claimed_entity": "State Bank of India",
        "matched_bank": None,
        "smoking_gun_inputs": {"brand_claim": True, "sms_trifecta": True},
        "cert_signal": {"cert_weight": -0.9},
        "findings": [
            {"type": "cert_debug_keystore", "severity": "high",
             "anomalies": ["debug_keystore"], "detail": "Signed with the Android debug keystore."},
            {"type": "brand_impersonation", "severity": "critical",
             "entity": "State Bank of India", "detail": "App presents itself as SBI."},
        ],
    },
}


def test_l0_findings_reach_the_spine_with_evidence_ids(tmp_path):
    """Without this the India differentiator has nothing for L5 to cite."""
    spine.update_layer(SHA, "l0", status=spine.LayerStatus.COMPLETE,
                       findings=promote.impersonation_findings(_L0_FIXTURE),
                       summary=promote.l0_summary(_L0_FIXTURE),
                       identity=promote.identity(_L0_FIXTURE, "sample.apk"),
                       root=tmp_path)
    doc = spine.load_spine(SHA, tmp_path)
    by_category = {f["category"]: f for f in doc["findings"]}
    assert set(by_category) == {"phishing_impersonation", "certificate_anomaly"}
    assert by_category["phishing_impersonation"]["id"] == "F001"  # critical sorts first
    assert by_category["phishing_impersonation"]["detail"]["entity"] == "State Bank of India"
    assert doc["identity"]["impersonates"] == "State Bank of India"
    assert doc["layers"]["l0"]["summary"]["smoking_gun_inputs"]["sms_trifecta"] is True


def test_promotion_is_lossless():
    for finding in promote.impersonation_findings(_L0_FIXTURE):
        assert finding["detail"]["l0_finding"] in _L0_FIXTURE["impersonation"]["findings"]


def test_cert_findings_are_not_dumped_into_other():
    findings = promote.impersonation_findings(_L0_FIXTURE)
    cert = [f for f in findings if f["detail"]["l0_finding_type"].startswith("cert_")]
    assert cert and all(f["category"] == "certificate_anomaly" for f in cert)
    assert all(f["mitre_techniques"] == [] for f in cert), "no unverified ATT&CK IDs"


def test_entity_is_part_of_finding_identity():
    a = {"type": "brand_impersonation", "severity": "critical", "entity": "SBI", "detail": ""}
    b = {"type": "brand_impersonation", "severity": "critical", "entity": "HDFC", "detail": ""}
    fa = promote.impersonation_findings({"impersonation": {"findings": [a]}})[0] | {"layer": "l0"}
    fb = promote.impersonation_findings({"impersonation": {"findings": [b]}})[0] | {"layer": "l0"}
    assert spine.fingerprint(fa) != spine.fingerprint(fb)


def test_l0_gaps_report_what_was_not_examined():
    blind = {"icon": {"extraction_ok": False}, "certificate": {}, "manifest": {}}
    assert set(promote.l0_gaps(blind)) == {
        "icon_not_extracted", "certificate_not_parsed", "manifest_not_parsed"}
    assert promote.l0_gaps(_L0_FIXTURE) == []
