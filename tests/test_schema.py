from __future__ import annotations

import json
import tempfile
from pathlib import Path

from L1.schema import (
    L1Finding, L1Report,
    Severity, Category, ObservationSource,
    CATEGORY_MITRE_MAP, load_l0_evidence,
)


def test_severity_values():
    assert Severity.INFO.value == "info"
    assert Severity.LOW.value == "low"
    assert Severity.MEDIUM.value == "medium"
    assert Severity.HIGH.value == "high"
    assert Severity.CRITICAL.value == "critical"


def test_category_values():
    assert Category.SMS_INTERCEPT.value == "sms_intercept"
    assert Category.OVERLAY.value == "overlay_attack"
    assert Category.C2_COMMS.value == "c2_communication"


def test_observation_values():
    assert ObservationSource.INFERRED.value == "inferred"
    assert ObservationSource.OBSERVED.value == "observed"
    assert ObservationSource.CONFIRMED.value == "confirmed"


def test_mitre_map_completeness():
    for cat in Category:
        assert cat in CATEGORY_MITRE_MAP, f"Missing MITRE mapping for {cat}"


def test_l1_finding_defaults():
    f = L1Finding(engine="test", category=Category.OTHER, severity=Severity.INFO, evidence="test")
    assert f.location == ""
    assert f.mitre_techniques == []
    assert f.observation == ObservationSource.INFERRED
    assert f.detail == {}


def test_l1_finding_to_dict():
    f = L1Finding(
        engine="jadx", category=Category.SMS_INTERCEPT, severity=Severity.HIGH,
        evidence="SMS permission requested", location="AndroidManifest.xml",
        mitre_techniques=["T1636.004"],
    )
    d = f.to_dict()
    assert d["engine"] == "jadx"
    assert d["category"] == "sms_intercept"
    assert d["severity"] == "high"
    assert d["observation"] == "inferred"
    assert d["mitre_techniques"] == ["T1636.004"]


def test_l1_report_to_dict():
    findings = [
        L1Finding(engine="jadx", category=Category.SMS_INTERCEPT, severity=Severity.HIGH,
                  evidence="test"),
    ]
    r = L1Report(
        sha256="abc123", source_apk="/tmp/test.apk", engine="jadx+yara",
        track="track1_jadx", generated_at="2025-01-01T00:00:00Z",
        findings=findings,
        artifacts={"decompiled_src": "/tmp/out"},
        summary={"finding_count": 1, "severity_counts": {"high": 1}, "categories": ["sms_intercept"]},
    )
    d = r.to_dict()
    assert d["sha256"] == "abc123"
    assert len(d["findings"]) == 1
    assert d["findings"][0]["engine"] == "jadx"


def test_l1_report_write():
    findings = [L1Finding(engine="test", category=Category.OTHER, severity=Severity.INFO, evidence="x")]
    r = L1Report(sha256="s1", source_apk="a.apk", engine="e", track="t", generated_at="now", findings=findings)
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
        out_path = Path(f.name)
    try:
        written = r.write(out_path)
        assert written == out_path
        loaded = json.loads(out_path.read_text())
        assert loaded["sha256"] == "s1"
        assert len(loaded["findings"]) == 1
    finally:
        out_path.unlink(missing_ok=True)


def test_load_l0_evidence_not_found(tmp_path):
    apk = tmp_path / "test_unknown.apk"
    apk.write_text("dummy content")
    result = load_l0_evidence(apk)
    assert result == {}


def test_load_l0_evidence_from_sibling(tmp_path):
    evidence = {"status": "complete", "fingerprint": {"sha256": "deadbeef"}}
    apk = tmp_path / "test.apk"
    apk.write_text("dummy")
    ev_file = tmp_path / "evidence.json"
    ev_file.write_text(json.dumps(evidence))
    result = load_l0_evidence(apk)
    assert result["fingerprint"]["sha256"] == "deadbeef"
