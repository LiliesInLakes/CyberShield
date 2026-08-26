"""L2's spine bridge.

L2 was the only evidence layer never wired to the spine: it has parsed
telemetry into OBSERVED findings since it was written, while all 1,248 spines
read `l2: {"status": "not_attempted"}`. These tests pin the bridge, and in
particular the distinction that makes dynamic analysis worth having — a
detonation that ran and saw nothing is not the same as one that never ran.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import spine  # noqa: E402
from L2 import promote  # noqa: E402


def report(**over):
    doc = {
        "sha256": "e" * 64,
        "engine": "l2_sandbox",
        "findings": [
            {"engine": "frida", "category": "sms_intercept", "severity": "critical",
             "evidence": "SmsManager.sendTextMessage called at runtime",
             "location": "runtime", "observation": "observed",
             "mitre_techniques": ["T1636.004"],
             "detail": {"hook": "android.telephony.SmsManager.sendTextMessage"}},
            {"engine": "mitmproxy", "category": "c2_communication", "severity": "high",
             "evidence": "POST to evil.ru/gate.php", "location": "network",
             "observation": "observed", "mitre_techniques": [],
             "detail": {"endpoint": "https://evil.ru/gate.php"}},
        ],
        "summary": {"finding_count": 2, "categories": ["c2_communication", "sms_intercept"],
                    "severity_counts": {"critical": 1, "high": 1},
                    "sandbox_type": "avd", "detonation_s": 120,
                    "evasion_bypassed": 3, "total_http_requests": 14,
                    "c2_count": 1, "confidence": "high"},
    }
    doc.update(over)
    return doc


# --------------------------------------------------------------------------
# The distinction that justifies the layer
# --------------------------------------------------------------------------

def test_findings_keep_observation_observed():
    """`inferred` means a static rule matched; `observed` means it happened.
    Flattening that discards the only thing detonation adds."""
    out = promote.l2_findings(report())
    assert all(f["observation"] == "observed" for f in out)


def test_a_detonation_that_saw_nothing_is_complete_not_skipped():
    doc = report(findings=[], summary={**report()["summary"], "finding_count": 0})
    assert promote.l2_status_for(doc) in ("complete", "partial")


def test_a_detonation_that_never_ran_is_skipped():
    """Collapsing this into 'complete, no findings' would let a failed sandbox
    read as a clean sample."""
    doc = report(findings=[], summary={"finding_count": 0, "detonation_s": 0})
    assert promote.l2_status_for(doc) == "skipped"


def test_partial_when_coverage_is_incomplete():
    doc = report(summary={**report()["summary"], "total_http_requests": 0})
    assert promote.l2_status_for(doc) == "partial"
    assert "network_not_captured" in promote.l2_gaps(doc)


# --------------------------------------------------------------------------
# Spine contract
# --------------------------------------------------------------------------

def test_every_finding_carries_a_spine_key():
    """Without it, finding_key falls back to the free-text evidence string and
    fingerprints churn on every wording change."""
    out = promote.l2_findings(report())
    assert all(f["detail"].get("spine_key") for f in out)
    keys = [f["detail"]["spine_key"] for f in out]
    assert len(set(keys)) == len(keys)


def test_spine_key_is_derived_from_what_was_seen_not_the_prose():
    a = promote.l2_findings(report())[0]["detail"]["spine_key"]
    reworded = report()
    reworded["findings"][0]["evidence"] = "completely different wording here"
    b = promote.l2_findings(reworded)[0]["detail"]["spine_key"]
    assert a == b


def test_an_unobservable_category_is_not_claimed():
    doc = report()
    doc["findings"][0]["category"] = "phishing_impersonation"   # an L0 judgement
    assert promote.l2_findings(doc)[0]["category"] == "other"


def test_l2_is_an_evidence_layer_and_may_contribute_gaps():
    """Unlike L3-L6, a detonation with no network capture genuinely leaves a
    hole in what can be claimed."""
    assert "l2" in spine.EVIDENCE_LAYERS
    assert promote.l2_gaps(report(summary={"finding_count": 0, "detonation_s": 0}))


def test_status_strings_are_valid_layer_statuses():
    for doc in (report(),
                report(findings=[], summary={"finding_count": 0, "detonation_s": 0}),
                report(summary={**report()["summary"], "confidence": "low"})):
        spine.LayerStatus(promote.l2_status_for(doc))     # raises if invalid


def test_summary_and_coverage_are_json_safe():
    import json
    json.dumps(promote.l2_summary(report()))
    json.dumps(promote.l2_coverage(report()))


# --------------------------------------------------------------------------
# End to end, against a real spine
# --------------------------------------------------------------------------

def test_l2_update_preserves_other_layers(tmp_path):
    sha = "f" * 64
    spine.update_layer(sha, "l0", status=spine.LayerStatus.COMPLETE,
                       findings=[{"engine": "l0_impersonation",
                                  "category": "phishing_impersonation",
                                  "severity": "critical", "evidence": "brand claim",
                                  "detail": {"spine_key": "brand:X"}}],
                       root=tmp_path)
    doc = report()
    spine.update_layer(sha, "l2",
                       status=spine.LayerStatus(promote.l2_status_for(doc)),
                       findings=promote.l2_findings(doc),
                       summary=promote.l2_summary(doc),
                       coverage=promote.l2_coverage(doc),
                       gaps=promote.l2_gaps(doc),
                       root=tmp_path)
    out = spine.load_spine(sha, root=tmp_path)
    by_layer = out["counts"]["by_layer"]
    assert by_layer["l0"] == 1 and by_layer["l2"] == 2
    assert "detonation_not_attempted" not in out["analysis_gaps"]
    assert out["layers"]["l2"]["status"] == "complete"
