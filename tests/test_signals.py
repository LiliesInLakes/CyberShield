"""The signal namespace is a contract, so it is pinned rather than described.

A weights file produced by A4 is keyed by these strings and outlives the code
that produced it. If a key changes shape, every stored weight silently attaches
to nothing — which no test of A4 or L5 alone would catch, because each would
still be internally consistent. These tests fail instead.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import signals  # noqa: E402


def make_spine(**over):
    doc = {
        "schema_version": "apk-sentinel-0.2",
        "sha256": "a" * 64,
        "layers": {
            "l0": {
                "status": "complete",
                "summary": {
                    "verdict": "impersonation_likely",
                    "smoking_gun_inputs": {
                        "brand_claim": True,
                        "claimed_entity": "State Bank of India",
                        "cert_anomalies": ["debug_keystore", "vendor_claiming_dn"],
                        "sms_trifecta": True,
                    },
                },
            },
            "l1": {"status": "complete"},
        },
        "findings": [
            {
                "id": "F001", "layer": "l0", "category": "phishing_impersonation",
                "detail": {"l0_finding_type": "brand_impersonation"},
            },
            {
                "id": "F002", "layer": "l0", "category": "certificate_anomaly",
                "detail": {"l0_finding_type": "cert_debug_keystore"},
            },
            {
                "id": "F003", "layer": "l1", "category": "sms_intercept",
                "detail": {"yara_rule": "Android_BFSI_SMS_Intercept_And_Forward",
                           "scopes": ["source"]},
            },
        ],
    }
    doc.update(over)
    return doc


def test_schema_version_is_pinned():
    # Bumping this is a deliberate act that invalidates stored weights.
    assert signals.SIGNAL_SCHEMA == "apk-sentinel-signals-1"


def test_key_shapes_are_exact():
    keys = signals.signal_keys(make_spine())
    assert keys == {
        "l0:brand_claim",
        "l0:sms_trifecta",
        "l0:cert_anomaly:debug_keystore",
        "l0:cert_anomaly:vendor_claiming_dn",
        "l0:verdict:impersonation_likely",
        "yara:Android_BFSI_SMS_Intercept_And_Forward",
    }


def test_self_signed_is_never_a_signal():
    """T6: every Android APK is self-signed, so it discriminates nothing.

    L0 strips it before promotion. If it ever leaks through, it would earn a
    near-zero weight and pad the report with a row that means nothing.
    """
    doc = make_spine()
    anomalies = doc["layers"]["l0"]["summary"]["smoking_gun_inputs"]["cert_anomalies"]
    anomalies.append("self_signed")

    keys = signals.signal_keys(doc)
    assert "l0:cert_anomaly:self_signed" not in keys
    # The discriminating anomalies on the same sample must survive the filter.
    assert "l0:cert_anomaly:debug_keystore" in keys
    assert "l0:cert_anomaly:vendor_claiming_dn" in keys


def test_signals_carry_the_evidence_ids_that_produced_them():
    """An L5 contribution must be able to name its evidence, not assert a number."""
    by_key = {s.key: s for s in signals.signals(make_spine())}
    assert by_key["l0:brand_claim"].evidence_ids == ("F001",)
    assert by_key["l0:cert_anomaly:debug_keystore"].evidence_ids == ("F002",)
    assert by_key["yara:Android_BFSI_SMS_Intercept_And_Forward"].evidence_ids == ("F003",)


def test_one_signal_per_rule_even_across_scopes():
    """A2's contract is one finding per (rule, sample); keep it true regardless."""
    doc = make_spine()
    doc["findings"].append({
        "id": "F004", "layer": "l1", "category": "sms_intercept",
        "detail": {"yara_rule": "Android_BFSI_SMS_Intercept_And_Forward",
                   "scopes": ["dex_class"]},
    })
    yara = [s for s in signals.signals(doc) if s.namespace == "yara"]
    assert len(yara) == 1
    assert yara[0].evidence_ids == ("F003", "F004")
    assert yara[0].scopes == ("dex_class", "source")


def test_absent_l0_inputs_produce_no_signals():
    doc = make_spine()
    doc["layers"]["l0"]["summary"]["smoking_gun_inputs"] = {
        "brand_claim": False, "sms_trifecta": False, "cert_anomalies": [],
    }
    keys = signals.signal_keys(doc)
    assert "l0:brand_claim" not in keys
    assert "l0:sms_trifecta" not in keys
    assert not any(k.startswith(signals.CERT_ANOMALY_PREFIX) for k in keys)


def test_empty_spine_does_not_raise():
    """A2/B26: samples die at L0. A missing layer must yield no signals, not a crash."""
    assert signals.signals({}) == []
    assert signals.signals({"layers": {}, "findings": []}) == []


def test_ordering_is_deterministic():
    """A4 output must be diffable across runs."""
    doc = make_spine()
    assert [s.key for s in signals.signals(doc)] == [s.key for s in signals.signals(doc)]


def test_vocabulary_counts_documents_not_occurrences():
    doc = make_spine()
    counts = signals.vocabulary([doc, doc, doc])
    assert counts["l0:brand_claim"] == 3
    assert counts["yara:Android_BFSI_SMS_Intercept_And_Forward"] == 3


@pytest.mark.parametrize("key,ns", [
    ("yara:Foo", "yara"), ("l0:brand_claim", "l0"), ("l0:cert_anomaly:x", "l0"),
])
def test_namespace_property(key, ns):
    assert signals.Signal(key=key).namespace == ns
