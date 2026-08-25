"""L3b's impersonation feature block and its non-evidence-layer treatment.

Mirrors ``tests/test_l3_features.py``'s style: the failure mode to design
against is silent zero-fill (a missing L0 block reading as "no bank
branding" instead of "we never checked"), so these tests exist to make that
loud, the way L3's own density check makes an empty vector loud.
"""

from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from L3b.features_ext import (  # noqa: E402
    FEATURE_NAMES, concatenate, extract_from_spine,
)


def _doc(l0_status="complete", **summary_over):
    summary = {
        "verdict": "unknown",
        "smoking_gun_inputs": {"brand_claim": False, "sms_trifecta": False},
        "cert_signal": {"cert_weight": 0.0},
        "cert_anomalies": [],
    }
    summary.update(summary_over)
    return {"layers": {"l0": {"status": l0_status, "summary": summary}}}


def test_missing_l0_layer_is_refused_not_zero_filled():
    result = extract_from_spine({"layers": {}})
    assert result.available is False
    assert result.reason == "l0_status_missing"


def test_incomplete_l0_layer_is_refused():
    result = extract_from_spine(_doc(l0_status="skipped"))
    assert result.available is False
    assert result.reason == "l0_status_skipped"


def test_a_clean_app_produces_an_all_zero_block():
    result = extract_from_spine(_doc())
    assert result.available is True
    assert result.vector.shape == (len(FEATURE_NAMES),)
    assert result.vector.sum() == 0


def test_brand_claim_sets_the_expected_dimension():
    result = extract_from_spine(_doc(
        smoking_gun_inputs={"brand_claim": True, "sms_trifecta": False}))
    idx = FEATURE_NAMES.index("brand_claim_present")
    assert result.vector[idx] == 1.0
    other_idx = [i for i in range(len(FEATURE_NAMES)) if i != idx]
    assert result.vector[other_idx].sum() == 0


def test_sms_trifecta_and_cert_anomaly_set_independent_dimensions():
    result = extract_from_spine(_doc(
        smoking_gun_inputs={"brand_claim": False, "sms_trifecta": True},
        cert_anomalies=["debug_keystore"],
        cert_signal={"cert_weight": -0.9}))
    assert result.vector[FEATURE_NAMES.index("sms_trifecta")] == 1.0
    assert result.vector[FEATURE_NAMES.index("cert_signer_anomaly")] == 1.0
    assert result.vector[FEATURE_NAMES.index("cert_weight_negative")] == 1.0
    assert result.vector[FEATURE_NAMES.index("brand_claim_present")] == 0.0


@pytest.mark.parametrize("verdict,dim", [
    ("impersonation_likely", "verdict_impersonation_likely"),
    ("impersonation_suspected", "verdict_impersonation_suspected"),
])
def test_verdict_sets_its_matching_dimension_only(verdict, dim):
    result = extract_from_spine(_doc(verdict=verdict))
    idx = FEATURE_NAMES.index(dim)
    other = "verdict_impersonation_suspected" if dim == "verdict_impersonation_likely" \
        else "verdict_impersonation_likely"
    assert result.vector[idx] == 1.0
    assert result.vector[FEATURE_NAMES.index(other)] == 0.0


def test_concatenate_appends_after_the_lamda_vector_in_fixed_order():
    lamda_vec = np.array([1, 0, 1], dtype=np.int8)
    impersonation_vec = np.array([1, 0, 0, 0, 0, 0], dtype=np.float32)
    out = concatenate(lamda_vec, impersonation_vec)
    assert out.shape == (9,)
    assert list(out[:3]) == [1, 0, 1]
    assert list(out[3:]) == list(impersonation_vec)


def test_l3b_is_not_an_evidence_layer():
    import spine
    assert "l3b" not in spine.EVIDENCE_LAYERS


def test_l3b_is_a_known_spine_layer():
    """It must be writable via spine.update_layer, or L3b/predict.py's
    write_layer raises ValueError the first time anyone runs it."""
    import spine
    assert "l3b" in spine.LAYERS


def test_writing_l3b_never_touches_l3s_block(tmp_path, monkeypatch):
    import spine

    sha = "c" * 64
    spine.update_layer(sha, "l3", status=spine.LayerStatus.COMPLETE,
                       findings=[], summary={"prob_malicious": 0.9},
                       coverage={}, gaps=None, root=tmp_path)
    before = spine.load_spine(sha, root=tmp_path)["layers"]["l3"]

    spine.update_layer(sha, "l3b", status=spine.LayerStatus.COMPLETE,
                       findings=[], summary={"prob_banking_malicious": 0.1},
                       coverage={}, gaps=None, root=tmp_path)
    after = spine.load_spine(sha, root=tmp_path)["layers"]["l3"]
    assert after == before


def test_promote_never_emits_a_verdict_or_a_finding():
    from L3b.predict import promote
    summary = promote({"status": "complete", "prob_banking_malicious": 0.9},
                      {"family_disjoint_status": "verified",
                       "malware_sources": ["banking_cicmaldroid"]})
    assert summary["is_verdict"] is False
    assert summary["bounded_points"] == 10
    assert summary["family_disjoint_status"] == "verified"


def test_skipped_prediction_records_why():
    from L3b.predict import promote
    summary = promote({"status": "skipped", "reason": "l0_status_missing"}, {})
    assert summary["skipped_reason"] == "l0_status_missing"
    assert summary["prob_banking_malicious"] is None
