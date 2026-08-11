"""L3 feature bridge.

The whole layer rests on our token spellings matching LAMDA's vocabulary. If
they do not, every feature is zero and a gradient-boosted tree returns a
confident constant that looks exactly like a prediction. These tests exist to
make that failure loud.
"""

from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from L3.features import (  # noqa: E402
    LAMDA_REFERENCE_DENSITY, MIN_PLAUSIBLE_DENSITY, Extraction, Vocabulary,
    _class_forms, _permission_forms, check_density, vectorise,
)


@pytest.fixture
def vocab() -> Vocabulary:
    return Vocabulary(
        index={
            "RequestedPermissionList_android.permission.SEND_SMS": 0,
            "RequestedPermissionList_SEND_SMS": 1,
            "ActivityList_.MainActivity": 2,
            "ActivityList_com.evil.app.MainActivity": 3,
            "URLDomainList_evil.ru": 4,
            "SuspiciousApiList_Landroid/app/Activity.getSystemService": 5,
            "RestrictedApiList_android.app.Activity.getSystemService": 6,
        },
        names=["RequestedPermissionList_android.permission.SEND_SMS",
               "RequestedPermissionList_SEND_SMS",
               "ActivityList_.MainActivity",
               "ActivityList_com.evil.app.MainActivity",
               "URLDomainList_evil.ru",
               "SuspiciousApiList_Landroid/app/Activity.getSystemService",
               "RestrictedApiList_android.app.Activity.getSystemService"],
    )


# --------------------------------------------------------------------------
# Candidate spellings
# --------------------------------------------------------------------------

def test_permissions_emit_both_spellings_the_vocabulary_uses():
    """The vocabulary is inconsistent: bare BIND_GET_INSTALL_REFERRER_SERVICE
    sits beside fully-qualified com.huawei.permission.X. Guessing one loses
    half the family."""
    forms = _permission_forms("android.permission.SEND_SMS")
    assert "android.permission.SEND_SMS" in forms
    assert "SEND_SMS" in forms


def test_vendor_permissions_are_not_truncated():
    forms = _permission_forms("com.huawei.permission.external_app_settings.USE_COMPONENT")
    assert forms == ("com.huawei.permission.external_app_settings.USE_COMPONENT",)


def test_component_names_emit_relative_and_qualified_forms():
    """Manifests use both '.About' and the fully-qualified name."""
    assert set(_class_forms(".MainActivity", "com.evil.app")) == {
        ".MainActivity", "com.evil.app.MainActivity"}
    assert set(_class_forms("com.evil.app.MainActivity", "com.evil.app")) == {
        "com.evil.app.MainActivity", ".MainActivity"}


def test_unrelated_qualified_name_is_left_alone():
    assert _class_forms("com.other.lib.Service", "com.evil.app") == (
        "com.other.lib.Service",)


# --------------------------------------------------------------------------
# Vectorisation
# --------------------------------------------------------------------------

def test_only_tokens_in_the_vocabulary_become_features(vocab):
    ex = Extraction()
    ex.add("RequestedPermissionList", "android.permission.SEND_SMS", "SEND_SMS")
    ex.add("URLDomainList", "evil.ru")
    ex.add("URLDomainList", "never-seen-in-lamda.example")
    vec, diag = vectorise(ex, vocab)
    assert vec.dtype == np.int8
    assert vec.sum() == 3
    assert diag["hits_by_family"] == {"RequestedPermissionList": 2, "URLDomainList": 1}


def test_vector_is_binary_not_counts(vocab):
    ex = Extraction()
    for _ in range(5):
        ex.add("URLDomainList", "evil.ru")
    vec, _ = vectorise(ex, vocab)
    assert set(np.unique(vec)) <= {0, 1}


def test_an_empty_extraction_is_flagged_implausible(vocab):
    """The silent-zero failure: a model would still return a probability."""
    vec, diag = vectorise(Extraction(), vocab)
    assert vec.sum() == 0
    assert diag["plausible"] is False
    assert "IMPLAUSIBLE" in check_density(diag)


def test_tokens_that_all_miss_the_vocabulary_are_implausible(vocab):
    ex = Extraction()
    for i in range(500):
        ex.add("ActivityList", f"com.nowhere.Activity{i}")
    _vec, diag = vectorise(ex, vocab)
    assert diag["tokens_extracted"] == 500
    assert diag["nonzero"] == 0
    assert diag["plausible"] is False


def test_a_realistic_hit_rate_is_plausible(vocab):
    ex = Extraction()
    ex.add("RequestedPermissionList", "android.permission.SEND_SMS")
    ex.add("ActivityList", ".MainActivity")
    _vec, diag = vectorise(ex, vocab)
    assert diag["plausible"] is True
    assert "ok:" in check_density(diag)


def test_density_thresholds_are_ordered_sensibly():
    assert 0 < MIN_PLAUSIBLE_DENSITY < LAMDA_REFERENCE_DENSITY


def test_check_density_reports_the_ratio_against_lamda(vocab):
    ex = Extraction()
    ex.add("URLDomainList", "evil.ru")
    _vec, diag = vectorise(ex, vocab)
    assert "LAMDA's mean" in check_density(diag)


# --------------------------------------------------------------------------
# Bound and scope
# --------------------------------------------------------------------------

def test_promote_never_emits_a_verdict_or_a_finding():
    """L3 is a consumer layer; a finding would enter counts.* and let a generic
    model inflate the frozen malware-category headline."""
    from L3.predict import promote
    summary = promote({"status": "complete", "prob_malicious": 0.99},
                      {"train_years": [2013, 2014]})
    assert summary["is_verdict"] is False
    assert summary["bounded_points"] == 10
    assert "non-banking" in summary["caveat"]


def test_skipped_prediction_records_why():
    from L3.predict import promote
    summary = promote({"status": "skipped", "reason": "feature_extraction_implausible"},
                      {})
    assert summary["skipped_reason"] == "feature_extraction_implausible"
    assert summary["prob_malicious"] is None


def test_l3_is_not_an_evidence_layer():
    import spine
    assert "l3" not in spine.EVIDENCE_LAYERS


# --------------------------------------------------------------------------
# Trainer contracts
# --------------------------------------------------------------------------

def test_year_matrices_are_float32_because_lightgbm_rejects_ints():
    """Regression: load_year() built int8 sparse matrices and every test passed,
    because they only checked shape and density. LightGBM's CSR path raises
    'Expected np.float32 or np.float64, met type(int8)' the moment you fit."""
    import os
    from pathlib import Path
    from L3.train import LAMDA_BASELINE, load_year

    if not LAMDA_BASELINE.is_dir():
        pytest.skip("LAMDA not fetched")
    years = sorted(int(p.name) for p in LAMDA_BASELINE.iterdir()
                   if p.is_dir() and p.name.isdigit())
    d = load_year(years[-1], "test")
    if d is None:
        pytest.skip("no test split for that year")
    assert d.X.dtype == np.float32


def test_a_tiny_fit_actually_runs():
    """The loader test above cannot catch a dtype LightGBM dislikes; only
    fitting can. Kept deliberately small so it costs a second."""
    lgb = pytest.importorskip("lightgbm")
    from scipy import sparse
    rng = np.random.default_rng(0)
    X = sparse.csr_matrix((rng.random((200, 30)) > 0.9).astype(np.int8),
                          dtype=np.float32)
    y = (X.toarray()[:, 0] > 0).astype(int)
    y[:5] = 1
    y[5:10] = 0
    lgb.LGBMClassifier(n_estimators=5, verbose=-1, n_jobs=1).fit(X, y)


def test_auroc_and_ece_agree_with_hand_values():
    from L3.train import auroc, expected_calibration_error
    assert auroc(np.array([0, 0, 1, 1]), np.array([.1, .4, .35, .8])) == pytest.approx(0.75)
    # Perfectly calibrated: predicted probability equals observed frequency.
    y = np.array([0, 1] * 50)
    p = np.full(100, 0.5)
    assert expected_calibration_error(y, p) == pytest.approx(0.0, abs=1e-9)
