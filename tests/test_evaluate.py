"""Evaluation harness.

The assertions here guard the denominator. A false-positive rate is a statement
about what you divided by, and this project's central claim is a false-positive
rate — so silently widening the negative class is the most damaging bug this
file could contain. It contained it once.
"""

from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools import corpus_labels  # noqa: E402
from tools.evaluate import (  # noqa: E402
    SCORED_CLASSES, auroc, bootstrap_auroc, operating_points,
)


def test_scored_classes_exclude_the_vulnerable_training_apps():
    """InsecureBankv2, PIVAA and UnCrackable are neither malicious nor
    benign-representative. Counting them as benign inflated the denominator
    from 4 to 8 and flattered every false-positive rate."""
    assert corpus_labels.CLASS_EXCLUDED not in SCORED_CLASSES
    assert corpus_labels.CLASS_CONFLICTED not in SCORED_CLASSES
    assert set(SCORED_CLASSES) == {corpus_labels.CLASS_MALWARE,
                                   corpus_labels.CLASS_BENIGN}


def test_auroc_matches_a_hand_computed_value():
    y = np.array([0, 0, 1, 1])
    s = np.array([0.1, 0.4, 0.35, 0.8])
    assert auroc(y, s) == pytest.approx(0.75)


def test_auroc_handles_ties_by_averaging_ranks():
    """A scoring system that emits integers 0-100 produces ties constantly."""
    y = np.array([0, 1])
    s = np.array([50.0, 50.0])
    assert auroc(y, s) == pytest.approx(0.5)


def test_auroc_is_nan_without_both_classes():
    assert np.isnan(auroc(np.array([1, 1]), np.array([1.0, 2.0])))


def test_operating_points_report_an_interval_not_just_a_rate():
    """'0 false positives' is meaningless without the denominator's width."""
    y = np.array([1] * 100 + [0] * 4)
    s = np.array([90.0] * 100 + [10.0] * 4)
    rows = operating_points(y, s, thresholds=(85,))
    row = rows[0]
    assert row["benign_fpr"] == 0.0
    assert row["n_benign"] == 4
    # At n=4 the Jeffreys upper bound on zero hits is wide enough to be useless.
    assert row["benign_fpr_ci95"][1] > 0.4


def test_operating_point_interval_narrows_with_a_real_denominator():
    y = np.array([1] * 100 + [0] * 600)
    s = np.array([90.0] * 100 + [10.0] * 600)
    row = operating_points(y, s, thresholds=(85,))[0]
    assert row["benign_fpr_ci95"][1] < 0.01


def test_bootstrap_interval_brackets_the_point_estimate():
    rng = np.random.default_rng(0)
    y = np.array([1] * 60 + [0] * 60)
    s = np.concatenate([rng.normal(1.0, 1.0, 60), rng.normal(0.0, 1.0, 60)])
    point = auroc(y, s)
    lo, hi = bootstrap_auroc(y, s, n=200, seed=1)
    assert lo <= point <= hi


def test_recall_and_fpr_move_in_the_expected_direction():
    y = np.array([1] * 50 + [0] * 50)
    s = np.concatenate([np.linspace(20, 100, 50), np.linspace(0, 60, 50)])
    rows = operating_points(y, s, thresholds=(25, 50, 70, 85))
    recalls = [r["recall"] for r in rows]
    fprs = [r["benign_fpr"] for r in rows]
    assert recalls == sorted(recalls, reverse=True)
    assert fprs == sorted(fprs, reverse=True)


# --------------------------------------------------------------------------
# Labelled-corpus import (acquired banking datasets)
# --------------------------------------------------------------------------

def test_labelled_root_carries_subclass_and_rejects_non_apks(tmp_path):
    """`banking` is the whole reason to acquire these corpora: it lets A4 and
    the evaluation split malware into 'after a bank' and 'not'."""
    from tools.corpus_labels import CLASS_MALWARE, claims_from_labelled_root

    (tmp_path / "real.apk").write_bytes(b"PK\x03\x04" + b"\x00" * 64)
    (tmp_path / "fake.apk").write_bytes(b"definitely not a zip")
    claims, src = claims_from_labelled_root(tmp_path, "cicmaldroid_banking",
                                            CLASS_MALWARE, subclass="banking")
    assert len(claims) == 1
    assert claims[0].subclass == "banking"
    assert src.cls == CLASS_MALWARE and src.n == 1


def test_a_sample_claimed_by_two_classes_becomes_conflicted(tmp_path):
    """An acquired corpus overlapping our benign set is plausible, and silently
    picking a winner would corrupt the denominator the project rests on."""
    from tools.corpus_labels import CLASS_BENIGN, CLASS_MALWARE, Claim, merge

    sha = "d" * 64
    labels, conflicts = merge([
        Claim(sha, CLASS_MALWARE, "cicmaldroid_banking", "x.apk", subclass="banking"),
        Claim(sha, CLASS_BENIGN, "benign_fdroid", "x.apk"),
    ])
    assert labels[sha]["class"] == "conflicted"
    assert conflicts == [sha]
    assert sorted(labels[sha]["conflicting_classes"]) == ["benign", "malware"]
