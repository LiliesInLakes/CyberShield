"""L4's deterministic scorer — one test per band in the plan's table.

`decisions/plan_l4_agentic_verdicts.md` §3 defines five bands. `kb_matches`
and `verifier_result` are duck-typed against `L4/knowledge/retriever.py`'s
`KBMatch` (`.similarity`) and `L4/verify_verdict.py`'s `VerifierVerdict`
(`.status`, `.confidence`) — both are being built by other agents in
parallel, so these tests use minimal stand-in objects rather than importing
either module.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from L4.scorer import ClassScore, score_class  # noqa: E402


@dataclass
class FakeKBMatch:
    similarity: float
    kb_id: str = "kb-1"


@dataclass
class FakeVerifierResult:
    status: str
    confidence: str = "medium"
    counter_argument: str = ""


def test_refuted_scores_zero():
    result = score_class(
        kept_claims={"api_calls": ["SmsManager.sendTextMessage"]},
        dropped_claims=[],
        kb_matches=[FakeKBMatch(similarity=0.9)],
        verifier_result=FakeVerifierResult(status="refuted"),
        suspicion={"flag": True, "reason": "looks bad"},
    )
    assert isinstance(result, ClassScore)
    assert result.score == 0
    assert result.band == "refuted"


def test_refuted_wins_even_with_kb_match_and_kept_claims():
    """Refuted is checked first and short-circuits every other condition."""
    result = score_class(
        kept_claims={"api_calls": ["a"], "iocs": ["b"]},
        dropped_claims=[],
        kb_matches=[FakeKBMatch(similarity=1.0)],
        verifier_result=FakeVerifierResult(status="refuted", confidence="high"),
        suspicion=None,
    )
    assert result.score == 0
    assert result.band == "refuted"


def test_hunch_band_scales_with_verifier_confidence_not_analyst_confidence():
    for confidence, expected in (("high", 4), ("medium", 2), ("low", 1)):
        result = score_class(
            kept_claims={},
            dropped_claims=[],
            kb_matches=[],
            verifier_result=FakeVerifierResult(status="confirmed", confidence=confidence),
            suspicion={"flag": True, "reason": "obfuscated string near a socket call"},
        )
        assert 1 <= result.score <= 4, (confidence, result)
        assert result.score == expected
        assert result.band == "hunch"


def test_no_suspicion_and_nothing_else_scores_zero_refuted():
    """No KB match, no kept claims, no flagged hunch: nothing to score."""
    result = score_class(
        kept_claims={},
        dropped_claims=[],
        kb_matches=[],
        verifier_result=FakeVerifierResult(status="confirmed"),
        suspicion={"flag": False, "reason": ""},
    )
    assert result.score == 0
    assert result.band == "refuted"


def test_ungrounded_kept_claim_band_is_3_to_5():
    result = score_class(
        kept_claims={"api_calls": ["SmsManager.sendTextMessage"]},
        dropped_claims=[],
        kb_matches=[],
        verifier_result=FakeVerifierResult(status="confirmed"),
        suspicion={},
    )
    assert 3 <= result.score <= 5
    assert result.band == "plausible"


def test_ungrounded_kept_claims_more_claims_score_higher_but_capped_at_5():
    low = score_class(
        kept_claims={"api_calls": ["x"]},
        dropped_claims=[], kb_matches=[],
        verifier_result=FakeVerifierResult(status="confirmed"), suspicion={},
    )
    high = score_class(
        kept_claims={"api_calls": ["x", "y"], "iocs": ["z"]},
        dropped_claims=[], kb_matches=[],
        verifier_result=FakeVerifierResult(status="confirmed"), suspicion={},
    )
    assert high.score >= low.score
    assert high.score <= 5


def test_kb_match_confirmed_scores_5_to_10_linear_on_similarity():
    low_sim = score_class(
        kept_claims={}, dropped_claims=[],
        kb_matches=[FakeKBMatch(similarity=0.3)],
        verifier_result=FakeVerifierResult(status="confirmed"), suspicion={},
    )
    high_sim = score_class(
        kept_claims={}, dropped_claims=[],
        kb_matches=[FakeKBMatch(similarity=1.0)],
        verifier_result=FakeVerifierResult(status="confirmed"), suspicion={},
    )
    assert low_sim.score == 5
    assert high_sim.score == 10
    assert low_sim.band == high_sim.band == "grounded"


def test_kb_match_confirmed_penalized_per_dropped_claim_floored_at_5():
    result = score_class(
        kept_claims={},
        dropped_claims=[{"kind": "decoded_strings", "claim": "x", "reason": "bad"}] * 10,
        kb_matches=[FakeKBMatch(similarity=1.0)],
        verifier_result=FakeVerifierResult(status="confirmed"),
        suspicion={},
    )
    assert result.score == 5  # floor, even with 10 dropped claims at max similarity


def test_kb_match_weakened_is_one_band_down_from_confirmed():
    confirmed = score_class(
        kept_claims={}, dropped_claims=[],
        kb_matches=[FakeKBMatch(similarity=1.0)],
        verifier_result=FakeVerifierResult(status="confirmed"), suspicion={},
    )
    weakened = score_class(
        kept_claims={}, dropped_claims=[],
        kb_matches=[FakeKBMatch(similarity=1.0)],
        verifier_result=FakeVerifierResult(status="weakened"), suspicion={},
    )
    assert weakened.score < confirmed.score
    assert weakened.score <= 5
    assert weakened.band == "grounded"


def test_kb_match_below_similarity_floor_is_not_a_match():
    """sim < 0.3 should not count as a KB match at all."""
    result = score_class(
        kept_claims={"api_calls": ["x"]},
        dropped_claims=[],
        kb_matches=[FakeKBMatch(similarity=0.1)],
        verifier_result=FakeVerifierResult(status="confirmed"),
        suspicion={},
    )
    assert result.band == "plausible"
    assert 3 <= result.score <= 5


def test_rationale_is_present_and_short():
    result = score_class(
        kept_claims={}, dropped_claims=[], kb_matches=[],
        verifier_result=FakeVerifierResult(status="confirmed"), suspicion={},
    )
    assert result.rationale
    assert len(result.rationale) < 200
