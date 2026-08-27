"""L6/recommend.py::priority_tier() -- pure function, no mocks needed.

Mirrors test_l4_scorer.py's style: both are deterministic functions over
already-computed inputs, so these tests just construct ScoreResults and
assert the mapping, no LLM/network involved anywhere.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from L5.score import ScoreResult  # noqa: E402
from L6.recommend import priority_tier  # noqa: E402


def _score(band: str, unsupported: bool = False, score: int = 50) -> ScoreResult:
    return ScoreResult(
        sha256="x", score=score, band=band, confidence=0.8,
        confidence_band="high", log_odds=0.0, contributions=(), gates=(),
        binding_reason="additive", policy_version="test", weights_version="test",
        ruleset_version="test", unsupported=unsupported,
    )


def test_critical_band_is_immediate():
    assert priority_tier(_score("Critical", score=90)) == "IMMEDIATE"


def test_high_band_is_urgent_24h():
    assert priority_tier(_score("High", score=75)) == "URGENT_24H"


def test_medium_band_is_standard():
    assert priority_tier(_score("Medium", score=55)) == "STANDARD"


def test_low_band_is_monitor():
    assert priority_tier(_score("Low", score=30)) == "MONITOR"


def test_informational_band_is_monitor():
    assert priority_tier(_score("Informational", score=10)) == "MONITOR"


def test_unsupported_critical_score_is_downgraded_to_monitor():
    # The whole point of the override: a statistically unsupported score
    # cannot justify urgent action, no matter what number it produced --
    # mirrors L5's own refusal to arm a gate on unsupported weights.
    assert priority_tier(_score("Critical", unsupported=True, score=95)) == "MONITOR"


def test_unsupported_high_score_is_also_downgraded():
    assert priority_tier(_score("High", unsupported=True, score=80)) == "MONITOR"
