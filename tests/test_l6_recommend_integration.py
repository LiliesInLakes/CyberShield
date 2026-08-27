"""L6/recommend.py::recommend() -- the full propose -> verify -> override
chain, with a mocked Provider (no real API calls).

Same FakeProvider pattern as tests/test_l4_reasoning_verifier.py established
for L4 -- a tiny dataclass whose .complete() returns a canned Completion.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from L4.provider import Completion  # noqa: E402
from L5.score import ScoreResult  # noqa: E402
from L6.recommend import recommend  # noqa: E402


@dataclass
class FakeProvider:
    response_text: str
    model: str = "fake/model"
    name: str = "fake"
    calls: list[dict] = field(default_factory=list)

    def complete(self, messages, *, max_tokens=2048, temperature=0.0,
                json_object=False, reasoning=False) -> Completion:
        self.calls.append({"messages": messages})
        return Completion(
            text=self.response_text, model=self.model, provider=self.name,
            prompt_tokens=10, completion_tokens=10, reasoning_chars=0,
            cost_usd=0.001, latency_s=0.01,
        )


def _doc(findings):
    return {"sha256": "abc123", "findings": findings}


def _score(band: str, unsupported: bool = False, score: int = 50) -> ScoreResult:
    return ScoreResult(
        sha256="abc123", score=score, band=band, confidence=0.8,
        confidence_band="high", log_odds=0.0, contributions=(), gates=(),
        binding_reason="additive", policy_version="test", weights_version="test",
        ruleset_version="test", unsupported=unsupported,
    )


def test_fabricated_finding_citation_is_dropped_end_to_end():
    doc = _doc([{"id": "F001", "category": "sms_intercept", "severity": "high",
                 "evidence": "SMS interception detected"}])
    # Proposes an action citing a finding id that does not exist (F999) --
    # must be dropped by the time recommend() returns.
    provider = FakeProvider(response_text=json.dumps({
        "summary": "Test summary.",
        "actions": [{"action": "notify_customers", "rationale": "x",
                     "citations": [{"kind": "finding", "id": "F999"}]}],
    }))
    rec = recommend(doc, _score("Medium", score=55), provider)
    assert not any(a.action == "notify_customers" for a in rec.actions)
    assert any(d["reason"] == "no_supporting_evidence" for d in rec.dropped)


def test_valid_proposal_survives_end_to_end():
    doc = _doc([{"id": "F001", "category": "sms_intercept", "severity": "high",
                 "evidence": "SMS interception detected"}])
    provider = FakeProvider(response_text=json.dumps({
        "summary": "Test summary.",
        "actions": [{"action": "notify_customers", "rationale": "Real finding.",
                     "citations": [{"kind": "finding", "id": "F001"}]}],
    }))
    rec = recommend(doc, _score("Medium", score=55), provider)
    assert any(a.action == "notify_customers" for a in rec.actions)
    assert rec.dropped == []


def test_immediate_tier_force_adds_escalation_when_model_omits_it():
    doc = _doc([{"id": "F001", "category": "ransomware", "severity": "critical",
                 "evidence": "Ransomware behaviour confirmed"}])
    # The model proposes only monitoring -- deliberately under-reacting to
    # a Critical-band report, to test the deterministic override.
    provider = FakeProvider(response_text=json.dumps({
        "summary": "Test summary.",
        "actions": [{"action": "monitor_only", "rationale": "x",
                     "citations": [{"kind": "finding", "id": "F001"}]}],
    }))
    rec = recommend(doc, _score("Critical", score=95), provider)
    assert rec.priority_tier == "IMMEDIATE"
    assert any(a.action == "escalate_cert_in" for a in rec.actions)
    forced = next(a for a in rec.actions if a.action == "escalate_cert_in")
    assert forced.citations == [{"kind": "deterministic", "id": "priority_tier"}]


def test_immediate_tier_does_not_duplicate_escalation_model_already_proposed():
    doc = _doc([{"id": "F001", "category": "ransomware", "severity": "critical",
                 "evidence": "Ransomware behaviour confirmed"}])
    provider = FakeProvider(response_text=json.dumps({
        "summary": "Test summary.",
        "actions": [{"action": "escalate_cert_in", "rationale": "Model's own call.",
                     "citations": [{"kind": "finding", "id": "F001"}]}],
    }))
    rec = recommend(doc, _score("Critical", score=95), provider)
    escalations = [a for a in rec.actions if a.action == "escalate_cert_in"]
    assert len(escalations) == 1
    assert escalations[0].rationale == "Model's own call."


def test_unsupported_score_forces_insufficient_evidence_regardless_of_model():
    doc = _doc([{"id": "F001", "category": "ransomware", "severity": "critical",
                 "evidence": "Ransomware behaviour confirmed"}])
    # Model confidently proposes escalation even though the score itself is
    # unsupported -- must be overridden, not trusted.
    provider = FakeProvider(response_text=json.dumps({
        "summary": "Test summary.",
        "actions": [{"action": "escalate_cert_in", "rationale": "x",
                     "citations": [{"kind": "finding", "id": "F001"}]}],
    }))
    rec = recommend(doc, _score("Critical", unsupported=True, score=95), provider)
    assert len(rec.actions) == 1
    assert rec.actions[0].action == "insufficient_evidence"


def test_unparsable_model_response_degrades_to_empty_actions_not_a_crash():
    doc = _doc([{"id": "F001", "category": "sms_intercept", "severity": "high",
                 "evidence": "x"}])
    provider = FakeProvider(response_text="not json at all, sorry")
    rec = recommend(doc, _score("Low", score=20), provider)
    assert rec.actions == []
    assert rec.priority_tier == "MONITOR"
