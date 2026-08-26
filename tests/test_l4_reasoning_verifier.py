"""Unit tests for L4/reasoning_trail.py and L4/verify_verdict.py.

No real API calls — ``Provider.complete()`` is mocked with a tiny fake that
implements the same call signature used throughout L4
(``L4/provider.py``'s ``Provider`` protocol, as consumed by
``L4/deobfuscate.py``'s ``explain_class``). There was no existing
Provider-mocking pattern in ``tests/`` to follow (``test_l4_verify.py`` tests
``L4/verify.py`` directly, with no LLM call involved), so this file
establishes one: a ``FakeProvider`` whose ``.complete()`` returns a
pre-built ``Completion`` with canned JSON text.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from L4.provider import Completion  # noqa: E402
from L4.reasoning_trail import ReasoningTrail, build_trail  # noqa: E402
from L4.verify_verdict import VerifierVerdict, verify_trail  # noqa: E402


@dataclass
class FakeProvider:
    """Mocks Provider.complete() with a canned response text."""

    response_text: str
    model: str = "fake/model"
    name: str = "fake"
    calls: list[dict] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        self.calls = []

    def complete(self, messages, *, max_tokens: int = 2048, temperature: float = 0.0,
                 json_object: bool = False, reasoning: bool = False) -> Completion:
        self.calls.append({"messages": messages, "max_tokens": max_tokens,
                            "json_object": json_object})
        return Completion(
            text=self.response_text, model=self.model, provider=self.name,
            prompt_tokens=10, completion_tokens=10, reasoning_chars=0,
            cost_usd=0.0, latency_s=0.01,
        )


@dataclass
class FakeKBMatch:
    kb_id: str
    title: str
    similarity: float = 0.9
    mitre_techniques: list | None = None


class FakeKBIndex:
    """dict-like .get(kb_id) -> KBMatch | None, per verify_trail's assumption."""

    def __init__(self, matches: list[FakeKBMatch]):
        self._by_id = {m.kb_id: m for m in matches}

    def get(self, kb_id: str):
        return self._by_id.get(kb_id)


# --------------------------------------------------------------------------
# build_trail
# --------------------------------------------------------------------------

def test_build_trail_cites_kb_when_matches_exist():
    kb_matches = [FakeKBMatch(kb_id="T1636.004", title="SMS interception")]
    response = (
        '{"steps": ['
        '{"text": "The class reads incoming SMS via a BroadcastReceiver.", '
        '"kb_id": "T1636.004"}'
        ']}'
    )
    provider = FakeProvider(response_text=response)
    kept_claims = {"api_calls": ["android.telephony.SmsMessage.createFromPdu"]}

    trail = build_trail(kept_claims, kb_matches, provider)

    assert isinstance(trail, ReasoningTrail)
    assert trail.kb_ids_cited == ["T1636.004"]
    assert len(trail.steps) == 1
    assert trail.steps[0].startswith("[T1636.004]")
    assert provider.calls[0]["json_object"] is True


def test_build_trail_no_kb_citation_when_no_matches():
    response = (
        '{"steps": ['
        '{"text": "An identifier was renamed but has no supporting KB entry.", '
        '"kb_id": null}'
        ']}'
    )
    provider = FakeProvider(response_text=response)
    kept_claims = {"renamed": {"a": "smsReceiver"}}

    trail = build_trail(kept_claims, [], provider)

    assert trail.kb_ids_cited == []
    assert len(trail.steps) == 1
    assert trail.steps[0].startswith("no KB citation:")


def test_build_trail_rejects_kb_id_not_offered():
    """A step citing a kb_id that was never in kb_matches is not a real citation."""
    kb_matches = [FakeKBMatch(kb_id="T1636.004", title="SMS interception")]
    response = (
        '{"steps": ['
        '{"text": "Suspicious.", "kb_id": "MADE-UP-ID"}'
        ']}'
    )
    provider = FakeProvider(response_text=response)

    trail = build_trail({}, kb_matches, provider)

    assert trail.kb_ids_cited == []
    assert trail.steps[0].startswith("no KB citation:")


# --------------------------------------------------------------------------
# verify_trail
# --------------------------------------------------------------------------

def test_verify_trail_confirmed_when_citation_is_real():
    kb_index = FakeKBIndex([FakeKBMatch(kb_id="T1636.004", title="SMS interception")])
    trail = ReasoningTrail(
        steps=["[T1636.004] The class reads incoming SMS."],
        kb_ids_cited=["T1636.004"],
    )
    response = '{"status": "confirmed", "counter_argument": "None found.", "confidence": "high"}'
    provider = FakeProvider(response_text=response)

    result = verify_trail(trail, source="class A { void onReceive() {} }",
                          kb_index=kb_index, provider=provider)

    assert isinstance(result, VerifierVerdict)
    assert result.status == "confirmed"
    assert result.fabricated_citations == []
    assert result.confidence == "high"


def test_verify_trail_mechanically_overrides_llm_self_report():
    """The mock LLM claims 'confirmed' but the cited kb_id does not exist in
    the index. The mechanical check must catch this regardless of what the
    LLM says — this is the anti-self-report override the plan requires."""
    kb_index = FakeKBIndex([])  # empty index: the cited id resolves to nothing
    trail = ReasoningTrail(
        steps=["[FAKE-ID-999] The class does something suspicious."],
        kb_ids_cited=["FAKE-ID-999"],
    )
    # The LLM (mocked) is lying / hallucinating agreement — it says confirmed.
    response = '{"status": "confirmed", "counter_argument": "Looks solid.", "confidence": "high"}'
    provider = FakeProvider(response_text=response)

    result = verify_trail(trail, source="class A {}", kb_index=kb_index, provider=provider)

    # Mechanical check must find the fabrication...
    assert result.fabricated_citations == ["FAKE-ID-999"]
    # ...and must override the LLM's "confirmed" self-report. All cited
    # citations were fabricated here, so status is pushed all the way to refuted.
    assert result.status == "refuted"
    # A trail resting entirely on a fabricated citation cannot retain "high"
    # confidence just because the LLM said so.
    assert result.confidence != "high"


def test_verify_trail_partial_fabrication_weakens_not_refutes():
    kb_index = FakeKBIndex([FakeKBMatch(kb_id="REAL-ID", title="Real entry")])
    trail = ReasoningTrail(
        steps=["[REAL-ID] real step", "[FAKE-ID] fake step"],
        kb_ids_cited=["REAL-ID", "FAKE-ID"],
    )
    response = '{"status": "confirmed", "counter_argument": "ok", "confidence": "medium"}'
    provider = FakeProvider(response_text=response)

    result = verify_trail(trail, source="class A {}", kb_index=kb_index, provider=provider)

    assert result.fabricated_citations == ["FAKE-ID"]
    assert result.status == "weakened"


def test_verify_trail_no_citations_no_fabrication():
    kb_index = FakeKBIndex([])
    trail = ReasoningTrail(steps=["no KB citation: a plain observation"], kb_ids_cited=[])
    response = '{"status": "weakened", "counter_argument": "Plausible but unconfirmed.", "confidence": "low"}'
    provider = FakeProvider(response_text=response)

    result = verify_trail(trail, source="class A {}", kb_index=kb_index, provider=provider)

    assert result.fabricated_citations == []
    assert result.status == "weakened"
    assert result.confidence == "low"
