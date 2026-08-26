"""L4's execution verifier.

Two failure directions matter equally here, and both are represented:

*Keeping a false claim* puts a fabricated C2 address into a report that a bank
may act on. The canonical case is real — during model selection a candidate
decoded ``aHR0cDovLzE5Mi4xNjguMS4xMDAvZ2F0ZS5waHA=`` as ``.../get.php`` when it
is ``gate.php``.

*Dropping a true claim* is not the safe direction. It discards real analysis and
makes the model look less reliable than it is. The first version of this module
did exactly that on four claims (``Log.i``, ``Log.e``, ``Log.d``,
``Date.<init>``) against a class that plainly contains all four, and it dropped
every single-character identifier — which is precisely what obfuscators emit.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from L4.verify import (  # noqa: E402
    _api_forms, _occurs_as_identifier, _try_decode, verify,
)

SOURCE = """package com.sbi.complaintregister;
import android.util.Log;
public class a extends BroadcastReceiver {
  private static String HttpUrl = "aHR0cDovLzE5Mi4xNjguMS4xMDAvZ2F0ZS5waHA=";
  private String b;
  public void onReceive(Context c, Intent intent) {
    Log.i(TAG, "Intent Action" + intent.getAction());
    Date carat = new Date();
    SmsMessage m = SmsMessage.createFromPdu((byte[]) z);
    SmsManager.getDefault().sendTextMessage(dst, null, body, null, null);
  }
}"""
CODE = [SOURCE]


# --------------------------------------------------------------------------
# Keeping false claims
# --------------------------------------------------------------------------

def test_the_real_hallucination_is_caught():
    """gate.php vs get.php — fluent, plausible, and refuted by a decoder."""
    v = verify({"decoded_strings": {
        "aHR0cDovLzE5Mi4xNjguMS4xMDAvZ2F0ZS5waHA=": "http://192.168.1.100/get.php"}},
        code=CODE)
    assert v.kept["decoded_strings"] == {}
    assert v.dropped[0]["reason"] == "decoding_does_not_match"
    assert v.dropped[0]["expected"] == ["http://192.168.1.100/gate.php"]


def test_the_correct_decoding_survives():
    v = verify({"decoded_strings": {
        "aHR0cDovLzE5Mi4xNjguMS4xMDAvZ2F0ZS5waHA=": "http://192.168.1.100/gate.php"}},
        code=CODE)
    assert v.kept["decoded_strings"]
    assert v.drop_count == 0


def test_an_invented_ioc_is_discarded():
    """The model may never introduce an indicator the deterministic layers
    missed — this is the claim class that reaches a blocklist."""
    v = verify({"iocs": ["192.168.1.100", "totally-invented.ru"]},
               code=CODE, extracted_iocs=["192.168.1.100"])
    assert v.kept["iocs"] == ["192.168.1.100"]
    assert any(d["claim"] == "totally-invented.ru" for d in v.dropped)


def test_an_api_not_in_the_code_is_discarded():
    v = verify({"api_calls": ["com.nowhere.Fake.methodThatIsNotThere"]}, code=CODE)
    assert v.kept["api_calls"] == []


def test_a_rename_of_an_absent_identifier_is_discarded():
    v = verify({"renamed": {"neverAppearsAnywhere": "Foo"}}, code=CODE)
    assert v.kept["renamed"] == {}


def test_a_literal_that_is_not_encoded_at_all_is_discarded():
    v = verify({"decoded_strings": {"just plain text": "something secret"}},
               code=CODE)
    assert v.kept["decoded_strings"] == {}
    assert v.dropped[0]["reason"] == "literal_is_not_decodable"


# --------------------------------------------------------------------------
# Dropping true claims (regressions)
# --------------------------------------------------------------------------

def test_single_character_identifiers_are_verifiable():
    """Obfuscators emit exactly the names a length floor rejects."""
    assert _occurs_as_identifier("a", CODE)
    assert _occurs_as_identifier("b", CODE)
    v = verify({"renamed": {"a": "SmsReceiver", "b": "payload"}}, code=CODE)
    assert v.kept["renamed"] == {"a": "SmsReceiver", "b": "payload"}


def test_identifier_matching_uses_word_boundaries_not_substrings():
    """'a' occurs inside 'class' and 'java'; that must not count."""
    assert not _occurs_as_identifier("lass", CODE)
    assert not _occurs_as_identifier("ntent", CODE)
    assert not _occurs_as_identifier("q", CODE)


def test_short_method_names_on_qualified_apis_are_verifiable():
    """android.util.Log.i has tail 'i'; matching the tail alone fails."""
    v = verify({"api_calls": ["android.util.Log.i"]}, code=CODE)
    assert v.kept["api_calls"] == ["android.util.Log.i"]


def test_constructors_are_matched_as_new_ClassName():
    """java.util.Date.<init> never appears literally in decompiled Java."""
    assert _api_forms("java.util.Date.<init>") == ["new Date"]
    v = verify({"api_calls": ["java.util.Date.<init>"]}, code=CODE)
    assert v.kept["api_calls"] == ["java.util.Date.<init>"]


def test_fully_qualified_apis_match_their_decompiled_spelling():
    v = verify({"api_calls": ["android.telephony.SmsManager.sendTextMessage",
                              "android.telephony.SmsMessage.createFromPdu"]},
               code=CODE)
    assert len(v.kept["api_calls"]) == 2


# --------------------------------------------------------------------------
# Narrative
# --------------------------------------------------------------------------

def test_unverifiable_narrative_is_marked_not_asserted():
    """A reader must be able to see which sentences rest on the model's word."""
    v = verify({"purpose": "Intercepts OTP messages",
                "behaviours": ["sms_interception"],
                "confidence": "high"}, code=CODE)
    assert set(v.unverified) == {"purpose", "behaviours", "confidence"}
    assert v.drop_count == 0


def test_summary_reports_what_survived():
    v = verify({"api_calls": ["android.util.Log.i", "com.nope.Absent.x"],
                "purpose": "x"}, code=CODE)
    s = v.summary()
    assert s["kept"]["api_calls"] == 1
    assert s["dropped"] == 1
    assert "purpose" in s["unverified_fields"]


# --------------------------------------------------------------------------
# Decoders
# --------------------------------------------------------------------------

def test_decoder_handles_base64_and_hex():
    assert "http://192.168.1.100/gate.php" in _try_decode(
        "aHR0cDovLzE5Mi4xNjguMS4xMDAvZ2F0ZS5waHA=")
    assert "evil.ru" in _try_decode("6576696c2e7275")


def test_decoder_returns_nothing_for_plain_text():
    assert _try_decode("hello world this is not encoded") == set()


def test_l4_mints_no_findings_and_defers_its_score_gate_to_l5():
    """L4 never asserts a fact with an evidence id — its narrative is not
    evidence. Whether a class reading moves the L5 score IS now a real policy
    (2026-08-26: gated on RAG-grounded or class score >= threshold, see
    ``L5/score.py::apply_l4``), so L4's own summary reports that as unknown
    (``None``) rather than a hardcoded 0 — the gate lives in L5's policy, not
    here, and duplicating the threshold check in both places would let them
    drift (T15). See ``tests/test_l5.py``'s ``test_ai_*`` cases for the gate
    itself.
    """
    from L4 import deobfuscate as deob
    src = (REPO_ROOT / "L4" / "deobfuscate.py").read_text()
    assert "contributes_points" in src
    summary = deob.promote(deob.DeobfuscationResult(sha256="x" * 64))
    assert summary["contributes_points"] is None
    # L4 never mints a finding — write_layer always passes findings=[].
    assert "findings=[]" in src
