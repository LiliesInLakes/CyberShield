"""Unit tests for L2/sandbox/genai_navigator.py.

No real LLM call and no real emulator -- ``Provider.complete()`` is
replaced with a ``FakeProvider`` (same pattern as
``tests/test_l4_reasoning_verifier.py``'s ``FakeProvider``: a dataclass
whose ``.complete()`` returns a canned ``L4.provider.Completion``), and
adb calls are mocked out at the ``subprocess.run`` boundary via
``GenAINavigator._adb`` monkeypatching. Any test that genuinely needs a
live emulator/adb is ``pytest.skip``-guarded.
"""

from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import pytest  # noqa: E402

from L4.provider import Completion, ProviderError  # noqa: E402
from L2.sandbox.genai_navigator import (  # noqa: E402
    DummyDataGenerator,
    GenAINavigator,
    NavAction,
    UiElement,
    parse_action_json,
    parse_ui_elements,
    screen_hash,
)


@dataclass
class FakeProvider:
    """Mocks Provider.complete() with a queue of canned response texts."""

    responses: list[str]
    model: str = "fake/model"
    name: str = "fake"
    calls: list[dict] = field(default_factory=list)
    _i: int = field(default=0, init=False)

    def complete(self, messages, *, max_tokens: int = 2048, temperature: float = 0.0,
                 json_object: bool = False, reasoning: bool = False) -> Completion:
        self.calls.append({"messages": messages, "json_object": json_object})
        text = self.responses[min(self._i, len(self.responses) - 1)]
        self._i += 1
        return Completion(
            text=text, model=self.model, provider=self.name,
            prompt_tokens=10, completion_tokens=10, reasoning_chars=0,
            cost_usd=0.0, latency_s=0.01,
        )


class ExplodingProvider:
    """Simulates a provider that is configured but fails on every call."""

    model = "fake/model"
    name = "exploding"

    def complete(self, *args, **kwargs) -> Completion:
        raise ProviderError("simulated network failure")


SAMPLE_XML = """<?xml version="1.0"?>
<hierarchy>
  <node text="" resource-id="" class="android.widget.FrameLayout" clickable="false"
        bounds="[0,0][1080,1920]">
    <node text="Mobile Number" resource-id="com.sbi.app:id/mobile_input"
          class="android.widget.EditText" clickable="true" password="false"
          content-desc="" bounds="[100,300][980,400]" />
    <node text="OTP" resource-id="com.sbi.app:id/otp_input"
          class="android.widget.EditText" clickable="true" password="false"
          content-desc="" bounds="[100,500][980,600]" />
    <node text="Login PIN" resource-id="com.sbi.app:id/pin_input"
          class="android.widget.EditText" clickable="true" password="true"
          content-desc="" bounds="[100,700][980,800]" />
    <node text="SUBMIT" resource-id="com.sbi.app:id/submit_btn"
          class="android.widget.Button" clickable="true" password="false"
          content-desc="" bounds="[100,900][980,1000]" />
    <node text="" resource-id="" class="android.widget.TextView" clickable="false"
          bounds="[0,0][0,0]" />
  </node>
</hierarchy>
"""


# --------------------------------------------------------------------------
# perception: uiautomator XML parsing
# --------------------------------------------------------------------------

def test_parse_ui_elements_extracts_interactable_nodes():
    elements = parse_ui_elements(SAMPLE_XML)
    # 3 EditTexts + 1 clickable button = 4; the non-clickable, zero-bounds
    # TextView and the root FrameLayout are excluded.
    assert len(elements) == 4
    resource_ids = {e.resource_id for e in elements}
    assert "com.sbi.app:id/mobile_input" in resource_ids
    assert "com.sbi.app:id/otp_input" in resource_ids
    assert "com.sbi.app:id/pin_input" in resource_ids
    assert "com.sbi.app:id/submit_btn" in resource_ids


def test_parse_ui_elements_marks_password_field():
    elements = parse_ui_elements(SAMPLE_XML)
    pin = next(e for e in elements if e.resource_id.endswith("pin_input"))
    assert pin.password is True
    mobile = next(e for e in elements if e.resource_id.endswith("mobile_input"))
    assert mobile.password is False


def test_parse_ui_elements_computes_center_bounds():
    elements = parse_ui_elements(SAMPLE_XML)
    submit = next(e for e in elements if e.resource_id.endswith("submit_btn"))
    assert submit.center() == (540, 950)


def test_parse_ui_elements_respects_max_elements_cap():
    many_nodes = "".join(
        f'<node text="f{i}" resource-id="id{i}" class="android.widget.EditText" '
        f'clickable="true" bounds="[0,{i}][100,{i+10}]" />'
        for i in range(100)
    )
    xml = f"<hierarchy>{many_nodes}</hierarchy>"
    elements = parse_ui_elements(xml, max_elements=10)
    assert len(elements) == 10


def test_parse_ui_elements_empty_screen_returns_empty_list():
    assert parse_ui_elements("<hierarchy></hierarchy>") == []


def test_parse_ui_elements_malformed_xml_does_not_raise():
    # Truncated / broken markup -- must degrade gracefully, never raise.
    garbage = '<hierarchy><node text="unterminated clickable="true'
    assert parse_ui_elements(garbage) == []


def test_screen_hash_stable_across_reparse():
    a = parse_ui_elements(SAMPLE_XML)
    b = parse_ui_elements(SAMPLE_XML)
    assert screen_hash(a) == screen_hash(b)


def test_screen_hash_changes_when_elements_differ():
    a = parse_ui_elements(SAMPLE_XML)
    b = parse_ui_elements(SAMPLE_XML.replace("SUBMIT", "CONTINUE"))
    assert screen_hash(a) != screen_hash(b)


# --------------------------------------------------------------------------
# reasoning: defensive action-JSON parsing (adversarial-safe)
# --------------------------------------------------------------------------

def test_parse_action_json_clean_tap():
    action = parse_action_json(
        '{"action": "tap", "target_i": 3, "value": null, "reason": "tap submit"}'
    )
    assert action is not None
    assert action.action == "tap"
    assert action.target_i == 3
    assert action.value is None


def test_parse_action_json_type_with_value():
    action = parse_action_json(
        '{"action": "type", "target_i": 0, "value": "mobile_number", "reason": "fill mobile"}'
    )
    assert action.action == "type"
    assert action.value == "mobile_number"


def test_parse_action_json_strips_markdown_fence_and_prose():
    text = 'Sure, here is my choice:\n```json\n{"action": "wait", "target_i": null, "value": null, "reason": "loading"}\n```\nDone.'
    action = parse_action_json(text)
    assert action is not None
    assert action.action == "wait"


def test_parse_action_json_rejects_invalid_action_verb():
    action = parse_action_json('{"action": "delete_everything", "reason": "x"}')
    assert action is None


def test_parse_action_json_rejects_non_json_garbage():
    assert parse_action_json("I refuse to answer in JSON today.") is None


def test_parse_action_json_rejects_empty_string():
    assert parse_action_json("") is None
    assert parse_action_json("   ") is None


def test_parse_action_json_handles_nested_braces_in_value():
    # Adversarial: a value string containing literal braces/quotes must not
    # truncate the bracket-aware scan early.
    text = '{"action": "type", "target_i": 1, "value": "weird } value \\" here", "reason": "r"}'
    action = parse_action_json(text)
    assert action is not None
    assert action.value == 'weird } value " here'


def test_parse_action_json_never_evals():
    # A payload that would be dangerous under eval()/exec() must simply
    # fail to parse as an action, not execute anything.
    text = '{"action": "tap", "target_i": __import__("os").system("echo pwned"), "reason": "x"}'
    action = parse_action_json(text)
    assert action is None


def test_parse_action_json_coerces_string_target_i():
    action = parse_action_json('{"action": "tap", "target_i": "2", "reason": "x"}')
    assert action is not None
    assert action.target_i == 2


def test_parse_action_json_missing_action_key_returns_none():
    assert parse_action_json('{"target_i": 1, "reason": "no action field"}') is None


def test_parse_action_json_top_level_not_object_returns_none():
    assert parse_action_json('["tap", 1]') is None


# --------------------------------------------------------------------------
# dummy-data generation: field matching
# --------------------------------------------------------------------------

def _element(text="", resource_id="", content_desc="", password=False) -> UiElement:
    return UiElement(
        i=0, text=text, resource_id=resource_id, class_name="android.widget.EditText",
        content_desc=content_desc, editable=True, clickable=True, password=password,
        bounds=(0, 0, 100, 100),
    )


def test_dummy_mobile_is_ten_digits_valid_prefix():
    gen = DummyDataGenerator(seed=1)
    mobile = gen.mobile()
    assert len(mobile) == 10
    assert mobile.isdigit()
    assert mobile[0] in "6789"


def test_dummy_card_number_is_sixteen_digits():
    gen = DummyDataGenerator(seed=1)
    assert len(gen.card_number()) == 16
    assert gen.card_number().isdigit()


def test_dummy_upi_id_matches_handle_pattern():
    gen = DummyDataGenerator(seed=1)
    upi = gen.upi_id()
    assert "@" in upi
    assert upi.split("@")[1] in ("oksbi", "okhdfcbank", "okicici", "ybl", "paytm")


def test_dummy_mpin_is_six_digits_atm_pin_is_four():
    gen = DummyDataGenerator(seed=1)
    assert len(gen.mpin()) == 6
    assert len(gen.atm_pin()) == 4


def test_dummy_pan_matches_indian_pan_format():
    gen = DummyDataGenerator(seed=1)
    pan = gen.pan()
    assert len(pan) == 10
    assert pan[:5].isalpha() and pan[:5].isupper()
    assert pan[5:9].isdigit()
    assert pan[9].isalpha()


def test_dummy_value_is_deterministic_per_instance():
    gen = DummyDataGenerator(seed=42)
    assert gen.mobile() == gen.mobile()
    assert gen.name() == gen.name()


def test_dummy_value_for_matches_mobile_field():
    gen = DummyDataGenerator(seed=1)
    el = _element(text="Enter Mobile Number", resource_id="id/mobile")
    value = gen.value_for(el)
    assert value == gen.mobile()


def test_dummy_value_for_matches_card_over_generic_pin():
    gen = DummyDataGenerator(seed=1)
    el = _element(text="Card Number", resource_id="id/card_no")
    assert gen.value_for(el) == gen.card_number()


def test_dummy_value_for_prefers_mpin_over_generic_pin_pattern():
    gen = DummyDataGenerator(seed=1)
    el = _element(text="Set your MPIN", resource_id="id/mpin_field")
    assert gen.value_for(el) == gen.mpin()


def test_dummy_value_for_falls_back_for_unrecognised_password_field():
    gen = DummyDataGenerator(seed=1)
    el = _element(text="", resource_id="id/mystery", password=True)
    assert gen.value_for(el) == gen.mpin()


def test_dummy_value_for_generic_fallback_for_unmatched_field():
    gen = DummyDataGenerator(seed=1)
    el = _element(text="Favourite Colour", resource_id="id/colour")
    assert gen.value_for(el) == gen.generic_fallback()


def test_dummy_email_contains_at_and_known_domain():
    gen = DummyDataGenerator(seed=1)
    email = gen.email()
    assert "@" in email
    assert email.split("@")[1] in {"gmail.com", "yahoo.com", "outlook.com", "rediffmail.com"}


# --------------------------------------------------------------------------
# OTP-from-hint-file
# --------------------------------------------------------------------------

def test_otp_reads_from_hint_file(tmp_path):
    hint = tmp_path / "latest_injected_otp.txt"
    hint.write_text("482913")
    gen = DummyDataGenerator(seed=1, otp_hint_file=hint)
    assert gen.otp() == "482913"


def test_otp_falls_back_when_hint_file_missing(tmp_path):
    gen = DummyDataGenerator(seed=1, otp_hint_file=tmp_path / "does_not_exist.txt")
    otp = gen.otp()
    assert len(otp) == 6
    assert otp.isdigit()


def test_otp_falls_back_when_no_hint_file_configured():
    gen = DummyDataGenerator(seed=1)
    otp = gen.otp()
    assert len(otp) == 6 and otp.isdigit()


def test_value_for_otp_field_uses_hint_file(tmp_path):
    hint = tmp_path / "latest_injected_otp.txt"
    hint.write_text("111222")
    gen = DummyDataGenerator(seed=1, otp_hint_file=hint)
    el = _element(text="Enter OTP", resource_id="id/otp_field")
    assert gen.value_for(el) == "111222"


def test_otp_hint_file_strips_whitespace(tmp_path):
    hint = tmp_path / "latest_injected_otp.txt"
    hint.write_text("  654321\n")
    gen = DummyDataGenerator(seed=1, otp_hint_file=hint)
    assert gen.otp() == "654321"


# --------------------------------------------------------------------------
# GenAINavigator loop control (mocked adb + fake provider)
# --------------------------------------------------------------------------

def _bare_navigator(provider, **kwargs) -> GenAINavigator:
    return GenAINavigator(
        device_serial="emulator-5554",
        package_name="com.sbi.complaintregister",
        provider=provider,
        **kwargs,
    )


def test_navigator_stops_on_done_action(monkeypatch):
    provider = FakeProvider(responses=[
        '{"action": "done", "target_i": null, "value": null, "reason": "flow complete"}',
    ])
    nav = _bare_navigator(provider, max_steps=40, budget_s=30)
    monkeypatch.setattr(nav, "_dump_ui", lambda: SAMPLE_XML)
    monkeypatch.setattr(nav, "_adb", lambda *a: subprocess.CompletedProcess(a, 0, "", ""))

    summary = nav.run()
    assert summary["stop_reason"] == "done"
    assert summary["steps_taken"] == 1


def test_navigator_stops_at_max_steps(monkeypatch):
    provider = FakeProvider(responses=[
        '{"action": "wait", "target_i": null, "value": null, "reason": "loading"}',
    ])
    nav = _bare_navigator(provider, max_steps=3, budget_s=9999)
    monkeypatch.setattr(nav, "_dump_ui", lambda: SAMPLE_XML)
    monkeypatch.setattr(nav, "_adb", lambda *a: subprocess.CompletedProcess(a, 0, "", ""))
    monkeypatch.setattr("L2.sandbox.genai_navigator.time.sleep", lambda s: None)

    summary = nav.run()
    assert summary["stop_reason"] == "max_steps"
    assert summary["steps_taken"] == 3


def test_navigator_stops_on_budget_exhausted(monkeypatch):
    provider = FakeProvider(responses=[
        '{"action": "wait", "target_i": null, "value": null, "reason": "loading"}',
    ])
    nav = _bare_navigator(provider, max_steps=9999, budget_s=0.0)
    monkeypatch.setattr(nav, "_dump_ui", lambda: SAMPLE_XML)
    monkeypatch.setattr(nav, "_adb", lambda *a: subprocess.CompletedProcess(a, 0, "", ""))

    summary = nav.run()
    assert summary["stop_reason"] == "budget_exhausted"
    assert summary["steps_taken"] == 0


def test_navigator_cycle_detection_switches_to_swipe(monkeypatch):
    # Same screen every time, model keeps suggesting the same tap -- after
    # cycle_repeat_threshold repeats the navigator should override to swipe
    # rather than tapping the same element forever.
    provider = FakeProvider(responses=[
        '{"action": "tap", "target_i": 0, "value": null, "reason": "tap again"}',
    ])
    nav = _bare_navigator(provider, max_steps=6, budget_s=9999, cycle_repeat_threshold=2)
    monkeypatch.setattr(nav, "_dump_ui", lambda: SAMPLE_XML)

    executed_actions = []
    monkeypatch.setattr(nav, "_adb", lambda *a: subprocess.CompletedProcess(a, 0, "", ""))
    monkeypatch.setattr("L2.sandbox.genai_navigator.time.sleep", lambda s: None)

    orig_execute = nav._execute

    def spy_execute(action, elements):
        executed_actions.append(action.action)
        orig_execute(action, elements)

    monkeypatch.setattr(nav, "_execute", spy_execute)

    nav.run()
    # After the threshold, at least one action should have been overridden
    # to "swipe" instead of the model's repeated "tap".
    assert "swipe" in executed_actions


def test_navigator_logs_each_step_to_jsonl(tmp_path, monkeypatch):
    provider = FakeProvider(responses=[
        '{"action": "done", "target_i": null, "value": null, "reason": "done"}',
    ])
    log_path = tmp_path / "genai_nav.jsonl"
    nav = _bare_navigator(provider, log_path=log_path, max_steps=5, budget_s=30)
    monkeypatch.setattr(nav, "_dump_ui", lambda: SAMPLE_XML)
    monkeypatch.setattr(nav, "_adb", lambda *a: subprocess.CompletedProcess(a, 0, "", ""))

    nav.run()
    assert log_path.exists()
    lines = [json.loads(l) for l in log_path.read_text().splitlines() if l.strip()]
    assert any("action" in rec for rec in lines)
    assert any("summary" in rec for rec in lines)


def test_navigator_survives_unparsable_llm_response(monkeypatch):
    # The model returns garbage every time -- the navigator must not crash,
    # it should degrade each such step to a "wait" no-op and keep going
    # until max_steps.
    provider = FakeProvider(responses=["not json at all, sorry"])
    nav = _bare_navigator(provider, max_steps=2, budget_s=9999)
    monkeypatch.setattr(nav, "_dump_ui", lambda: SAMPLE_XML)
    monkeypatch.setattr(nav, "_adb", lambda *a: subprocess.CompletedProcess(a, 0, "", ""))
    monkeypatch.setattr("L2.sandbox.genai_navigator.time.sleep", lambda s: None)

    summary = nav.run()
    assert summary["steps_taken"] == 2
    assert summary["stop_reason"] == "max_steps"


def test_navigator_survives_provider_exception_mid_run(monkeypatch):
    nav = _bare_navigator(ExplodingProvider(), max_steps=2, budget_s=9999)
    monkeypatch.setattr(nav, "_dump_ui", lambda: SAMPLE_XML)
    monkeypatch.setattr(nav, "_adb", lambda *a: subprocess.CompletedProcess(a, 0, "", ""))
    monkeypatch.setattr("L2.sandbox.genai_navigator.time.sleep", lambda s: None)

    summary = nav.run()
    # Every step's reasoning call raises -- the loop still completes
    # max_steps rather than propagating the exception.
    assert summary["steps_taken"] == 2


def test_navigator_type_action_resolves_otp_from_hint_file(tmp_path, monkeypatch):
    hint = tmp_path / "latest_injected_otp.txt"
    hint.write_text("999888")
    provider = FakeProvider(responses=[
        '{"action": "type", "target_i": 1, "value": "otp", "reason": "fill otp"}',
        '{"action": "done", "target_i": null, "value": null, "reason": "done"}',
    ])
    nav = _bare_navigator(provider, otp_hint_file=hint, max_steps=5, budget_s=30)
    monkeypatch.setattr(nav, "_dump_ui", lambda: SAMPLE_XML)
    monkeypatch.setattr("L2.sandbox.genai_navigator.time.sleep", lambda s: None)

    typed_values = []

    def fake_adb(*args):
        if args[:2] == ("shell", "input") and args[2] == "text":
            typed_values.append(args[3])
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(nav, "_adb", fake_adb)

    nav.run()
    assert "999888" in typed_values


# --------------------------------------------------------------------------
# provider-unavailable fallback (orchestrator wiring)
# --------------------------------------------------------------------------

def test_orchestrator_start_genai_navigator_falls_back_when_provider_missing(monkeypatch):
    """L2Orchestrator._start_genai_navigator must return None (never raise)
    when OPENROUTER_API_KEY is absent, so detonate() falls back to
    DroidBot instead of hard-failing the run."""
    from L2.sandbox.orchestrator import L2Orchestrator
    from L4 import provider as provider_mod

    orch = L2Orchestrator.__new__(L2Orchestrator)
    orch.device_serial = "emulator-5554"
    orch.package_name = "com.sbi.complaintregister"
    orch.apk_path = Path("/nonexistent.apk")
    orch.detonation_time_s = 60
    orch.droidbot_duration_s = 120
    orch.otp_file_path = Path("/tmp/does_not_matter_otp.txt")
    orch.genai_nav_log_path = Path("/tmp/does_not_matter_nav.jsonl")
    orch.navigator_provider = "openrouter"

    monkeypatch.setattr(provider_mod, "load_env", lambda path=provider_mod.ENV_FILE: {})
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)

    result = orch._start_genai_navigator()
    assert result is None


def test_orchestrator_navigator_field_validated_in_post_init(tmp_path, monkeypatch):
    """Constructing with an unknown navigator mode fails fast and clearly."""
    from L2.sandbox.orchestrator import L2Orchestrator

    fake_apk = tmp_path / "fake.apk"
    fake_apk.write_bytes(b"PK\x03\x04")

    with pytest.raises(ValueError, match="navigator"):
        L2Orchestrator(
            apk_path=fake_apk,
            package_name="com.example.test",
            navigator="not_a_real_mode",
            auto_launch_emulator=False,
        )


# --------------------------------------------------------------------------
# live smoke (skip-guarded: needs a real attached emulator)
# --------------------------------------------------------------------------

def test_live_navigator_smoke_against_real_emulator():
    pytest.skip(
        "live smoke test: requires a booted sentinel30 AVD with adb attached "
        "and OPENROUTER_API_KEY configured -- run manually via "
        "'orchestrator.py <apk> <package> --navigator genai'"
    )
