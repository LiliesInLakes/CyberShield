"""L5 invariants.

Most of these guard properties that no amount of eyeballing a score would
catch: that scoring does not perturb the frozen detection denominator, that a
gate cannot be satisfied twice by one finding, that the ML prior cannot promote
a sample to Critical on its own, and that a failed analysis is reported as
unknown rather than clean.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import spine  # noqa: E402
from L5 import gates as gates_mod  # noqa: E402
from L5 import promote  # noqa: E402
from L5.score import (  # noqa: E402
    Policy, accumulate, apply_banking_ml, apply_gates, apply_ml, score_spine, to_score,
)
from L5.validate_policy import validate  # noqa: E402

import signals as sig_mod  # noqa: E402


# --------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------

def make_policy(**over) -> Policy:
    raw = {
        "policy_version": "test-1",
        "scoring": {"min_abs_weight": 0.2, "exclude_degenerate": True},
        "families": {
            "sms": {"decay": 0.5, "cap": 4.0,
                    "members": ["yara:*SMS*", "l0:sms_trifecta", "cat:sms_intercept"]},
            "brand": {"decay": 1.0, "cap": 4.0, "members": ["l0:brand_claim"]},
        },
        "calibration": {"method": "sigmoid", "s0": 3.0, "temperature": 2.0,
                        "status": "declared", "fitted_on": None},
        "bands": [[0, 24, "Informational"], [25, 49, "Low"], [50, 69, "Medium"],
                  [70, 84, "High"], [85, 100, "Critical"]],
        "ml": {"enabled": False, "max_delta": 10, "may_reach_critical": False},
        "gate_rule_lists": {"sms_intercept_rules": [], "exfil_rules": [],
                            "credential_ui_rules": []},
        "gate_constraints": {"max_benign_rate_upper_ci": 0.02, "require_supported": True},
        "gates": {
            "G1_bank_impersonation_credential_ui": {"enabled": True, "floor": 85,
                                                    "require_distinct_evidence": True},
            "G2_sms_intercept_exfil": {"enabled": True, "floor": 85,
                                       "require_distinct_evidence": True},
            "G3_accessibility_overlay_bank_target": {"enabled": False, "floor": 85},
            "G4_dropper_embedded_apk": {"enabled": False, "floor": 70},
        },
        "confidence": {
            "start": 1.0,
            "penalties": {"detonation_not_attempted": 0.25,
                          "decompilation_partial": 0.15,
                          "ghidra_unavailable": 0.05,
                          "gate_indeterminate": 0.10},
            "unsupported_weights_cap": 0.5,
            "bands": [[0.0, 0.39, "low"], [0.40, 0.74, "moderate"], [0.75, 1.0, "high"]],
        },
    }
    raw.update(over)
    weights = {
        "l0:brand_claim": {"w": 2.0, "support": "supported", "degenerate": False,
                           "category": "phishing_impersonation", "b": 0, "B": 600,
                           "ben_rate_ci95": [0.0, 0.006]},
        "l0:sms_trifecta": {"w": 1.5, "support": "supported", "degenerate": False,
                            "category": "sms_intercept", "b": 0, "B": 600,
                            "ben_rate_ci95": [0.0, 0.006]},
        "yara:A_SMS_One": {"w": 1.0, "support": "supported", "degenerate": False,
                           "category": "sms_intercept", "b": 0, "B": 600,
                           "ben_rate_ci95": [0.0, 0.006]},
        "yara:A_SMS_Two": {"w": 1.0, "support": "supported", "degenerate": False,
                           "category": "sms_intercept", "b": 0, "B": 600,
                           "ben_rate_ci95": [0.0, 0.006]},
        "yara:Noise": {"w": 0.05, "support": "supported", "degenerate": False,
                       "category": "other", "b": 0, "B": 600,
                       "ben_rate_ci95": [0.0, 0.006]},
        "yara:Everything": {"w": 2.9, "support": "supported", "degenerate": True,
                            "category": "other", "b": 590, "B": 600,
                            "ben_rate_ci95": [0.95, 0.99]},
    }
    meta = {"support": {"status": "supported"}, "ruleset_version": "test",
            "generated_at": "2026-08-11T00:00:00+00:00",
            "signal_schema": sig_mod.SIGNAL_SCHEMA}
    return Policy(raw=raw, weights=weights, weights_meta=meta)


def make_doc(**over):
    doc = {
        "schema_version": "apk-sentinel-0.2",
        "sha256": "b" * 64,
        "identity": {},
        "layers": {
            "l0": {"status": "complete", "summary": {
                "verdict": "impersonation_likely",
                "smoking_gun_inputs": {"brand_claim": True,
                                       "claimed_entity": "State Bank of India",
                                       "cert_anomalies": [], "sms_trifecta": True}}},
            "l1": {"status": "complete", "coverage": {"decompiled_files": 100}},
            "l2": {"status": "not_attempted"},
        },
        "findings": [
            {"id": "F001", "layer": "l0", "category": "phishing_impersonation",
             "detail": {"l0_finding_type": "brand_impersonation"}},
            {"id": "F002", "layer": "l1", "category": "sms_intercept",
             "detail": {"yara_rule": "A_SMS_One", "scopes": ["source"]}},
        ],
        "analysis_gaps": ["detonation_not_attempted"],
        "counts": {"malware_category": 2},
    }
    doc.update(over)
    return doc


# --------------------------------------------------------------------------
# Accumulation
# --------------------------------------------------------------------------

def test_family_decay_discounts_correlated_evidence():
    """Three SMS rules firing on one class is close to one fact, not three."""
    policy = make_policy()
    sigs = [sig_mod.Signal("yara:A_SMS_One", ("F001",), (), "sms_intercept"),
            sig_mod.Signal("yara:A_SMS_Two", ("F002",), (), "sms_intercept")]
    total, contribs = accumulate(sigs, policy)
    # 1.0 + 1.0*0.5, not 2.0
    assert total == pytest.approx(1.5)
    assert {c.discount for c in contribs} == {1.0, 0.5}


def test_log_odds_equals_sum_of_applied_contributions():
    """Every point in the score must trace to a contribution — no residue."""
    policy = make_policy()
    sigs = sig_mod.signals(make_doc())
    total, contribs = accumulate(sigs, policy)
    assert total == pytest.approx(sum(c.weight_applied for c in contribs))


def test_degenerate_and_negligible_signals_are_priced_at_zero():
    policy = make_policy()
    sigs = [sig_mod.Signal("yara:Everything", ("F001",), (), "other"),
            sig_mod.Signal("yara:Noise", ("F002",), (), "other")]
    total, contribs = accumulate(sigs, policy)
    assert total == pytest.approx(0.0)
    assert {c.status for c in contribs} == {"degenerate", "negligible"}


def test_unknown_signal_is_unpriced_not_guessed():
    policy = make_policy()
    total, contribs = accumulate(
        [sig_mod.Signal("yara:NeverSeenBefore", ("F009",), (), "other")], policy)
    assert total == 0.0
    assert contribs[0].status == "unpriced"


def test_family_cap_bounds_a_pile_of_correlated_rules():
    policy = make_policy(families={
        "sms": {"decay": 1.0, "cap": 2.0, "members": ["yara:*SMS*"]}})
    sigs = [sig_mod.Signal(f"yara:A_SMS_{n}", (f"F{n}",), (), "sms_intercept")
            for n in ("One", "Two")]
    total, _ = accumulate(sigs, policy)
    assert total == pytest.approx(2.0)


# --------------------------------------------------------------------------
# Mapping and bounds
# --------------------------------------------------------------------------

def test_score_is_bounded_and_monotone():
    policy = make_policy()
    scores = [to_score(s, policy) for s in (-50, -5, 0, 3, 10, 50)]
    assert scores == sorted(scores)
    assert 0 <= scores[0] and scores[-1] <= 100
    assert to_score(3.0, policy) == 50  # s0 is the 50-point anchor, by definition


def test_ml_is_bounded_to_ten_points():
    policy = make_policy(ml={"enabled": True, "max_delta": 10,
                             "may_reach_critical": False})
    doc = make_doc()
    for prob in (0.0, 0.25, 0.5, 0.75, 1.0):
        doc["layers"]["l3"] = {"status": "complete",
                               "summary": {"prob_malicious": prob}}
        _score, delta, _ = apply_ml(50, doc, policy)
        assert -10 <= delta <= 10


def test_ml_alone_cannot_reach_critical():
    """LAMDA is ~99.6% non-banking; it must not declare a banking trojan."""
    policy = make_policy(ml={"enabled": True, "max_delta": 10,
                             "may_reach_critical": False})
    doc = make_doc(layers={**make_doc()["layers"],
                           "l3": {"status": "complete",
                                  "summary": {"prob_malicious": 1.0}}})
    score, _delta, reason = apply_ml(80, doc, policy)
    assert score == 84
    assert reason == "ml_clamp"


def test_absent_l3_contributes_nothing():
    policy = make_policy(ml={"enabled": True, "max_delta": 10})
    score, delta, reason = apply_ml(50, make_doc(), policy)
    assert (score, delta, reason) == (50, 0, "")


# --------------------------------------------------------------------------
# L3b (banking-specific prior) — independent bound, independent refusal
# --------------------------------------------------------------------------

def _doc_with_l3b(prob: float, family_disjoint_status: str = "verified"):
    doc = make_doc()
    doc["layers"]["l3b"] = {
        "status": "complete",
        "summary": {"prob_banking_malicious": prob,
                    "family_disjoint_status": family_disjoint_status},
    }
    return doc


def test_banking_ml_is_bounded_to_ten_points():
    policy = make_policy(banking_ml={"enabled": True, "max_delta": 10,
                                     "may_reach_critical": False,
                                     "require_family_disjoint": True})
    for prob in (0.0, 0.25, 0.5, 0.75, 1.0):
        doc = _doc_with_l3b(prob)
        _score, delta, _ = apply_banking_ml(50, doc, policy)
        assert -10 <= delta <= 10


def test_banking_ml_alone_cannot_reach_critical():
    policy = make_policy(banking_ml={"enabled": True, "max_delta": 10,
                                     "may_reach_critical": False,
                                     "require_family_disjoint": True})
    doc = _doc_with_l3b(1.0)
    score, _delta, reason = apply_banking_ml(80, doc, policy)
    assert score == 84
    assert reason == "banking_ml_clamp"


def test_absent_l3b_contributes_nothing():
    policy = make_policy(banking_ml={"enabled": True, "max_delta": 10})
    score, delta, reason = apply_banking_ml(50, make_doc(), policy)
    assert (score, delta, reason) == (50, 0, "")


def test_banking_ml_refuses_to_move_the_score_while_split_is_unverified():
    """B37: a random split over clustered banking families means nothing.
    require_family_disjoint keeps an unverified model from moving the score,
    even though the delta is still computed and surfaced for --explain."""
    policy = make_policy(banking_ml={"enabled": True, "max_delta": 10,
                                     "require_family_disjoint": True})
    doc = _doc_with_l3b(1.0, family_disjoint_status="unverified_pending_malradar")
    score, delta, reason = apply_banking_ml(50, doc, policy)
    assert score == 50
    assert delta != 0
    assert reason == "banking_ml_unverified_split"


def test_banking_ml_applies_once_split_is_verified():
    policy = make_policy(banking_ml={"enabled": True, "max_delta": 10,
                                     "require_family_disjoint": True})
    doc = _doc_with_l3b(1.0, family_disjoint_status="verified")
    score, delta, reason = apply_banking_ml(50, doc, policy)
    assert score == 60
    assert delta == 10
    assert reason == ""


def test_banking_ml_and_ml_are_independently_toggleable():
    """L3's bound must not be affected by L3b existing, and vice versa."""
    policy = make_policy(ml={"enabled": True, "max_delta": 10},
                         banking_ml={"enabled": False, "max_delta": 10})
    doc = make_doc()
    doc["layers"]["l3"] = {"status": "complete", "summary": {"prob_malicious": 1.0}}
    doc["layers"]["l3b"] = {"status": "complete",
                            "summary": {"prob_banking_malicious": 1.0,
                                       "family_disjoint_status": "verified"}}
    _score, ml_delta, _ = apply_ml(50, doc, policy)
    _score, banking_delta, _ = apply_banking_ml(50, doc, policy)
    assert ml_delta == 10
    assert banking_delta == 0  # banking_ml.enabled is False


# --------------------------------------------------------------------------
# Gates
# --------------------------------------------------------------------------

def test_gate_is_a_floor_never_an_override():
    from L5.score import GateResult
    fired = [GateResult("G2_sms_intercept_exfil", "fired", 85)]
    # raises a low score...
    assert apply_gates(40, fired) == (85, "gate:G2_sms_intercept_exfil")
    # ...but never lowers a higher one
    assert apply_gates(92, fired) == (92, "additive")


def test_gate_is_indeterminate_when_coverage_failed_not_false():
    """A failed analysis must not read as a clean app."""
    policy = make_policy()
    doc = make_doc()
    doc["layers"]["l1"] = {"status": "failed"}
    g2 = [g for g in gates_mod.evaluate_all(doc, policy)
          if g.gate_id == "G2_sms_intercept_exfil"][0]
    assert g2.state == "indeterminate"
    assert "sms_intercept" in g2.missing_inputs


def test_one_finding_cannot_satisfy_both_legs_of_a_gate():
    """Otherwise a gate is just a rule rename wearing a gate's clothes."""
    policy = make_policy()
    doc = make_doc(findings=[
        {"id": "F001", "layer": "l1", "category": "sms_intercept",
         "detail": {"yara_rule": "A_SMS_One"}},
        {"id": "F001", "layer": "l1", "category": "data_exfiltration",
         "detail": {"yara_rule": "A_SMS_One"}},
    ])
    g2 = [g for g in gates_mod.evaluate_all(doc, policy)
          if g.gate_id == "G2_sms_intercept_exfil"][0]
    assert g2.state == "not_fired"
    assert "distinct evidence" in g2.note


def test_gate_fires_on_distinct_evidence():
    policy = make_policy()
    doc = make_doc(findings=[
        {"id": "F001", "layer": "l1", "category": "sms_intercept",
         "detail": {"yara_rule": "A_SMS_One"}},
        {"id": "F002", "layer": "l1", "category": "data_exfiltration",
         "detail": {"yara_rule": "Other"}},
    ])
    g2 = [g for g in gates_mod.evaluate_all(doc, policy)
          if g.gate_id == "G2_sms_intercept_exfil"][0]
    assert g2.state == "fired"


def test_disabled_gates_report_disabled_not_not_fired():
    """'Did not fire' would read as evidence of innocence; it is not."""
    policy = make_policy()
    states = {g.gate_id: g.state for g in gates_mod.evaluate_all(make_doc(), policy)}
    assert states["G3_accessibility_overlay_bank_target"] == "disabled"
    assert states["G4_dropper_embedded_apk"] == "disabled"


# --------------------------------------------------------------------------
# Confidence
# --------------------------------------------------------------------------

def test_confidence_never_changes_the_score():
    policy = make_policy()
    a = score_spine(make_doc(), policy)
    doc_b = make_doc(analysis_gaps=["detonation_not_attempted",
                                    "decompilation_partial"])
    b = score_spine(doc_b, policy)
    assert a.score == b.score
    assert b.confidence < a.confidence


def test_ghidra_gap_is_not_penalised_without_native_code():
    """149 samples carry this gap; most have no .so at all."""
    policy = make_policy()
    doc = make_doc(analysis_gaps=["ghidra_unavailable"])
    result = score_spine(doc, policy)
    assert result.confidence == pytest.approx(1.0)


def test_ghidra_gap_is_penalised_when_native_code_exists():
    policy = make_policy()
    doc = make_doc(analysis_gaps=["ghidra_unavailable"])
    doc["layers"]["l1"]["coverage"]["native_lib_count"] = 3
    result = score_spine(doc, policy)
    assert result.confidence == pytest.approx(0.95)


def test_unsupported_weights_cap_confidence():
    policy = make_policy()
    policy.weights_meta["support"] = {"status": "unsupported"}
    result = score_spine(make_doc(), policy)
    assert result.unsupported
    assert result.confidence <= 0.5


# --------------------------------------------------------------------------
# Spine contract
# --------------------------------------------------------------------------

def test_gate_findings_never_carry_a_malware_category():
    """counts.malware_category is the frozen 37% denominator (T15/B23)."""
    from L5.score import GateResult, ScoreResult
    result = ScoreResult(
        sha256="c" * 64, score=90, band="Critical", confidence=0.6,
        confidence_band="moderate", log_odds=5.0, contributions=(),
        gates=(GateResult("G2_sms_intercept_exfil", "fired", 85,
                          legs=({"leg": "sms_intercept", "satisfied": True,
                                 "evidence_ids": ["F001"]},
                                {"leg": "exfiltration", "satisfied": True,
                                 "evidence_ids": ["F002"]})),),
        binding_reason="gate:G2_sms_intercept_exfil", policy_version="t",
        weights_version="t", ruleset_version="t", unsupported=False)
    findings = promote.gate_findings(result)
    assert len(findings) == 1
    assert findings[0]["category"] == "other"
    assert findings[0]["category"] not in spine.MALWARE_CATEGORIES
    assert findings[0]["detail"]["spine_key"] == "l5_gate:G2_sms_intercept_exfil"
    assert findings[0]["detail"]["supporting_evidence_ids"] == ["F001", "F002"]


def test_no_finding_is_minted_for_the_additive_score():
    from L5.score import ScoreResult
    result = ScoreResult(
        sha256="c" * 64, score=60, band="Medium", confidence=0.8,
        confidence_band="high", log_odds=4.0, contributions=(), gates=(),
        binding_reason="additive", policy_version="t", weights_version="t",
        ruleset_version="t", unsupported=False)
    assert promote.gate_findings(result) == []


def test_l5_is_a_consumer_layer_and_writes_no_gaps():
    """spine._recompute reads gaps from every layer, so an L5 gap would feed
    back into L5's own confidence axis."""
    assert "l5" not in spine.EVIDENCE_LAYERS
    src = (REPO_ROOT / "L5" / "l5.py").read_text()
    assert "gaps=None" in src


# --------------------------------------------------------------------------
# Policy validation
# --------------------------------------------------------------------------

def test_a_gate_is_blocked_by_its_JOINT_benign_rate_not_its_legs():
    """B35: bounding each leg independently blocked both gates, because
    sms_intercept alone fires on 3.3% of benign apps. Measured end to end the
    same gate fires on 0 of 604. The conjunction is the whole point."""
    policy = make_policy()
    rates = {"G2_sms_intercept_exfil": {
        "fired_malware": 7, "fired_benign": 40, "n_benign": 604, "n_malware": 640,
        "ben_rate": 0.066, "ben_rate_ci95": [0.048, 0.089]}}
    problems, _warnings = validate(policy, rates)
    assert any("fires on 40/604 benign" in p for p in problems)


def test_a_gate_with_a_clean_joint_rate_passes():
    policy = make_policy()
    rates = {g: {"fired_malware": 7, "fired_benign": 0, "n_benign": 604,
                 "n_malware": 640, "ben_rate": 0.0, "ben_rate_ci95": [0.0, 0.0041]}
             for g in ("G1_bank_impersonation_credential_ui", "G2_sms_intercept_exfil")}
    problems, _ = validate(policy, rates)
    assert problems == []


def test_a_wide_legged_rule_is_a_warning_not_a_block():
    """Its specificity comes from the conjunction, so it is worth saying and
    not worth blocking on."""
    policy = make_policy()
    policy.raw["gate_rule_lists"]["sms_intercept_rules"] = ["yara_wide"]
    policy.weights["yara:yara_wide"] = {
        "w": 1.0, "support": "supported", "degenerate": False,
        "category": "sms_intercept", "b": 20, "B": 604,
        "ben_rate_ci95": [0.021, 0.050]}
    problems, warnings = validate(policy, {})
    assert any("exceeds" in w for w in warnings)
    assert not any("exceeds" in p for p in problems)


def test_a_gate_that_fires_on_no_malware_is_flagged_untested():
    policy = make_policy()
    rates = {"G2_sms_intercept_exfil": {
        "fired_malware": 0, "fired_benign": 0, "n_benign": 604, "n_malware": 640,
        "ben_rate": 0.0, "ben_rate_ci95": [0.0, 0.0041]}}
    _problems, warnings = validate(policy, rates)
    assert any("fires on no malware" in w for w in warnings)


def test_validator_rejects_an_ml_bound_above_ten():
    policy = make_policy()
    policy.raw["ml"]["max_delta"] = 25
    problems, _ = validate(policy)
    assert any("max_delta" in p for p in problems)


def test_validator_rejects_a_banking_ml_bound_above_ten():
    policy = make_policy()
    policy.raw["banking_ml"] = {"enabled": False, "max_delta": 25,
                                "may_reach_critical": False,
                                "require_family_disjoint": True}
    problems, _ = validate(policy)
    assert any("banking_ml.max_delta" in p for p in problems)


def test_validator_rejects_banking_ml_reaching_critical():
    policy = make_policy()
    policy.raw["banking_ml"] = {"enabled": True, "max_delta": 10,
                                "may_reach_critical": True,
                                "require_family_disjoint": True}
    problems, _ = validate(policy)
    assert any("banking_ml.may_reach_critical" in p for p in problems)


def test_validator_warns_when_banking_ml_enabled_without_family_disjoint_guard():
    policy = make_policy()
    policy.raw["banking_ml"] = {"enabled": True, "max_delta": 10,
                                "may_reach_critical": False,
                                "require_family_disjoint": False}
    _problems, warnings = validate(policy)
    assert any("require_family_disjoint" in w for w in warnings)


def test_validator_rejects_signal_schema_drift():
    policy = make_policy()
    policy.weights_meta["signal_schema"] = "apk-sentinel-signals-0"
    problems, _ = validate(policy)
    assert any("signal schema" in p for p in problems)


def test_shipped_policy_bands_tile_zero_to_hundred():
    from L5.score import load_policy
    policy = load_policy()
    problems, _ = validate(policy)
    assert [p for p in problems if "band" in p] == []


# --------------------------------------------------------------------------
# The frozen denominator
# --------------------------------------------------------------------------

def test_pre_l5_census_exists_and_records_the_frozen_headline():
    """L5 must not change a single one of these numbers."""
    path = REPO_ROOT / "tests" / "baseline" / "pre_L5" / "malware_category_census.json"
    doc = json.loads(path.read_text())
    assert doc["n_spines"] == 648
    assert doc["totals"]["samples_with_malware_category"] == 236
