"""The four smoking-gun gates, evaluated as ternary predicates over the spine.

Gates are the **primary** mechanism, not an override bolted onto a blend. Each
sets a *floor* on the score: ``max(score, floor)``. A floor rather than an
override because the additive score may legitimately exceed it, and in that
case the full reason chain must survive — and because a gate should never be
able to lower a score.

**Evaluation is ternary.** ``fired`` / ``not_fired`` / ``indeterminate``. A gate
whose input is missing *because coverage failed* is indeterminate, never false.
This matters: treating "jadx never produced the sources" as "the credential-UI
leg is absent" makes a failed analysis read as a clean app. Indeterminate legs
feed the confidence axis instead.

**Distinct evidence is required.** Both legs of a gate must cite different
finding ids. Without that, ``Android_BFSI_SMS_Intercept_And_Forward`` — which
detects reading SMS *and* forwarding it, inside one rule — would satisfy both
halves of G2 by itself, and the gate would be a rule rename wearing a gate's
clothes. That rule earns a large additive weight instead, which is where a
single-rule detection belongs.

🔴 **Two gates ship disabled because their evidence does not exist yet.** G3
needs "targets a known bank package", for which there is no source in the spine
(``Android_BFSI_Installed_App_Targeting`` fires 112 times but does not record
*which* packages). G4 needs the dropper permission and an embedded payload,
neither of which L0 currently records. Shipping them enabled-but-always-false
would be worse than shipping them off, because "gate did not fire" would look
like evidence of innocence.
"""

from __future__ import annotations

from typing import Any

from L5.score import GateResult

# Categories that satisfy the exfiltration leg of G2.
EXFIL_CATEGORIES = frozenset({"c2_communication", "data_exfiltration", "messaging_c2"})


def _findings(doc: dict[str, Any]) -> list[dict[str, Any]]:
    return doc.get("findings", []) or []


def _ids_for_category(doc: dict[str, Any], categories: frozenset[str] | set[str],
                      layers: tuple[str, ...] = ("l0", "l1", "l2")) -> list[str]:
    return [f["id"] for f in _findings(doc)
            if f.get("category") in categories and f.get("layer") in layers and f.get("id")]


def _ids_for_rules(doc: dict[str, Any], rule_names: list[str]) -> list[str]:
    wanted = set(rule_names or ())
    return [f["id"] for f in _findings(doc)
            if (f.get("detail") or {}).get("yara_rule") in wanted and f.get("id")]


def _l1_usable(doc: dict[str, Any]) -> bool:
    """Did static analysis actually get far enough to have an opinion?"""
    l1 = doc.get("layers", {}).get("l1") or {}
    return l1.get("status") in ("complete", "partial")


def _leg(name: str, ids: list[str], satisfied: bool | None,
         note: str = "") -> dict[str, Any]:
    return {"leg": name, "satisfied": satisfied,
            "evidence_ids": sorted(set(ids)), "note": note}


def _resolve(gate_id: str, cfg: dict[str, Any], legs: list[dict[str, Any]],
             require_distinct: bool) -> GateResult:
    floor = int(cfg.get("floor", 85))

    if any(l["satisfied"] is None for l in legs):
        return GateResult(gate_id=gate_id, state="indeterminate", floor=floor,
                          legs=tuple(legs),
                          missing_inputs=tuple(l["leg"] for l in legs
                                               if l["satisfied"] is None))
    if not all(l["satisfied"] for l in legs):
        return GateResult(gate_id=gate_id, state="not_fired", floor=floor,
                          legs=tuple(legs))

    if require_distinct:
        sets = [set(l["evidence_ids"]) for l in legs if l["evidence_ids"]]
        # Every leg must contribute at least one id no other leg already used.
        used: set[str] = set()
        for s in sets:
            fresh = s - used
            if not fresh:
                return GateResult(
                    gate_id=gate_id, state="not_fired", floor=floor,
                    legs=tuple(legs),
                    note="legs satisfied by the same finding; distinct evidence required")
            used |= fresh

    return GateResult(gate_id=gate_id, state="fired", floor=floor, legs=tuple(legs))


def gate_g1(doc: dict[str, Any], policy: Any) -> GateResult:
    """Bank impersonation + credential-harvesting UI."""
    cfg = (policy.raw.get("gates") or {}).get("G1_bank_impersonation_credential_ui", {})
    lists = policy.raw.get("gate_rule_lists") or {}

    l0 = (doc.get("layers", {}).get("l0") or {})
    inputs = (l0.get("summary") or {}).get("smoking_gun_inputs") or {}
    brand = bool(inputs.get("brand_claim")) and bool(inputs.get("claimed_entity"))
    brand_ids = _ids_for_category(doc, {"phishing_impersonation"}, layers=("l0",))

    if l0.get("status") not in ("complete", "partial"):
        leg_a = _leg("bank_impersonation", [], None, "L0 did not complete")
    else:
        leg_a = _leg("bank_impersonation", brand_ids, brand)

    if not _l1_usable(doc):
        leg_b = _leg("credential_ui", [], None, "L1 did not complete")
    else:
        ui_ids = (_ids_for_category(doc, {"phishing_impersonation"}, layers=("l1",))
                  + _ids_for_rules(doc, lists.get("credential_ui_rules", [])))
        leg_b = _leg("credential_ui", ui_ids, bool(ui_ids))

    return _resolve("G1_bank_impersonation_credential_ui", cfg, [leg_a, leg_b],
                    bool(cfg.get("require_distinct_evidence", True)))


def gate_g2(doc: dict[str, Any], policy: Any) -> GateResult:
    """SMS interception + exfiltration to an external C2."""
    cfg = (policy.raw.get("gates") or {}).get("G2_sms_intercept_exfil", {})
    lists = policy.raw.get("gate_rule_lists") or {}

    if not _l1_usable(doc):
        legs = [_leg("sms_intercept", [], None, "L1 did not complete"),
                _leg("exfiltration", [], None, "L1 did not complete")]
        return _resolve("G2_sms_intercept_exfil", cfg, legs, True)

    sms_ids = (_ids_for_category(doc, {"sms_intercept"})
               + _ids_for_rules(doc, lists.get("sms_intercept_rules", [])))
    exf_ids = (_ids_for_category(doc, EXFIL_CATEGORIES)
               + _ids_for_rules(doc, lists.get("exfil_rules", [])))

    legs = [_leg("sms_intercept", sms_ids, bool(sms_ids)),
            _leg("exfiltration", exf_ids, bool(exf_ids))]
    return _resolve("G2_sms_intercept_exfil", cfg, legs,
                    bool(cfg.get("require_distinct_evidence", True)))


def gate_g3(doc: dict[str, Any], policy: Any) -> GateResult:
    """Accessibility abuse + overlay on a *known bank package*.

    Leg C has no evidence source in the spine today, so the gate ships disabled.
    """
    cfg = (policy.raw.get("gates") or {}).get("G3_accessibility_overlay_bank_target", {})
    floor = int(cfg.get("floor", 85))
    if not cfg.get("enabled"):
        return GateResult(gate_id="G3_accessibility_overlay_bank_target",
                          state="disabled", floor=floor,
                          note=str(cfg.get("blocked_on", "")))

    acc = _ids_for_category(doc, {"accessibility_abuse"})
    ovl = _ids_for_category(doc, {"overlay_attack"})
    legs = [_leg("accessibility_abuse", acc, bool(acc)),
            _leg("overlay", ovl, bool(ovl)),
            _leg("bank_target", [], None, "no evidence source (A5 target-list rule)")]
    return _resolve("G3_accessibility_overlay_bank_target", cfg, legs, True)


def gate_g4(doc: dict[str, Any], policy: Any) -> GateResult:
    """Dropper permission + embedded secondary APK.

    Rewired to statically observable evidence — no network dependency — but L0
    does not yet record either input, so it ships disabled.
    """
    cfg = (policy.raw.get("gates") or {}).get("G4_dropper_embedded_apk", {})
    floor = int(cfg.get("floor", 70))
    if not cfg.get("enabled"):
        return GateResult(gate_id="G4_dropper_embedded_apk", state="disabled",
                          floor=floor, note=str(cfg.get("blocked_on", "")))

    inputs = ((doc.get("layers", {}).get("l0") or {}).get("summary") or {}) \
        .get("smoking_gun_inputs") or {}
    dropper = inputs.get("dropper_inputs") or {}
    if not dropper:
        legs = [_leg("request_install_packages", [], None, "L0 does not record it"),
                _leg("embedded_payload", [], None, "L0 does not record it")]
        return _resolve("G4_dropper_embedded_apk", cfg, legs, True)

    legs = [
        _leg("request_install_packages", [],
             bool(dropper.get("request_install_packages"))),
        _leg("embedded_payload", [],
             bool(dropper.get("embedded_apk_members")
                  or dropper.get("embedded_dex_members"))),
    ]
    return _resolve("G4_dropper_embedded_apk", cfg, legs, False)


GATES = (gate_g1, gate_g2, gate_g3, gate_g4)


def evaluate_all(doc: dict[str, Any], policy: Any) -> list[GateResult]:
    results: list[GateResult] = []
    for fn in GATES:
        gate_id = fn.__name__
        cfg_key = {
            "gate_g1": "G1_bank_impersonation_credential_ui",
            "gate_g2": "G2_sms_intercept_exfil",
            "gate_g3": "G3_accessibility_overlay_bank_target",
            "gate_g4": "G4_dropper_embedded_apk",
        }[gate_id]
        cfg = (policy.raw.get("gates") or {}).get(cfg_key, {})
        if not cfg.get("enabled") and cfg_key.startswith(("G1", "G2")):
            results.append(GateResult(gate_id=cfg_key, state="disabled",
                                      floor=int(cfg.get("floor", 85))))
            continue
        results.append(fn(doc, policy))
    return results
