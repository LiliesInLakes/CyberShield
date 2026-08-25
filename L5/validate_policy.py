"""Check the policy against the weights file it claims to be built on.

    $SENTINEL_PYTHON L5/validate_policy.py

Run by pytest, not only by hand. The point is to make a whole class of mistake
un-shippable rather than merely unlikely.

**The load-bearing check is on gate membership.** A gate sets a Critical floor
on the score, so a rule inside one must be *measurably* specific. The obvious
candidates for G1's credential-UI leg are ``Android_WebView_JavaScriptEnabled``
(286/640 malware, but **3/4 benign**) and ``Android_WebView_JavascriptInterface``
(168/640, **2/4 benign**). Putting either in a Critical gate would be T7 with
extra steps — a plausible-looking rule that fires on ordinary software and
brands it critical.

So a rule may appear in a gate list only if the weights file shows its benign
rate's 95% **upper** bound under ``gate_constraints.max_benign_rate_upper_ci``,
and its support marked ``supported``. At n_benign = 4 that upper bound is 0.445
for *every* rule in the corpus, so **no gate can pass validation until the
benign corpus lands**. That is the correct behaviour, and it is I14 enforced in
code instead of in prose.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import signals as sig_mod  # noqa: E402
from L5.score import Policy, load_policy  # noqa: E402


def measure_gate_rates(policy: Policy) -> dict[str, dict]:
    """Empirical joint fire rate per gate, over the labelled corpus.

    This is the number that decides whether a Critical floor is safe: how often
    the whole conjunction fires on an app known to be benign.
    """
    import spine
    from L5 import gates as gates_mod
    from tools import corpus_labels
    from tools.rule_firing_report import jeffreys_interval

    try:
        labels = corpus_labels.general_population(corpus_labels.load()["labels"])
    except SystemExit:
        return {}

    tally: dict[str, dict] = {}
    n_mal = n_ben = 0
    for doc in spine.iter_spines():
        entry = labels.get(doc.get("sha256", ""))
        if not entry or entry["class"] not in ("malware", "benign"):
            continue
        is_mal = entry["class"] == "malware"
        n_mal += is_mal
        n_ben += not is_mal
        for g in gates_mod.evaluate_all(doc, policy):
            t = tally.setdefault(g.gate_id, {"fired_malware": 0, "fired_benign": 0,
                                             "indeterminate": 0})
            if g.state == "fired":
                t["fired_malware" if is_mal else "fired_benign"] += 1
            elif g.state == "indeterminate":
                t["indeterminate"] += 1

    for t in tally.values():
        lo, hi = jeffreys_interval(t["fired_benign"], n_ben)
        t["n_benign"] = n_ben
        t["n_malware"] = n_mal
        t["ben_rate"] = t["fired_benign"] / n_ben if n_ben else 0.0
        t["ben_rate_ci95"] = [lo, hi]
    return tally


def validate(policy: Policy,
             measured_gate_rates: dict[str, dict] | None = None
             ) -> tuple[list[str], list[str]]:
    """Returns (problems, warnings). Empty problems means the policy is coherent."""
    problems: list[str] = []
    warnings: list[str] = []
    measured_gate_rates = measured_gate_rates or {}
    raw = policy.raw
    weights = policy.weights
    constraints = raw.get("gate_constraints") or {}
    max_ci = float(constraints.get("max_benign_rate_upper_ci", 0.02))
    require_supported = bool(constraints.get("require_supported", True))

    # --- signal-schema agreement ------------------------------------------
    declared = policy.weights_meta.get("signal_schema")
    if declared and declared != sig_mod.SIGNAL_SCHEMA:
        problems.append(
            f"weights file was built against signal schema {declared!r}, "
            f"but signals.py is {sig_mod.SIGNAL_SCHEMA!r} — every key may have moved"
        )

    # --- gate membership ---------------------------------------------------
    #
    # 🔴 The blocking criterion is the gate's JOINT fire rate on benign apps,
    # measured end to end — not the benign rate of each rule it references.
    #
    # The first version of this function bounded each leg independently and
    # blocked both enabled gates. That is statistically wrong, and the corpus
    # says so plainly: `sms_intercept` fires on 3.3% of benign apps and the
    # exfiltration categories on ~2%, so every leg fails a 2% bar — yet
    # G2 requires **both, satisfied by distinct findings**, and fires on
    # 7 malware and 0 of 604 benign. Bounding the parts of a conjunction
    # discards exactly the specificity the conjunction was built to create.
    #
    # Per-rule rates are still computed, as warnings, because a gate resting on
    # a rule that fires on nothing is unmeasured rather than specific.
    lists = raw.get("gate_rule_lists") or {}
    gates = raw.get("gates") or {}
    enabled_gates = [g for g, cfg in gates.items() if cfg.get("enabled")]

    for name, rules in lists.items():
        for rule in rules or []:
            entry = weights.get(f"{sig_mod.NS_YARA}{rule}")
            if entry is None:
                warnings.append(
                    f"gate list {name!r} names {rule!r}, which fires on nothing "
                    "in this corpus — its specificity is unmeasured, not proven")
                continue
            hi = (entry.get("ben_rate_ci95") or [0.0, 1.0])[1]
            if hi > max_ci:
                warnings.append(
                    f"gate list {name!r} names {rule!r}: benign-rate 95% upper "
                    f"bound {hi:.3f} exceeds {max_ci:.3f} alone "
                    f"(b={entry.get('b')}/{entry.get('B')}) — acceptable only "
                    "because the gate requires a distinct-evidence conjunction")
            if require_supported and entry.get("support") != "supported":
                problems.append(
                    f"gate list {name!r} names {rule!r}, whose weight is "
                    f"{entry.get('support')!r} — a Critical floor cannot rest on it")

    if enabled_gates and measured_gate_rates:
        for gid in enabled_gates:
            stats = measured_gate_rates.get(gid)
            if stats is None:
                problems.append(
                    f"gate {gid} is enabled but its joint fire rate was not "
                    "measured — run validate_policy against a labelled corpus")
                continue
            hi = stats["ben_rate_ci95"][1]
            if hi > max_ci:
                problems.append(
                    f"gate {gid} fires on {stats['fired_benign']}/{stats['n_benign']} "
                    f"benign apps (95% upper bound {hi:.4f} > {max_ci:.3f}) — "
                    "a Critical floor cannot rest on that")
            if stats["fired_malware"] == 0:
                warnings.append(
                    f"gate {gid} is enabled but fires on no malware in this "
                    "corpus — it is untested, not safe")

    # --- calibration honesty ----------------------------------------------
    cal = raw.get("calibration") or {}
    if cal.get("status") == "fitted" and not cal.get("fitted_on"):
        problems.append("calibration claims status 'fitted' but records no fitted_on")

    # --- bands must tile 0..100 without gaps or overlaps -------------------
    bands = sorted((int(lo), int(hi)) for lo, hi, _n in raw.get("bands", []))
    if bands:
        if bands[0][0] != 0 or bands[-1][1] != 100:
            problems.append(f"bands do not cover 0..100: {bands}")
        for (_lo1, hi1), (lo2, _hi2) in zip(bands, bands[1:]):
            if lo2 != hi1 + 1:
                problems.append(f"band gap or overlap between {hi1} and {lo2}")

    # --- ML bound ----------------------------------------------------------
    ml = raw.get("ml") or {}
    if int(ml.get("max_delta", 10)) > 10:
        problems.append(
            f"ml.max_delta is {ml.get('max_delta')}, above the agreed ±10 bound"
        )
    if ml.get("may_reach_critical"):
        problems.append(
            "ml.may_reach_critical is true — a generic prior trained on a ~99.6% "
            "non-banking corpus must not be able to declare a banking trojan"
        )

    # --- banking_ml bound ----------------------------------------------
    banking_ml = raw.get("banking_ml") or {}
    if int(banking_ml.get("max_delta", 10)) > 10:
        problems.append(
            f"banking_ml.max_delta is {banking_ml.get('max_delta')}, above "
            "the agreed ±10 bound"
        )
    if banking_ml.get("may_reach_critical"):
        problems.append(
            "banking_ml.may_reach_critical is true — L3b is trained on a "
            "small, partially family-verified corpus and must not be able "
            "to declare a banking trojan by itself"
        )
    if banking_ml.get("enabled") and not banking_ml.get("require_family_disjoint", True):
        warnings.append(
            "banking_ml.require_family_disjoint is false while banking_ml is "
            "enabled — this lets an unverified-split model move the score; "
            "see B37 in docs/PROJECT_LOG.md for why that split matters"
        )

    return problems, warnings


def main(argv: list[str] | None = None) -> int:
    policy = load_policy()
    rates = measure_gate_rates(policy)
    problems, warnings = validate(policy, rates)

    print(f"policy {policy.version}  weights {policy.weights_version}  "
          f"support={'supported' if not policy.unsupported else 'UNSUPPORTED'}")

    if rates:
        print("\nmeasured gate fire rates (the blocking criterion):")
        for gid, s in sorted(rates.items()):
            print(f"  {gid:42s} mal {s['fired_malware']:4d}/{s['n_malware']}  "
                  f"ben {s['fired_benign']:3d}/{s['n_benign']}  "
                  f"95%up {s['ben_rate_ci95'][1]:.4f}")

    if warnings:
        print(f"\n⚠  {len(warnings)} warning(s):")
        for w in warnings:
            print(f"  - {w}")

    if not problems:
        print("\n✅ policy is coherent with its weights file")
        return 0
    print(f"\n❌ {len(problems)} problem(s):\n")
    for p in problems:
        print(f"  - {p}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
