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


def validate(policy: Policy) -> list[str]:
    """Returns a list of problems. Empty means the policy is coherent."""
    problems: list[str] = []
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
    lists = raw.get("gate_rule_lists") or {}
    gates = raw.get("gates") or {}
    enabled_gates = [g for g, cfg in gates.items() if cfg.get("enabled")]

    referenced: set[str] = set()
    for name, rules in lists.items():
        for rule in rules or []:
            referenced.add(rule)
            key = f"{sig_mod.NS_YARA}{rule}"
            entry = weights.get(key)
            if entry is None:
                problems.append(
                    f"gate list {name!r} names {rule!r}, which has no weight — "
                    "it fires on nothing in this corpus, so its specificity is unmeasured"
                )
                continue
            hi = (entry.get("ben_rate_ci95") or [0.0, 1.0])[1]
            if hi > max_ci:
                problems.append(
                    f"gate list {name!r} names {rule!r}: benign-rate 95% upper "
                    f"bound is {hi:.3f}, above the limit {max_ci:.3f} "
                    f"(b={entry.get('b')}/{entry.get('B')})"
                )
            if require_supported and entry.get("support") != "supported":
                problems.append(
                    f"gate list {name!r} names {rule!r}, whose weight is "
                    f"{entry.get('support')!r} — a Critical floor cannot rest on it"
                )

    if enabled_gates and problems:
        problems.append(
            f"{len(enabled_gates)} gate(s) are enabled ({', '.join(enabled_gates)}) "
            "while the checks above fail — disable them or fix the evidence"
        )

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

    return problems


def main(argv: list[str] | None = None) -> int:
    policy = load_policy()
    problems = validate(policy)

    print(f"policy {policy.version}  weights {policy.weights_version}  "
          f"support={'supported' if not policy.unsupported else 'UNSUPPORTED'}")
    if not problems:
        print("✅ policy is coherent with its weights file")
        return 0
    print(f"\n❌ {len(problems)} problem(s):\n")
    for p in problems:
        print(f"  - {p}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
