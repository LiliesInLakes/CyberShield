"""The signal namespace shared by A4 (which prices signals) and L5 (which spends them).

A4 measures how often each signal fires on malware versus benign apps and turns
that into a weight. L5 reads those weights and adds them up. If each derived
"what signals does this spine carry" independently, the two would drift the
moment either changed — and a weight silently applied to the wrong signal is
undetectable by inspection. That is T15 with a different name, so both import
this module and a test pins the vocabulary.

**Keys are stable strings, not positions.** A weights file is keyed by these
strings and outlives the code that produced it, so renaming a key invalidates
every stored weight. ``SIGNAL_SCHEMA`` exists to make that break loud.

The namespace:

    yara:<RuleName>           a YARA rule fired          detail.yara_rule
    l0:brand_claim            app claims a bank identity smoking_gun_inputs
    l0:sms_trifecta           READ + RECEIVE + SEND SMS  smoking_gun_inputs
    l0:cert_anomaly:<name>    one signer anomaly         smoking_gun_inputs
    l0:verdict:<verdict>      L0's triage verdict        layers.l0.summary

``self_signed`` never appears as a ``cert_anomaly`` signal: L0 strips it before
promotion because every Android APK is self-signed (T6), so it is a ~100%
base-rate token that would earn a weight near zero and add noise to the report.

Every Signal carries the ``id`` of each finding that produced it. That is what
makes an L5 score auditable — a contribution can name the evidence it came from
rather than asserting a number.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

SIGNAL_SCHEMA = "apk-sentinel-signals-1"

# Prefixes, so consumers can filter a namespace without string-literal guessing.
NS_YARA = "yara:"
NS_L0 = "l0:"

CERT_ANOMALY_PREFIX = "l0:cert_anomaly:"
VERDICT_PREFIX = "l0:verdict:"

# ~100% base-rate tokens: present on essentially every APK, so they discriminate
# nothing and would earn a weight near zero while padding the report (T6, T23).
# L0 already strips `self_signed` before promotion; this is defence in depth,
# because a signal that reaches the namespace gets priced.
BASE_RATE_CERT_ANOMALIES = frozenset({"self_signed"})


@dataclass(frozen=True)
class Signal:
    """One priceable observation about one sample."""

    key: str
    evidence_ids: tuple[str, ...] = ()
    scopes: tuple[str, ...] = ()
    category: str = "other"

    @property
    def namespace(self) -> str:
        return self.key.split(":", 1)[0]


def _l0_summary(doc: dict[str, Any]) -> dict[str, Any]:
    return (doc.get("layers", {}).get("l0", {}) or {}).get("summary", {}) or {}


def yara_signals(doc: dict[str, Any]) -> list[Signal]:
    """One signal per distinct YARA rule that fired on this sample.

    L1 already emits one finding per (rule, sample) — that is the A2 contract,
    so ``len(findings)`` means "how many distinct detections fired". Grouping
    here is therefore defensive rather than corrective: it keeps the invariant
    true even if a future scope produces a second finding for the same rule.
    """
    by_rule: dict[str, dict[str, Any]] = {}
    for finding in doc.get("findings", []):
        detail = finding.get("detail") or {}
        rule = detail.get("yara_rule")
        if not rule:
            continue
        entry = by_rule.setdefault(
            rule, {"ids": [], "scopes": set(), "category": finding.get("category", "other")}
        )
        if finding.get("id"):
            entry["ids"].append(finding["id"])
        entry["scopes"].update(detail.get("scopes") or ())

    return [
        Signal(
            key=f"{NS_YARA}{rule}",
            evidence_ids=tuple(entry["ids"]),
            scopes=tuple(sorted(entry["scopes"])),
            category=entry["category"],
        )
        for rule, entry in sorted(by_rule.items())
    ]


def l0_signals(doc: dict[str, Any]) -> list[Signal]:
    """Impersonation, SMS-permission and certificate signals promoted by L0.

    These are read from ``layers.l0.summary`` rather than recomputed, because
    ``smoking_gun_inputs`` is documented as the literal input to L5's override
    gates — deriving it a second way here would create exactly the divergence
    this module exists to prevent.
    """
    summary = _l0_summary(doc)
    inputs = summary.get("smoking_gun_inputs") or {}

    # L0 findings that back these signals, so a contribution can cite evidence.
    impersonation_ids = tuple(
        f["id"]
        for f in doc.get("findings", [])
        if f.get("layer") == "l0"
        and (f.get("detail") or {}).get("l0_finding_type") == "brand_impersonation"
        and f.get("id")
    )
    cert_ids = tuple(
        f["id"]
        for f in doc.get("findings", [])
        if f.get("layer") == "l0"
        and str((f.get("detail") or {}).get("l0_finding_type", "")).startswith("cert_")
        and f.get("id")
    )

    out: list[Signal] = []

    if inputs.get("brand_claim"):
        out.append(Signal(
            key=f"{NS_L0}brand_claim",
            evidence_ids=impersonation_ids,
            category="phishing_impersonation",
        ))

    if inputs.get("sms_trifecta"):
        # Permission-derived, so there is no finding to cite: L0 records the
        # trifecta in its summary without minting a finding for it.
        out.append(Signal(key=f"{NS_L0}sms_trifecta", category="sms_intercept"))

    for anomaly in sorted(inputs.get("cert_anomalies") or ()):
        if anomaly in BASE_RATE_CERT_ANOMALIES:
            continue
        out.append(Signal(
            key=f"{CERT_ANOMALY_PREFIX}{anomaly}",
            evidence_ids=cert_ids,
            category="certificate_anomaly",
        ))

    verdict = summary.get("verdict")
    if verdict:
        out.append(Signal(key=f"{VERDICT_PREFIX}{verdict}", category="other"))

    return out


def signals(doc: dict[str, Any]) -> list[Signal]:
    """Every priceable signal in one spine, in one namespace, deterministically ordered."""
    return [*l0_signals(doc), *yara_signals(doc)]


def signal_keys(doc: dict[str, Any]) -> set[str]:
    """Just the keys — the form A4 counts over."""
    return {s.key for s in signals(doc)}


def vocabulary(docs: Iterable[dict[str, Any]]) -> dict[str, int]:
    """How many documents carry each signal key. The corpus-level A4 primitive."""
    counts: dict[str, int] = {}
    for doc in docs:
        for key in signal_keys(doc):
            counts[key] = counts.get(key, 0) + 1
    return counts
