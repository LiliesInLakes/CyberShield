"""Promote L0's triage output into unified spine findings.

L0 records impersonation and certificate signals in its own nested shape
(``l0.impersonation.findings``). Left there, they are invisible to the rest of
the pipeline: L5 can only score what carries an evidence ID, and L6 can only
show what L5 scored. The bank-impersonation hit — the one detection that
distinguishes this system from a generic APK scanner — would have had nothing
for a report to cite.

This module is the translation. It is stdlib-only and takes plain dicts so it
can be tested without androguard and without an APK.
"""

from __future__ import annotations

from typing import Any

# Every impersonation finding type L0 can emit, mapped to a spine category.
# An unmapped type is a *loud* fallback (see `_category_for`) rather than a
# silent drop into `other` — a new detector must be classified deliberately.
_TYPE_CATEGORY = {
    "brand_impersonation": "phishing_impersonation",
    "label_spoof": "phishing_impersonation",
    "icon_spoof": "phishing_impersonation",
    "package_match_label_mismatch": "phishing_impersonation",
    "vision_logo_impersonation": "phishing_impersonation",
}

# Where the evidence physically lives in the APK. A finding whose location is
# a real file is one an analyst can go and check.
_TYPE_LOCATION = {
    "brand_impersonation": "AndroidManifest.xml",
    "label_spoof": "AndroidManifest.xml",
    "package_match_label_mismatch": "AndroidManifest.xml",
    "icon_spoof": "res/ (launcher icon)",
    "vision_logo_impersonation": "res/ (launcher icon)",
}

_MITRE = {
    "phishing_impersonation": ["T1655", "T1660"],
    "certificate_anomaly": [],
}


def _category_for(finding_type: str) -> str:
    if finding_type.startswith("cert_"):
        return "certificate_anomaly"
    return _TYPE_CATEGORY.get(finding_type, "other")


def _location_for(finding_type: str, icon: dict[str, Any] | None) -> str:
    if finding_type.startswith("cert_"):
        return "META-INF/ (signing block)"
    if finding_type in ("icon_spoof", "vision_logo_impersonation"):
        source = (icon or {}).get("source")
        if source:
            return str(source)
    return _TYPE_LOCATION.get(finding_type, "AndroidManifest.xml")


def _spine_key(finding: dict[str, Any]) -> str:
    """Identity of an L0 finding, stable across whitelist edits.

    The claimed entity is part of the identity: the same app flagged for
    impersonating a *different* bank is a different detection, not an update to
    the old one.
    """
    ftype = finding.get("type", "unknown")
    entity = finding.get("entity") or finding.get("bank") or finding.get("detected_brand")
    return f"{ftype}:{entity}" if entity else ftype


def impersonation_findings(l0: dict[str, Any]) -> list[dict[str, Any]]:
    """Convert ``l0.impersonation.findings`` into spine finding dicts."""
    impersonation = l0.get("impersonation") or {}
    icon = l0.get("icon") or {}
    out: list[dict[str, Any]] = []
    for finding in impersonation.get("findings") or []:
        ftype = finding.get("type", "unknown")
        category = _category_for(ftype)
        detail = {
            "spine_key": _spine_key(finding),
            "l0_finding_type": ftype,
            # The original record verbatim: promotion must never be lossy, and
            # a reviewer has to be able to check the translation.
            "l0_finding": finding,
        }
        entity = finding.get("entity") or finding.get("bank") or finding.get("detected_brand")
        if entity:
            detail["entity"] = entity
        out.append({
            "engine": "l0_impersonation",
            "category": category,
            "severity": finding.get("severity", "medium"),
            "evidence": f"[{ftype}] {finding.get('detail', '')}".strip(),
            "location": _location_for(ftype, icon),
            "mitre_techniques": _MITRE.get(category, []),
            "observation": "inferred",
            "detail": detail,
        })
    return out


def l0_summary(l0: dict[str, Any]) -> dict[str, Any]:
    """The distilled L0 block the spine carries.

    Deliberately small. The full L0 record stays in its own artifact; what goes
    in the spine is what a downstream layer actually reads — above all
    ``smoking_gun_inputs``, which is the literal input to L5's override gates.
    """
    impersonation = l0.get("impersonation") or {}
    certificate = l0.get("certificate") or {}
    routing = l0.get("routing") or {}
    reputation = l0.get("reputation") or {}
    return {
        "verdict": impersonation.get("verdict"),
        "claimed_entity": impersonation.get("claimed_entity"),
        "matched_bank": impersonation.get("matched_bank"),
        "smoking_gun_inputs": impersonation.get("smoking_gun_inputs", {}),
        "cert_signal": impersonation.get("cert_signal", {}),
        "cert_anomalies": [
            a for a in (certificate.get("anomalies") or []) if a != "self_signed"
        ],
        "track": routing.get("track"),
        "reputation_hit": bool(reputation.get("local_cache_hit")),
    }


def l0_coverage(l0: dict[str, Any]) -> dict[str, Any]:
    """What L0 was actually able to look at — the confidence axis's raw input."""
    icon = l0.get("icon") or {}
    certificate = l0.get("certificate") or {}
    manifest = l0.get("manifest") or {}
    return {
        "manifest_parsed": bool(manifest.get("package_name")),
        "icon_extracted": bool(icon.get("extraction_ok")),
        "certificate_parsed": bool(certificate.get("present")),
        "permission_count": manifest.get("permission_count", 0),
        "reputation_checked": bool((l0.get("reputation") or {}).get("local_cache_hit")),
    }


def l0_gaps(l0: dict[str, Any]) -> list[str]:
    """Machine-readable coverage holes. Consumed directly by L5's confidence."""
    gaps: list[str] = []
    icon = l0.get("icon") or {}
    certificate = l0.get("certificate") or {}
    manifest = l0.get("manifest") or {}
    if not icon.get("extraction_ok"):
        gaps.append("icon_not_extracted")
    if not certificate.get("present"):
        gaps.append("certificate_not_parsed")
    if not manifest.get("package_name"):
        gaps.append("manifest_not_parsed")
    return gaps


def identity(l0: dict[str, Any], source_apk: str = "") -> dict[str, Any]:
    """The top-level identity block: who this sample claims to be."""
    manifest = l0.get("manifest") or {}
    fingerprint = l0.get("fingerprint") or {}
    impersonation = l0.get("impersonation") or {}
    return {
        "sha256": fingerprint.get("sha256"),
        "sha1": fingerprint.get("sha1"),
        "md5": fingerprint.get("md5"),
        "package": manifest.get("package_name"),
        "app_label": manifest.get("app_label"),
        "version_name": manifest.get("version_name"),
        "source_apk": source_apk or None,
        "impersonates": impersonation.get("claimed_entity"),
    }
