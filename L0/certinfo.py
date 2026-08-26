"""Signing-certificate extraction and anomaly classification.

Split out of ``ingest.py`` because the previous implementation was silently
broken: it called ``cert.public_bytes(...)`` on the objects returned by
androguard 4.x's ``APK.get_certificates()``, which are ``asn1crypto.x509
.Certificate`` and have no such method. The resulting ``AttributeError`` was
swallowed by a fallback that set ``present``/``sha256_fingerprint`` but left
``issuer``, ``subject``, ``self_signed`` and ``debug_signed`` as ``None`` — so
the failure looked like a clean parse of an unremarkable certificate.

Two design points worth stating up front:

* ``self_signed`` is **not** evidence. Every Android APK is self-signed; that is
  how the platform works. It is recorded, and it is weighted zero on its own.
  Only the *conjunction* of a bank-brand claim and an anomalous signer matters.
* The discriminating signal is the class of signer anomalies below — debug
  keystores, AOSP test keys, placeholder/empty distinguished names, and absurd
  validity windows. These are things a real publisher never ships.
"""

from __future__ import annotations

import re
from datetime import timezone
from typing import Any

# Distinguished-name value tokens that mark a non-production signer. Matched as
# whole tokens, never substrings, so "Testa Ltd" / "Contest" do not fire.
DEBUG_DN_TOKENS = {"debug", "debugging", "debugkey", "debugkeystore"}
PLACEHOLDER_DN_TOKENS = {
    "testkey", "dummy", "unknown", "example", "localhost",
    "common name", "your company", "changeme",
}

# The AOSP platform test key ships with a fixed notBefore of 2008-02-29.
AOSP_TEST_KEY_NOT_BEFORE = (2008, 2, 29)
MAX_SANE_VALIDITY_YEARS = 100

# Vendor identities that a self-signed third-party APK has no right to claim.
VENDOR_CLAIM_NAMES = {
    "android", "google", "google inc.", "google inc", "google llc",
    "samsung", "samsung electronics", "huawei", "xiaomi", "oneplus",
    "qualcomm", "mediatek", "oppo", "vivo",
}

_TOKEN_SPLIT = re.compile(r"[^a-z0-9]+")


def _dn_to_dict(name: Any) -> dict[str, str]:
    """asn1crypto Name -> plain {attribute: value} dict."""
    try:
        native = name.native
    except Exception:  # noqa: BLE001
        return {}
    if not isinstance(native, dict):
        return {}
    return {str(k): str(v) for k, v in native.items()}


# Attributes that actually name the publisher. Geographic fields are excluded
# from placeholder checks because `keytool` fills unspecified ones with
# "Unknown" — normal for any self-generated cert, and a false-positive source.
IDENTITY_DN_FIELDS = ("common_name", "organization_name")


def _dn_tokens(dn: dict[str, str], fields: tuple[str, ...] | None = None) -> set[str]:
    """Whole-word tokens across DN attribute values.

    `fields` restricts which attributes are considered; None means all of them.
    """
    tokens: set[str] = set()
    for key, value in dn.items():
        if fields is not None and key not in fields:
            continue
        lowered = value.casefold()
        tokens.update(t for t in _TOKEN_SPLIT.split(lowered) if t)
        tokens.add(lowered.strip())
    return tokens


def _validity_years(not_before: Any, not_after: Any) -> float | None:
    try:
        return (not_after - not_before).days / 365.25
    except Exception:  # noqa: BLE001
        return None


def classify_anomalies(subject: dict[str, str], issuer: dict[str, str],
                       not_before: Any, not_after: Any,
                       self_signed: bool) -> list[str]:
    """Return the anomaly ids present on this certificate."""
    anomalies: list[str] = []
    tokens = _dn_tokens(subject) | _dn_tokens(issuer)

    if tokens & DEBUG_DN_TOKENS:
        anomalies.append("debug_keystore")

    cn = (subject.get("common_name") or "").strip()
    org = (subject.get("organization_name") or "").strip()
    if cn == "Android" and org == "Android":
        nb = None
        try:
            nb = (not_before.year, not_before.month, not_before.day)
        except Exception:  # noqa: BLE001
            pass
        if nb == AOSP_TEST_KEY_NOT_BEFORE:
            anomalies.append("aosp_test_key")

    # Only identity-bearing fields: "Unknown" in locality/state is a keytool
    # default and is present on perfectly legitimate self-signed apps.
    identity_tokens = (_dn_tokens(subject, IDENTITY_DN_FIELDS)
                       | _dn_tokens(issuer, IDENTITY_DN_FIELDS))
    if identity_tokens & PLACEHOLDER_DN_TOKENS:
        anomalies.append("placeholder_dn")

    # A DN carrying nothing, or only a country field whose value is not a
    # two-letter code, is not a real publisher identity. One corpus sample
    # declares country_name="debugging".
    if not subject:
        anomalies.append("empty_dn")
    elif set(subject) == {"country_name"} and len(subject["country_name"]) != 2:
        anomalies.append("empty_dn")

    # A self-signed certificate naming a major device/OS vendor is a lie by
    # construction: those vendors do not self-sign third-party apps, and anyone
    # can put any string in a DN. Catches signers like "CN=Android, O=Google Inc."
    if self_signed:
        identity = {v.strip().casefold()
                    for k, v in list(subject.items()) + list(issuer.items())
                    if k in IDENTITY_DN_FIELDS}
        if identity & VENDOR_CLAIM_NAMES and "aosp_test_key" not in anomalies:
            anomalies.append("vendor_claiming_dn")

    years = _validity_years(not_before, not_after)
    if years is not None and years > MAX_SANE_VALIDITY_YEARS:
        anomalies.append("absurd_validity")

    if self_signed:
        # Recorded for completeness; carries no weight on its own (see docstring).
        anomalies.append("self_signed")

    return anomalies


def extract_cert_info(apk: Any) -> dict[str, Any]:
    """Extract signing-certificate metadata from an androguard APK object.

    Never raises. On failure sets ``extraction_ok=False`` and records ``error``
    plus ``parse_stage`` so the caller can surface an explicit analysis gap
    instead of a certificate that merely looks unremarkable.
    """
    result: dict[str, Any] = {
        "present": False,
        "extraction_ok": False,
        "parse_stage": "init",
        "cert_count": 0,
        "sha256_fingerprint": None,
        "issuer": None,
        "subject": None,
        "issuer_fields": {},
        "subject_fields": {},
        "serial_number": None,
        "not_before": None,
        "not_after": None,
        "validity_years": None,
        "self_signed": None,
        "debug_signed": None,
        "anomalies": [],
        "schemes": {},
    }

    try:
        result["parse_stage"] = "schemes"
        result["schemes"] = {
            "v1": bool(getattr(apk, "is_signed_v1", lambda: False)()),
            "v2": bool(getattr(apk, "is_signed_v2", lambda: False)()),
            "v3": bool(getattr(apk, "is_signed_v3", lambda: False)()),
        }
    except Exception:  # noqa: BLE001
        pass

    try:
        result["parse_stage"] = "get_certificates"
        certs = apk.get_certificates()
        if not certs:
            result["parse_stage"] = "no_certificates"
            result["extraction_ok"] = True   # parsed fine; there simply are none
            return result

        result["present"] = True
        result["cert_count"] = len(certs)
        cert = certs[0]

        result["parse_stage"] = "fingerprint"
        # asn1crypto exposes the DER digest directly; no hashlib, and no
        # dependency on `cryptography` (whose x509 API this object does not have).
        try:
            result["sha256_fingerprint"] = cert.sha256.hex()
        except Exception:  # noqa: BLE001
            import hashlib
            result["sha256_fingerprint"] = hashlib.sha256(cert.dump()).hexdigest()

        result["parse_stage"] = "names"
        subject = _dn_to_dict(cert.subject)
        issuer = _dn_to_dict(cert.issuer)
        result["subject_fields"] = subject
        result["issuer_fields"] = issuer
        try:
            result["subject"] = cert.subject.human_friendly
            result["issuer"] = cert.issuer.human_friendly
        except Exception:  # noqa: BLE001
            result["subject"] = str(subject)
            result["issuer"] = str(issuer)

        result["parse_stage"] = "validity"
        tbs = cert["tbs_certificate"]["validity"]
        not_before = tbs["not_before"].native
        not_after = tbs["not_after"].native
        result["not_before"] = str(not_before)
        result["not_after"] = str(not_after)
        result["validity_years"] = _validity_years(not_before, not_after)

        try:
            result["serial_number"] = str(cert.serial_number)
        except Exception:  # noqa: BLE001
            pass

        result["parse_stage"] = "classify"
        self_signed = subject == issuer and bool(subject)
        result["self_signed"] = self_signed
        anomalies = classify_anomalies(subject, issuer, not_before, not_after, self_signed)
        result["anomalies"] = anomalies
        # Retained for backwards compatibility with cert_registry.py and any
        # existing evidence reader.
        result["debug_signed"] = ("debug_keystore" in anomalies
                                  or "aosp_test_key" in anomalies)

        result["parse_stage"] = "done"
        result["extraction_ok"] = True
    except Exception as exc:  # noqa: BLE001
        result["error"] = f"{type(exc).__name__}: {exc}"
        result["extraction_ok"] = False

    return result
