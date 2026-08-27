from __future__ import annotations

import logging
import io

import hashlib
import json
import os
import re
import subprocess
import sys
import zipfile
import requests
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from androguard.core.apk import APK
from PIL import Image
import imagehash

L0_DIR = Path(__file__).resolve().parent
REPO_ROOT = L0_DIR.parent
for _p in (str(L0_DIR), str(REPO_ROOT)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

# Certificate parsing lives in certinfo.py. Re-exported here so existing callers
# (cert_registry.py, evidence readers) keep importing it from ingest unchanged.
from certinfo import extract_cert_info  # noqa: E402,F401
import impersonation  # noqa: E402
import promote  # noqa: E402
import spine  # noqa: E402
WHITELIST_PATH = L0_DIR / "bank_whitelist.json"
CACHE_PATH = L0_DIR / "threat_cache.json"


def load_env(path: Path | None = None) -> None:
    """Minimal .env loader (no external dependency). Skips if vars already set."""
    env_path = path or (L0_DIR.parent / ".env")
    if not env_path.exists():
        return
    for raw in env_path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key, val = key.strip(), val.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = val

logging.getLogger("androguard").setLevel(logging.ERROR)
for _nh in ("androguard.core.axml", "androguard.core.analysis", "androguard.core.bytecodes"):
    logging.getLogger(_nh).setLevel(logging.ERROR)

log = logging.getLogger("L0.ingest")

HIGH_RISK_PERMISSIONS = {
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_MMS",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.READ_PHONE_STATE",
    "android.permission.READ_PHONE_NUMBERS",
    "android.permission.CALL_PHONE",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.USE_CREDENTIALS",
    "android.permission.GET_ACCOUNTS",
    "android.permission.RECEIVE_BOOT_COMPLETED",
    "android.permission.WRITE_SETTINGS",
}


@dataclass
class Evidence:
    schema_version: str = "apk-sentinel-0.1"
    generated_at: str = ""
    source_apk: str = ""
    l0: dict[str, Any] = field(default_factory=dict)
    l1: dict[str, Any] = field(default_factory=lambda: {"status": spine.LayerStatus.NOT_ATTEMPTED.value})
    l2: dict[str, Any] = field(default_factory=lambda: {"status": spine.LayerStatus.NOT_ATTEMPTED.value})
    l3: dict[str, Any] = field(default_factory=lambda: {"status": spine.LayerStatus.NOT_ATTEMPTED.value})
    l4: dict[str, Any] = field(default_factory=lambda: {"status": spine.LayerStatus.NOT_ATTEMPTED.value})
    l5: dict[str, Any] = field(default_factory=lambda: {"status": spine.LayerStatus.NOT_ATTEMPTED.value})
    l6: dict[str, Any] = field(default_factory=lambda: {"status": spine.LayerStatus.NOT_ATTEMPTED.value})


def compute_hashes(apk_path: Path) -> dict[str, str]:
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    with apk_path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            md5.update(chunk)
            sha256.update(chunk)
    return {"md5": md5.hexdigest(), "sha256": sha256.hexdigest()}


def _find_aapt() -> str | None:
    """Locate the `aapt` binary shipped with the bundled Android SDK.

    Uses the newest build-tools version present. Returns None if the SDK or
    build-tools aren't installed (the fallback then just doesn't run, and L0
    degrades exactly as it did before this fallback existed).
    """
    sdk = os.environ.get("ANDROID_SDK_ROOT")
    roots = [Path(sdk)] if sdk else []
    roots.append(REPO_ROOT / "tools" / "android-sdk")
    for root in roots:
        bts = root / "build-tools"
        if not bts.is_dir():
            continue
        for version_dir in sorted(bts.iterdir(), reverse=True):  # newest first
            cand = version_dir / "aapt"
            if cand.is_file() and os.access(cand, os.X_OK):
                return str(cand)
    return None


def _aapt_badging(apk_path: Path) -> dict[str, Any] | None:
    """Parse `aapt dump badging` — Android's own manifest reader.

    Why this exists: androguard's binary-XML parser gives up (returns None
    for the package name) on a manifest that has been *deliberately*
    corrupted to evade static analysis — e.g. resource type names padded
    with invisible Unicode filler (U+3164), false chunk sizes. That is
    exactly the anti-analysis technique the "Bank of lndia" typosquat sample
    uses. aapt is the same parser a real Android device runs at install
    time, and it is far more tolerant, so where androguard reads nothing,
    aapt still recovers the package, label and permissions. Without a
    package name, L2 (detonation) has nothing to `am start` and skips the
    sample outright — so the very samples sophisticated enough to sabotage
    their manifest were also the ones escaping dynamic analysis.

    Returns only the fields aapt actually reports; the caller fills these in
    over androguard's blanks, never overriding a value androguard got.
    Any failure (aapt absent, non-zero exit, timeout, unparseable output)
    returns None — a best-effort fallback, never a hard dependency.
    """
    aapt = _find_aapt()
    if not aapt:
        return None
    try:
        proc = subprocess.run(
            [aapt, "dump", "badging", str(apk_path)],
            capture_output=True, text=True, timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        log.warning("aapt fallback failed to run: %s", exc)
        return None
    # aapt exits non-zero on some malformed inputs but still prints a usable
    # `package:` line first, so parse stdout regardless of return code.
    out = proc.stdout or ""
    pkg_match = re.search(r"package: name='([^']*)'", out)
    if not pkg_match or not pkg_match.group(1):
        return None  # nothing usable recovered

    result: dict[str, Any] = {"package_name": pkg_match.group(1),
                              "recovered_via": "aapt"}
    for field, pat in (
        ("version_name", r"versionName='([^']*)'"),
        ("version_code", r"versionCode='([^']*)'"),
        ("min_sdk", r"sdkVersion:'([^']*)'"),
        ("target_sdk", r"targetSdkVersion:'([^']*)'"),
    ):
        m = re.search(pat, out)
        if m and m.group(1):
            result[field] = m.group(1)
    label = re.search(r"application-label:'([^']*)'", out)
    if label:
        result["app_label"] = label.group(1)
    perms = re.findall(r"uses-permission: name='([^']*)'", out)
    if perms:
        result["permissions"] = sorted(set(perms))
    return result


def harvest_manifest(apk: APK, apk_path: Path | None = None) -> dict[str, Any]:
    permissions = list(apk.get_permissions())
    manifest = {
        "package_name": apk.get_package(),
        "app_label": apk.get_app_name(),
        "version_name": apk.get_androidversion_name(),
        "version_code": apk.get_androidversion_code(),
        "min_sdk": apk.get_min_sdk_version(),
        "target_sdk": apk.get_target_sdk_version(),
        "permissions": sorted(permissions),
    }

    # Anti-analysis fallback: a sabotaged manifest leaves androguard with no
    # package name (and often no permissions). Recover what we can from aapt,
    # filling ONLY the blanks androguard left — never overriding a value it
    # did read. See _aapt_badging's docstring.
    if not manifest["package_name"] and apk_path is not None:
        recovered = _aapt_badging(Path(apk_path))
        if recovered:
            manifest["manifest_parse_fallback"] = "aapt"
            for key, value in recovered.items():
                if key == "recovered_via":
                    continue
                if not manifest.get(key):
                    manifest[key] = value
            permissions = list(manifest["permissions"])

    high_risk = sorted(set(permissions) & HIGH_RISK_PERMISSIONS)
    manifest.update({
        "permission_count": len(permissions),
        "high_risk_permissions": high_risk,
        "high_risk_permission_count": len(high_risk),
    })
    return manifest


def extract_icon_phash(apk: APK, artifacts_dir: Path | None = None) -> dict[str, Any]:
    """Extract the launcher icon and perceptual hashes.

    androguard's ``get_app_icon()`` defaults to ``max_dpi=65536``, which selects
    the ``anydpi-v26`` **adaptive-icon binary XML** in preference to any raster.
    PIL cannot decode that, so the icon silently failed to extract on roughly
    half of all modern APKs — including every India-targeted sample in the
    corpus. Walking down a dpi ladder makes it pick a real bitmap instead.
    """
    result: dict[str, Any] = {
        "present": False, "extraction_ok": False, "phash": None, "dhash": None,
        "source": None, "saved_path": None, "attempted_sources": [],
    }
    try:
        for max_dpi in (640, 480, 320, 240, 160, 65536):
            try:
                icon_path = apk.get_app_icon(max_dpi=max_dpi)
            except Exception:  # noqa: BLE001
                continue
            if not icon_path or icon_path in result["attempted_sources"]:
                continue
            result["attempted_sources"].append(icon_path)
            data = apk.get_file(icon_path)
            if not data:
                continue
            try:
                img = Image.open(io.BytesIO(data)).convert("RGB")
            except Exception:  # noqa: BLE001
                continue  # adaptive-icon XML or another non-raster: try lower dpi
            result["present"] = True
            result["extraction_ok"] = True
            result["phash"] = str(imagehash.phash(img))
            result["dhash"] = str(imagehash.dhash(img))
            result["source"] = icon_path
            if artifacts_dir:
                artifacts_dir.mkdir(parents=True, exist_ok=True)
                out = artifacts_dir / "icon.png"
                img.save(out, format="PNG")
                result["saved_path"] = str(out.relative_to(L0_DIR))
            return result
        result["error"] = "no decodable raster icon found"
    except Exception as exc:  # noqa: BLE001
        result["error"] = str(exc)
    return result


# (extract_cert_info now lives in certinfo.py — imported at the top of this file)


def load_threat_cache() -> dict[str, Any]:
    if not CACHE_PATH.exists():
        return {"hashes": {}}
    with CACHE_PATH.open() as fh:
        return json.load(fh)


def lookup_local_cache(sha256_hash: str, cache: dict[str, Any]) -> dict[str, Any] | None:
    record = cache.get("hashes", {}).get(sha256_hash)
    if not record:
        return None
    return {"source": "local_cache", "cache_hit": True, **record}


def load_whitelist() -> dict[str, Any]:
    if not WHITELIST_PATH.exists():
        return {"banks": []}
    with WHITELIST_PATH.open() as fh:
        return json.load(fh)


def _best_label_sim(app_label: str, bank: dict) -> float:
    """Check app_label against a bank's primary label and alt_labels."""
    app_lower = (app_label or "").lower()
    best = _label_similarity(bank.get("app_label", "").lower(), app_lower)
    for alt in bank.get("alt_labels", []):
        sim = _label_similarity(alt.lower(), app_lower)
        if sim > best:
            best = sim
    # Also check if bank_name appears as substring
    bank_name = bank.get("bank_name", "").lower()
    if bank_name and bank_name in app_lower:
        best = max(best, 0.75)
    return best


_ANOMALY_DETAIL = {
    "debug_keystore": "APK signed with an Android debug keystore — never used for "
                      "legitimate distribution.",
    "aosp_test_key": "APK signed with the public AOSP platform test key — anyone can "
                     "sign with it, so it proves no publisher identity.",
    "empty_dn": "Signing certificate carries no real publisher identity.",
    "placeholder_dn": "Signing certificate uses placeholder publisher details.",
    "absurd_validity": "Signing certificate has an implausible validity period.",
    "vendor_claiming_dn": "Self-signed certificate claims to be a major device vendor.",
}


def impersonation_check(manifest: dict, icon: dict, whitelist: dict, threshold: int = 8, detected_logos: list[str] | None = None, cert_info: dict[str, Any] | None = None) -> dict[str, Any]:
    findings = []
    matched_bank = None
    closest = None
    min_dist = None

    banks = whitelist.get("banks", [])

    # Brand claims from manifest-declared identity only (never dex/strings).
    brand_claims = (impersonation.match_label_brand(manifest.get("app_label") or "", whitelist)
                    + impersonation.match_package(manifest.get("package_name") or "", whitelist))
    official_packages = {b.get("package_name") for b in banks if b.get("package_name")}
    is_official_package = manifest.get("package_name") in official_packages
    trusted_names = {b.get("bank_name", "").lower() for b in banks}
    for bank in banks:
        pkg = bank.get("package_name", "")
        trusted_phash = bank.get("icon_phash")

        pkg_match = bool(pkg) and pkg == manifest.get("package_name")
        label_sim = _best_label_sim(manifest.get("app_label"), bank)

        dist = None
        if trusted_phash and icon.get("phash"):
            dist = imagehash.hex_to_hash(trusted_phash) - imagehash.hex_to_hash(icon["phash"])
            if min_dist is None or dist < min_dist:
                min_dist = dist
                closest = bank.get("bank_name")

        if pkg_match and label_sim >= 0.9:
            matched_bank = bank.get("bank_name")
        elif pkg_match and not label_sim >= 0.9:
            findings.append({
                "type": "package_match_label_mismatch",
                "bank": bank.get("bank_name"),
                "severity": "medium",
                "detail": "Package matches trusted bank but label differs (possible spoof).",
            })
        elif not pkg_match and label_sim >= 0.9:
            findings.append({
                "type": "label_spoof",
                "bank": bank.get("bank_name"),
                "severity": "high",
                "detail": "App label closely mimics trusted bank brand.",
            })

        if dist is not None and dist <= threshold and not pkg_match:
            findings.append({
                "type": "icon_spoof",
                "bank": bank.get("bank_name"),
                "phash_distance": int(dist),
                "severity": "high" if dist <= 4 else "medium",
                "detail": "Icon perceptual hash near trusted bank logo (possible lookalike).",
            })

    logo_findings = []
    if detected_logos:
        for logo in detected_logos:
            lname = (logo or "").lower()
            if lname in trusted_names:
                matched_pkg = next(
                    (b.get("package_name") for b in banks if b.get("bank_name", "").lower() == lname),
                    None,
                )
                if matched_pkg and manifest.get("package_name") != matched_pkg:
                    logo_findings.append({
                        "type": "vision_logo_impersonation",
                        "detected_brand": logo,
                        "severity": "high",
                        "detail": f"Vision API detected '{logo}' logo but package is not the official {matched_pkg}.",
                    })
                elif matched_pkg:
                    matched_bank = matched_bank or logo
    findings.extend(logo_findings)

    # ── Certificate-based signals (asymmetric weighting) ──────────────
    # Cert in whitelist  → strong positive  (+0.9)
    # Cert unknown        → neutral          (0.0) — absence ≠ evidence
    # Self-signed + bank  → red flag         (-0.9)
    # Debug-signed        → moderate negative (-0.5)
    cert_signal: dict[str, Any] = {
        "cert_in_whitelist": False,
        "cert_weight": 0.0,
        "cert_detail": None,
    }
    if cert_info and cert_info.get("present"):
        fp = cert_info.get("sha256_fingerprint")

        # Positive match: cert fingerprint is in our verified whitelist
        for bank in banks:
            ref_cert = bank.get("cert_sha256")
            if ref_cert and fp and ref_cert.lower() == fp.lower():
                cert_signal["cert_in_whitelist"] = True
                cert_signal["cert_weight"] = 0.9
                cert_signal["cert_detail"] = f"Certificate matches verified {bank.get('bank_name')} cert"
                matched_bank = bank.get("bank_name")
                break

        # Signer anomalies. `self_signed` is deliberately NOT among them: every
        # Android APK is self-signed (verified 22/22 locally, including all
        # benign controls), so on its own it carries no information and is
        # weighted zero. Only anomalies a real publisher never ships count.
        anomalies = [a for a in (cert_info.get("anomalies") or []) if a != "self_signed"]
        if not cert_signal["cert_in_whitelist"] and anomalies:
            brand_claimed = bool(brand_claims)
            # Two strong anomalies without a brand claim is still high: it is
            # how the mayJioTarget family presents (debug DN + 999-year validity)
            # with no brand token in its label at all.
            strong = {"debug_keystore", "aosp_test_key", "vendor_claiming_dn"}
            severity = ("high" if (brand_claimed and set(anomalies) & strong)
                        else "high" if len(anomalies) >= 2 and set(anomalies) & strong
                        else "medium" if set(anomalies) & strong
                        else "low")
            cert_signal["cert_weight"] = -0.9 if brand_claimed else -0.5
            cert_signal["cert_detail"] = f"Signer anomalies: {', '.join(anomalies)}"
            findings.append({
                "type": f"cert_{anomalies[0]}",
                "severity": severity,
                "anomalies": anomalies,
                "subject": cert_info.get("subject"),
                "detail": _ANOMALY_DETAIL.get(
                    anomalies[0], "Signing certificate shows publisher anomalies.")
                + (f" App claims to be {brand_claims[0]['entity']}." if brand_claimed else ""),
            })

        # If cert not in whitelist and not self-signed/debug → NEUTRAL (0.0)
        # This is intentional: we can't penalise unknown certs because we'll
        # never have every legitimate cert. The whitelist grows over time.

    # Brand claims become findings only when the app is NOT the official package.
    claimed_entity = None
    if brand_claims and not is_official_package:
        claimed_entity = brand_claims[0]["entity"]
        entities = sorted({c["entity"] for c in brand_claims if c.get("entity")})
        has_cert_anomaly = any(f["type"].startswith("cert_") for f in findings)
        sev = ("critical" if has_cert_anomaly
               else "high" if len(brand_claims) >= 2 else "medium")
        findings.append({
            "type": "brand_impersonation",
            "severity": sev,
            "entity": claimed_entity,
            "entities": entities,
            "claims": brand_claims,
            "detail": f"App presents itself as {claimed_entity} "
                      f"({', '.join(c['type'] for c in brand_claims)}) but is not an "
                      f"official {claimed_entity} package."
                      + (" Signer is anomalous." if has_cert_anomaly else ""),
        })

    # The verdict is a function of the findings, never of matched_bank alone.
    # Previously `matched_bank` short-circuited it, so a package+label clone was
    # reported `trusted` while carrying a critical finding in the same object.
    _RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    worst = max((_RANK.get(f.get("severity", "low"), 1) for f in findings), default=0)
    if matched_bank and worst <= 1:
        verdict = "trusted"
    elif worst >= 4:
        verdict = "impersonation_likely"
    elif worst == 3:
        verdict = "impersonation_suspected"
    elif findings:
        verdict = "suspicious"
    else:
        verdict = "unknown"
    return {
        "verdict": verdict,
        "matched_bank": matched_bank,
        "claimed_entity": claimed_entity,
        "brand_claims": brand_claims,
        "smoking_gun_inputs": {
            "brand_claim": bool(brand_claims) and not is_official_package,
            "claimed_entity": claimed_entity,
            "cert_anomalies": [a for a in ((cert_info or {}).get("anomalies") or [])
                               if a != "self_signed"],
            "sms_trifecta": {"android.permission.READ_SMS",
                             "android.permission.RECEIVE_SMS",
                             "android.permission.SEND_SMS"}.issubset(
                                 set(manifest.get("permissions") or [])),
        },
        "closest_bank": closest,
        "closest_phash_distance": int(min_dist) if min_dist is not None else None,
        "phash_threshold": threshold,
        "vision_logos": detected_logos,
        "cert_signal": cert_signal,
        "findings": findings,
    }


def _label_similarity(a: str, b: str) -> float:
    if not a or not b:
        return 0.0
    if a == b:
        return 1.0
    import difflib
    return difflib.SequenceMatcher(None, a, b).ratio()


def track_routing(apk_path: Path) -> dict[str, Any]:
    """Deterministic L0 -> L1 track routing.

    Decides which extraction engine(s) the sample must hit:
      - track1_jadx              : Dalvik bytecode only
      - track2_ghidra            : native .so only (no dex)
      - track1_jadx_then_track2_ghidra : hybrid (dex + native)
    Also flags packing/obfuscation signals that raise Ghidra priority.
    """
    with zipfile.ZipFile(apk_path) as zf:
        names = zf.namelist()
        dex_sizes = {n: zf.getinfo(n).file_size for n in names if n.endswith(".dex")}

    dex = [n for n in names if n.endswith(".dex")]
    native = [n for n in names if n.endswith(".so")]
    arches = sorted({n.split("/")[1] for n in native if n.startswith("lib/") and len(n.split("/")) > 2})

    has_dex = bool(dex)
    has_native = bool(native)

    if has_native and not has_dex:
        track = "track2_ghidra"
    elif has_native and has_dex:
        track = "track1_jadx_then_track2_ghidra"
    else:
        track = "track1_jadx"

    frameworks = _framework_indicators(names)
    packing_signals = _packing_signals(names, dex_sizes)

    decisions = []
    if has_dex:
        decisions.append({
            "engine": "jadx",
            "targets": dex,
            "reason": "Dalvik bytecode present; decompile smali to Java for static triage.",
        })
    if has_native:
        decisions.append({
            "engine": "ghidra",
            "targets": native,
            "arches": arches,
            "reason": "Native shared libraries present; decompile ARM/x86 .so for C2 strings and hidden payloads.",
        })
    if packing_signals:
        decisions.append({
            "engine": "ghidra",
            "priority": "elevated",
            "reason": "Packing/obfuscation indicators detected; native layer likely hides payloads.",
        })

    return {
        "track": track,
        "dex_files": dex,
        "dex_count": len(dex),
        "native_libs": native,
        "native_lib_count": len(native),
        "native_arches": arches,
        "framework_indicators": frameworks,
        "packing_signals": packing_signals,
        "routing_decisions": decisions,
    }


def _framework_indicators(names: list[str]) -> list[str]:
    indicators = []
    joined = "\n".join(names).lower()
    probes = {
        "flutter": "flutter",
        "react_native": "react_native",
        "xamarin": "xamarin",
        "cordova": "cordova",
        "unity": "unity",
        "kotlin": "kotlin",
    }
    for key, token in probes.items():
        if token in joined:
            indicators.append(key)
    return indicators


def _packing_signals(names: list[str], dex_sizes: dict[str, int]) -> list[str]:
    """Heuristics suggesting packing/obfuscation -> Ghidra priority."""
    signals = []
    lowered = [n.lower() for n in names]
    joined = "\n".join(lowered)

    packer_tokens = {
        "libshell": "Tencent Legu / libshell packer",
        "libmsaoaidsec": "Bangcle (BangcleSec) packer",
        "libprotect": "Generic protection wrapper",
        "libchaos": "Chaos packer",
        "libnqshield": "NQ Shield packer",
        "payload_dex": "Secondary payload dex (dynamic loading)",
    }
    for token, label in packer_tokens.items():
        if token in joined:
            signals.append(label)

    # Many dex files or abnormally large primary dex hint at packed payloads.
    if len(dex_sizes) > 3:
        signals.append(f"unusual_dex_count ({len(dex_sizes)})")
    big = [n for n, s in dex_sizes.items() if s > 8_000_000]
    if big:
        signals.append(f"large_dex ({', '.join(big)})")

    return signals


def lookup_malwarebazaar(sha256_hash: str, auth_key: str | None = None, timeout: int = 15) -> dict | None:
    """Optional external reputation enrichment via abuse.ch MalwareBazaar.

    Free Auth-Key required (https://bazaar.abuse.ch/api/). Offline-safe:
    returns None when no key supplied. On-prem commitment: opt-in only.
    """
    if not auth_key:
        return None
    try:
        response = requests.post(
            "https://mb-api.abuse.ch/api/v1/",
            headers={"Auth-Key": auth_key},
            data={"query": "get_info", "hash": sha256_hash},
            timeout=timeout,
        )
        data = response.json()
    except (requests.RequestException, ValueError) as exc:
        return {"source": "malwarebazaar", "error": str(exc)}
    if data.get("query_status") != "ok":
        return {"source": "malwarebazaar", "query_status": data.get("query_status")}
    sample = data.get("data", [{}])[0]
    return {
        "source": "malwarebazaar",
        "malware_family": sample.get("signature", "unknown"),
        "file_type": sample.get("file_type", ""),
        "file_size": sample.get("file_size", 0),
        "first_seen": sample.get("first_seen", ""),
        "tags": sample.get("tags", []),
        "delivery_method": sample.get("delivery_method", ""),
        "yara_rules": [y.get("rule_name") for y in sample.get("yara_rules", [])],
    }


def detect_logo_vision(icon_path: Path | None, api_key: str | None = None, timeout: int = 15) -> dict | None:
    """Optional brand-logo detection via Google Cloud Vision API.

    Sends the extracted app icon; returns detected brand/logos. Used to
    escalate L0 impersonation checks when local pHash whitelist is inconclusive.
    Requires GOOGLE_VISION_KEY env var. Offline-safe: None if no key.
    """
    if not api_key or not icon_path:
        return None
    import base64
    url = f"https://vision.googleapis.com/v1/images:annotate?key={api_key}"
    b64 = base64.b64encode(Path(icon_path).read_bytes()).decode()
    payload = {
        "requests": [{
            "image": {"content": b64},
            "features": [{"type": "LOGO_DETECTION", "maxResults": 5}],
        }]
    }
    try:
        resp = requests.post(url, json=payload, timeout=timeout)
        data = resp.json()
    except (requests.RequestException, ValueError) as exc:
        return {"source": "google_vision", "error": str(exc)}
    annotations = data.get("responses", [{}])[0].get("logoAnnotations", [])
    logos = [a.get("description") for a in annotations]
    return {"source": "google_vision", "detected_logos": logos, "score": [a.get("score") for a in annotations]}


def lookup_hash_metadata(sha256_hash: str, api_key: str | None = None, timeout: int = 15) -> dict | None:
    """Optional external reputation enrichment via VirusTotal v3.

    Offline-safe: returns None when no API key supplied. Per the project's
    data-residency commitment this is opt-in only and never blocks L0.
    """
    if not api_key:
        return None
    url = f"https://www.virustotal.com/api/v3/files/{sha256_hash}"
    headers = {"accept": "application/json", "x-apikey": api_key}
    try:
        response = requests.get(url, headers=headers, timeout=timeout)
    except requests.RequestException as exc:
        return {"error": str(exc)}
    if response.status_code == 200:
        attributes = response.json().get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        sig = attributes.get("signature_info", {})
        return {
            "source": "virustotal",
            "meaningful_name": attributes.get("meaningful_name", "Unknown"),
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "undetected": stats.get("undetected", 0),
            "harmless": stats.get("harmless", 0),
            "total_scans": sum(stats.values()),
            "signer": sig.get("description"),
        }
    if response.status_code == 404:
        return {"source": "virustotal", "verdict": "not_found"}
    return {"source": "virustotal", "error": f"api_error_{response.status_code}"}


def run_l0(apk_path: str | Path, out_path: str | Path | None = None, vt_api_key: str | None = None, mb_auth_key: str | None = None, force_external: bool = False, vision_key: str | None = None) -> dict:
    apk_path = Path(apk_path)
    apk = APK(str(apk_path))

    hashes = compute_hashes(apk_path)
    manifest = harvest_manifest(apk, apk_path)
    artifacts_dir = L0_DIR / "artifacts" / hashes["sha256"]
    icon = extract_icon_phash(apk, artifacts_dir)
    cert_info = extract_cert_info(apk)
    whitelist = load_whitelist()
    cache = load_threat_cache()
    local_hit = None if force_external else lookup_local_cache(hashes["sha256"], cache)
    vt_hit = lookup_hash_metadata(hashes["sha256"], vt_api_key) if not local_hit else None
    mb_hit = lookup_malwarebazaar(hashes["sha256"], mb_auth_key) if not local_hit and vt_hit is None else None
    icon_file = L0_DIR / icon["saved_path"] if icon.get("saved_path") else None
    detected_logos = detect_logo_vision(icon_file, vision_key)
    vision_logos = detected_logos.get("detected_logos") if detected_logos else None
    impersonation = impersonation_check(manifest, icon, whitelist, detected_logos=vision_logos, cert_info=cert_info)
    routing = track_routing(apk_path)

    l0 = {
        "status": "complete",
        "fingerprint": hashes,
        "manifest": manifest,
        "icon": icon,
        "certificate": cert_info,
        "impersonation": impersonation,
        "vision_logo_check": detected_logos,
        "routing": routing,
        "reputation": {
            "local_cache_hit": local_hit is not None,
            "local": local_hit,
            "external_vt": vt_hit,
            "external_malwarebazaar": mb_hit,
            "note": "Local cache checked first (on-prem). External enrichment (VT or MalwareBazaar) only if no cache hit and respective key is set.",
        },
    }

    evidence = Evidence(
        generated_at=datetime.now(timezone.utc).isoformat(),
        source_apk=str(apk_path),
        l0=l0,
    )
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    out = Path(out_path) if out_path else (artifacts_dir / "evidence.json")
    with out.open("w") as fh:
        json.dump(asdict(evidence), fh, indent=2)

    # Fold L0 into the shared spine. This file is L0's own record and is
    # rewritten wholesale on every run — which is exactly why the spine lives
    # elsewhere and is merged into rather than overwritten.
    spine.update_layer(
        hashes["sha256"],
        "l0",
        status=spine.LayerStatus.COMPLETE,
        findings=promote.impersonation_findings(l0),
        summary=promote.l0_summary(l0),
        coverage=promote.l0_coverage(l0),
        gaps=promote.l0_gaps(l0),
        identity=promote.identity(l0, str(apk_path)),
        artifact=out,
    )

    return l0


def main(argv: list[str]) -> int:
    load_env()
    if len(argv) < 2:
        print(f"usage: {Path(argv[0]).name} <path-to-apk> [output-json] [--force-external]", file=sys.stderr)
        return 2
    force = "--force-external" in argv
    positional = [a for a in argv[1:] if not a.startswith("--")]
    l0 = run_l0(
        positional[0],
        positional[1] if len(positional) > 1 else None,
        os.environ.get("VT_API_KEY"),
        os.environ.get("MB_AUTH_KEY"),
        force_external=force,
        vision_key=os.environ.get("GOOGLE_VISION_KEY"),
    )
    print(json.dumps(l0, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
