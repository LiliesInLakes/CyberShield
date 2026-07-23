from __future__ import annotations

import logging
import io
import os

import hashlib
import json
import os
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

from cryptography.hazmat.primitives.serialization import Encoding

L0_DIR = Path(__file__).resolve().parent
WHITELIST_PATH = L0_DIR / "bank_whitelist.json"
CACHE_PATH = L0_DIR / "threat_cache.json"
EVIDENCE_PATH = L0_DIR / "evidence.json"

_log = logging.getLogger(__name__)


def load_env(path: Path | None = None) -> None:
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
    l1: dict[str, Any] = field(default_factory=lambda: {"status": "pending"})
    l2: dict[str, Any] = field(default_factory=lambda: {"status": "pending"})
    l3: dict[str, Any] = field(default_factory=lambda: {"status": "pending"})
    l4: dict[str, Any] = field(default_factory=lambda: {"status": "pending"})
    l5: dict[str, Any] = field(default_factory=lambda: {"status": "pending"})
    l6: dict[str, Any] = field(default_factory=lambda: {"status": "pending"})


def validate_apk(apk_path: Path) -> None:
    if not apk_path.exists():
        raise FileNotFoundError(f"APK not found: {apk_path}")
    if not apk_path.is_file():
        raise ValueError(f"Not a file: {apk_path}")
    if apk_path.stat().st_size < 1000:
        raise ValueError(f"APK too small to be valid: {apk_path.stat().st_size} bytes")
    if not zipfile.is_zipfile(apk_path):
        raise ValueError(f"Not a valid ZIP/APK file: {apk_path}")
    with zipfile.ZipFile(apk_path) as zf:
        names = zf.namelist()
        if "AndroidManifest.xml" not in names:
            raise ValueError("APK missing AndroidManifest.xml")


def compute_hashes(apk_path: Path) -> dict[str, str]:
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    with apk_path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            md5.update(chunk)
            sha256.update(chunk)
    return {"md5": md5.hexdigest(), "sha256": sha256.hexdigest()}


def harvest_manifest(apk: APK) -> dict[str, Any]:
    permissions = list(apk.get_permissions())
    high_risk = sorted(set(permissions) & HIGH_RISK_PERMISSIONS)
    return {
        "package_name": apk.get_package(),
        "app_label": apk.get_app_name(),
        "version_name": apk.get_androidversion_name(),
        "version_code": apk.get_androidversion_code(),
        "min_sdk": apk.get_min_sdk_version(),
        "target_sdk": apk.get_target_sdk_version(),
        "permissions": sorted(permissions),
        "permission_count": len(permissions),
        "high_risk_permissions": high_risk,
        "high_risk_permission_count": len(high_risk),
    }


def extract_icon_phash(apk: APK, artifacts_dir: Path | None = None) -> dict[str, Any]:
    result = {"present": False, "phash": None, "source": None, "saved_path": None}
    try:
        icon_path = apk.get_app_icon()
        if not icon_path:
            _log.debug("No app icon found")
            return result
        data = apk.get_file(icon_path)
        if not data:
            _log.debug("Icon resource missing: %s", icon_path)
            return result
        img = Image.open(io.BytesIO(data)).convert("RGB")
        result["present"] = True
        result["phash"] = str(imagehash.phash(img))
        result["source"] = icon_path
        if artifacts_dir:
            artifacts_dir.mkdir(parents=True, exist_ok=True)
            safe = "icon.png"
            out = artifacts_dir / safe
            img.save(out, format="PNG")
            result["saved_path"] = str(out.relative_to(L0_DIR))
    except Exception as exc:
        _log.warning("Icon extraction failed: %s", exc)
        result["error"] = str(exc)
    return result


def _cert_to_der(cert: Any) -> bytes | None:
    if hasattr(cert, "dump"):
        try:
            raw = cert.dump()
            if isinstance(raw, bytes):
                return raw
        except Exception:
            pass
    for method in ("public_bytes", "certificate", "der", "contents"):
        attr = getattr(cert, method, None)
        if attr is None:
            continue
        try:
            if method in ("der", "contents"):
                return attr if isinstance(attr, bytes) else None
            if method == "certificate":
                return attr if isinstance(attr, bytes) else None
            raw = attr(Encoding.DER)
            if isinstance(raw, bytes):
                return raw
        except Exception:
            continue
    return None


def _fingerprint_from_der(der: bytes) -> str:
    return hashlib.sha256(der).hexdigest()


def extract_cert_info(apk: APK) -> dict[str, Any]:
    result: dict[str, Any] = {
        "present": False,
        "sha256_fingerprint": None,
        "issuer": None, "subject": None,
        "serial_number": None,
        "not_before": None, "not_after": None,
        "self_signed": None, "debug_signed": None,
    }
    try:
        certs = apk.get_certificates()
        if not certs:
            _log.debug("No certificates found in APK")
            return result
        cert = certs[0]
        der = _cert_to_der(cert)
        if der:
            result["present"] = True
            result["sha256_fingerprint"] = _fingerprint_from_der(der)
        def _name_str(n: Any) -> str:
            try:
                return n.rfc4514_string()
            except Exception:
                pass
            try:
                return str(n.human_friendly) if hasattr(n, "human_friendly") else str(n)
            except Exception:
                return str(n)

        issuer = None
        issuer_str = getattr(cert, "issuer", None)
        if issuer_str is not None:
            issuer = _name_str(issuer_str)
            result["issuer"] = issuer
        subject_str = getattr(cert, "subject", None)
        if subject_str is not None:
            subject = _name_str(subject_str)
            result["subject"] = subject
            if result.get("issuer"):
                result["self_signed"] = (issuer == subject)
            result["debug_signed"] = "android debug" in subject.lower()
        try:
            result["serial_number"] = str(cert.serial_number)
            nb = getattr(cert, "not_valid_before_utc", None) or getattr(cert, "not_valid_before", None)
            na = getattr(cert, "not_valid_after_utc", None) or getattr(cert, "not_valid_after", None)
            if nb: result["not_before"] = str(nb)
            if na: result["not_after"] = str(na)
        except Exception:
            pass
    except Exception as exc:
        _log.warning("Certificate extraction failed (primary API): %s", exc)
        result["error"] = str(exc)
    if not result["sha256_fingerprint"]:
        try:
            certs_v2 = apk.get_certificates_der_v2()
            if certs_v2:
                der = certs_v2[0]
                result["present"] = True
                result["sha256_fingerprint"] = _fingerprint_from_der(der)
        except Exception as fallback_exc:
            _log.warning("Certificate extraction failed: %s", fallback_exc)
    return result


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
    app_lower = (app_label or "").lower()
    best = _label_similarity(bank.get("app_label", "").lower(), app_lower)
    for alt in bank.get("alt_labels", []):
        sim = _label_similarity(alt.lower(), app_lower)
        if sim > best:
            best = sim
    bank_name = bank.get("bank_name", "").lower()
    if bank_name and bank_name in app_lower:
        best = max(best, 0.75)
    return best


def impersonation_check(manifest: dict, icon: dict, whitelist: dict, threshold: int = 8, detected_logos: list[str] | None = None, cert_info: dict[str, Any] | None = None) -> dict[str, Any]:
    findings = []
    matched_bank = None
    closest = None
    min_dist = None

    banks = whitelist.get("banks", [])
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

    cert_signal: dict[str, Any] = {
        "cert_in_whitelist": False,
        "cert_weight": 0.0,
        "cert_detail": None,
    }
    if cert_info and cert_info.get("present"):
        fp = cert_info.get("sha256_fingerprint")

        for bank in banks:
            ref_cert = bank.get("cert_sha256")
            if ref_cert and fp and ref_cert.lower() == fp.lower():
                cert_signal["cert_in_whitelist"] = True
                cert_signal["cert_weight"] = 0.9
                cert_signal["cert_detail"] = f"Certificate matches verified {bank.get('bank_name')} cert"
                matched_bank = bank.get("bank_name")
                break

        if not cert_signal["cert_in_whitelist"] and cert_info.get("self_signed"):
            looks_like_bank = any(
                _best_label_sim(manifest.get("app_label"), b) >= 0.6
                for b in banks
            )
            if looks_like_bank:
                cert_signal["cert_weight"] = -0.9
                cert_signal["cert_detail"] = "Self-signed cert on bank-branded app"
                findings.append({
                    "type": "self_signed_bank_impersonation",
                    "severity": "critical",
                    "detail": "Self-signed certificate on an app mimicking a bank. "
                              "No legitimate Indian bank ships self-signed.",
                })
            else:
                cert_signal["cert_weight"] = -0.4
                cert_signal["cert_detail"] = "Self-signed certificate (not bank-branded)"

        if not cert_signal["cert_in_whitelist"] and cert_info.get("debug_signed"):
            cert_signal["cert_weight"] = -0.5
            cert_signal["cert_detail"] = "Debug-signed certificate"
            findings.append({
                "type": "debug_signed",
                "severity": "high",
                "detail": "APK signed with Android debug key.",
            })

    verdict = "trusted" if matched_bank else ("suspicious" if findings else "unknown")
    return {
        "verdict": verdict,
        "matched_bank": matched_bank,
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

    if len(dex_sizes) > 3:
        signals.append(f"unusual_dex_count ({len(dex_sizes)})")
    big = [n for n, s in dex_sizes.items() if s > 8_000_000]
    if big:
        signals.append(f"large_dex ({', '.join(big)})")

    return signals


def lookup_malwarebazaar(sha256_hash: str, auth_key: str | None = None, timeout: int = 15) -> dict | None:
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
        _log.warning("MalwareBazaar lookup failed: %s", exc)
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
        _log.warning("Google Vision API call failed: %s", exc)
        return {"source": "google_vision", "error": str(exc)}
    annotations = data.get("responses", [{}])[0].get("logoAnnotations", [])
    logos = [a.get("description") for a in annotations]
    return {"source": "google_vision", "detected_logos": logos, "score": [a.get("score") for a in annotations]}


def lookup_hash_metadata(sha256_hash: str, api_key: str | None = None, timeout: int = 15) -> dict | None:
    if not api_key:
        return None
    url = f"https://www.virustotal.com/api/v3/files/{sha256_hash}"
    headers = {"accept": "application/json", "x-apikey": api_key}
    try:
        response = requests.get(url, headers=headers, timeout=timeout)
    except requests.RequestException as exc:
        _log.warning("VirusTotal lookup failed: %s", exc)
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
    validate_apk(apk_path)
    apk = APK(str(apk_path))

    hashes = compute_hashes(apk_path)
    manifest = harvest_manifest(apk)
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
