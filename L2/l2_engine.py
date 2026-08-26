"""L2 Dynamic Analysis Engine.

Parses raw sandbox output (dynamic.json, frida_hooks.jsonl,
network_evidence.json) from a completed detonation run, normalises
findings into the shared L1Finding schema with observation=OBSERVED,
and writes a standardised analysis.json alongside the L0/L1 artifacts.

This module is invoked *after* the sandbox orchestrator has finished.
It bridges the gap between raw sandbox telemetry and the unified
evidence spine that the scoring layers (L3+) consume.

Graceful degradation: when the emulator is unavailable (T14) or no
sandbox artifacts exist for a sample, ``process()`` writes a valid
analysis.json with zero findings and updates the spine with status
``skipped``, so every downstream layer sees an honest record rather
than a crash.

Usage:
    python l2_engine.py <sha256> [--sandbox-dir DIR] [--out DIR]
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Resolve imports — L1 schema lives one level up
# ---------------------------------------------------------------------------
_REPO = Path(__file__).resolve().parent.parent
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

from L1.schema import (  # noqa: E402
    L1Finding,
    L1Report,
    Category,
    Severity,
    ObservationSource,
    CATEGORY_MITRE_MAP,
)

log = logging.getLogger(__name__)

L2_DIR = Path(__file__).resolve().parent
ARTIFACTS = L2_DIR / "artifacts"
SANDBOX_ARTIFACTS = L2_DIR / "sandbox" / "artifacts"

# ---------------------------------------------------------------------------
# Category string → enum mapping (tolerant of sandbox JSON values)
# ---------------------------------------------------------------------------
_CAT_MAP: dict[str, Category] = {c.value: c for c in Category}
_CAT_MAP.update({
    "sms_exfiltration": Category.SMS_INTERCEPT,
    "send_sms":         Category.SMS_INTERCEPT,
    "overlay":          Category.OVERLAY,
    "overlay_attack":   Category.OVERLAY,
    "add_overlay":      Category.OVERLAY,
    "load_dex":         Category.NATIVE_PAYLOAD,
    "native_payload":   Category.NATIVE_PAYLOAD,
    "clipboard_hijack": Category.CLIPBOARD_HIJACK,
    "set_clipboard":    Category.CLIPBOARD_HIJACK,
    "c2_communication": Category.C2_COMMS,
    "c2_beacon":        Category.C2_COMMS,
    "credential_exfiltration": Category.DATA_EXFIL,
    "auth_fill":           Category.PHISHING_IMPERSONATION,
    "auth_bypass":         Category.EVASION,
    "auth_state":          Category.EVASION,
    "ssl_unpin":           Category.EVASION,
    "accessibility_abuse": Category.ACCESSIBILITY_ABUSE,
    "bulk_exfil":          Category.DATA_EXFIL,
    "biometric_prompt_bypass":     Category.EVASION,
    "fingerprint_manager_bypass":  Category.EVASION,
    "keyguard_spoof":              Category.EVASION,
    "biometric_prompt_framework_bypass": Category.EVASION,
})

_SEV_MAP: dict[str, Severity] = {s.value: s for s in Severity}


def _resolve_category(raw: str) -> Category:
    return _CAT_MAP.get(raw.lower(), Category.OTHER)


def _resolve_severity(raw: str) -> Severity:
    return _SEV_MAP.get(raw.lower(), Severity.MEDIUM)


# ---------------------------------------------------------------------------
# Parsers for each raw artifact type
# ---------------------------------------------------------------------------

def _parse_dynamic_json(path: Path) -> list[L1Finding]:
    """Parse the main dynamic.json summary produced by a sandbox run."""
    if not path.exists():
        return []
    data = json.loads(path.read_text())
    findings: list[L1Finding] = []

    # Explicit findings array (already structured)
    for raw in data.get("findings", []):
        cat = _resolve_category(raw.get("category", "other"))
        sev = _resolve_severity(raw.get("severity", "medium"))
        mitre = raw.get("mitre", "")
        techniques = [mitre] if mitre else CATEGORY_MITRE_MAP.get(cat, [])

        findings.append(L1Finding(
            engine="l2_sandbox",
            category=cat,
            severity=sev,
            evidence=raw.get("evidence", ""),
            location="runtime",
            mitre_techniques=techniques,
            observation=ObservationSource.OBSERVED,
            detail=raw,
        ))

    # Synthesise findings from behavioral summary flags
    behaviors = data.get("runtime_behaviors", {})
    network = data.get("network", {})

    if behaviors.get("sms_intercepted"):
        findings.append(L1Finding(
            engine="l2_sandbox",
            category=Category.SMS_INTERCEPT,
            severity=Severity.CRITICAL,
            evidence="SMS interception observed during detonation",
            location="runtime",
            mitre_techniques=CATEGORY_MITRE_MAP[Category.SMS_INTERCEPT],
            observation=ObservationSource.OBSERVED,
        ))

    if behaviors.get("overlay_displayed"):
        findings.append(L1Finding(
            engine="l2_sandbox",
            category=Category.OVERLAY,
            severity=Severity.CRITICAL,
            evidence="Overlay attack UI observed during detonation",
            location="runtime",
            mitre_techniques=CATEGORY_MITRE_MAP[Category.OVERLAY],
            observation=ObservationSource.OBSERVED,
        ))

    if behaviors.get("files_dropped", 0) > 0:
        findings.append(L1Finding(
            engine="l2_sandbox",
            category=Category.NATIVE_PAYLOAD,
            severity=Severity.HIGH,
            evidence=f"{behaviors['files_dropped']} file(s) dropped during detonation",
            location="runtime",
            mitre_techniques=CATEGORY_MITRE_MAP[Category.NATIVE_PAYLOAD],
            observation=ObservationSource.OBSERVED,
        ))

    if behaviors.get("clipboard_hijacked"):
        findings.append(L1Finding(
            engine="l2_sandbox",
            category=Category.CLIPBOARD_HIJACK,
            severity=Severity.MEDIUM,
            evidence="Clipboard content modified during detonation",
            location="runtime",
            mitre_techniques=CATEGORY_MITRE_MAP[Category.CLIPBOARD_HIJACK],
            observation=ObservationSource.OBSERVED,
        ))

    if network.get("exfiltration_detected"):
        targets = ", ".join(network.get("data_exfiltrated", []))
        findings.append(L1Finding(
            engine="l2_sandbox",
            category=Category.DATA_EXFIL,
            severity=Severity.CRITICAL,
            evidence=f"Data exfiltration detected — targets: {targets}",
            location="runtime/network",
            mitre_techniques=CATEGORY_MITRE_MAP[Category.DATA_EXFIL],
            observation=ObservationSource.OBSERVED,
        ))

    for endpoint in network.get("c2_endpoints", []):
        findings.append(L1Finding(
            engine="l2_sandbox",
            category=Category.C2_COMMS,
            severity=Severity.HIGH,
            evidence=f"C2 beacon detected: {endpoint}",
            location="runtime/network",
            mitre_techniques=CATEGORY_MITRE_MAP[Category.C2_COMMS],
            observation=ObservationSource.OBSERVED,
        ))

    return findings


def _parse_frida_hooks(path: Path) -> list[L1Finding]:
    """Parse frida_hooks.jsonl (one JSON object per line)."""
    if not path.exists():
        return []
    findings: list[L1Finding] = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            raw = json.loads(line)
        except json.JSONDecodeError:
            continue

        # Frida CLI wraps send() payloads as {"type": "send", "payload": {...}}
        if raw.get("type") == "send":
            payload = raw.get("payload")
            if not isinstance(payload, dict):
                continue
            raw = payload

        if raw.get("type") == "auth_state":
            cat = _resolve_category("auth_state")
            evidence = raw.get(
                "evidence",
                f"Runtime auth state forced: {raw.get('key', 'unknown')} "
                f"{raw.get('original')!r} -> {raw.get('forced')!r} via {raw.get('method', 'unknown')}",
            )
            findings.append(L1Finding(
                engine="frida",
                category=cat,
                severity=Severity.HIGH,
                evidence=evidence,
                location="runtime/frida",
                mitre_techniques=CATEGORY_MITRE_MAP.get(cat, []),
                observation=ObservationSource.OBSERVED,
                detail=raw,
            ))
            continue

        # Only process structured finding payloads from dynamic_hooks.js
        if raw.get("type") != "finding":
            continue
        cat = _resolve_category(raw.get("category", raw.get("action", "other")))
        sev = _resolve_severity(raw.get("severity", "medium"))
        mitre = raw.get("mitre", "")
        techniques = [mitre] if mitre else CATEGORY_MITRE_MAP.get(cat, [])

        findings.append(L1Finding(
            engine="frida",
            category=cat,
            severity=sev,
            evidence=raw.get("evidence", f"Frida hook fired: {raw.get('action', 'unknown')}"),
            location="runtime/frida",
            mitre_techniques=techniques,
            observation=ObservationSource.OBSERVED,
            detail=raw,
        ))
    return findings


def _parse_network_evidence(path: Path) -> list[L1Finding]:
    """Parse network_evidence.json from mitmproxy addon."""
    if not path.exists():
        return []
    data = json.loads(path.read_text())
    if not isinstance(data, list):
        return []
    findings: list[L1Finding] = []
    for entry in data:
        # Only promote entries flagged by the addon
        if "alert" not in entry and "hijacked" not in entry:
            continue
        if entry.get("alert") == "CREDENTIAL_EXFILTRATION":
            findings.append(L1Finding(
                engine="mitmproxy",
                category=Category.DATA_EXFIL,
                severity=Severity.CRITICAL,
                evidence=f"Credential exfiltration to {entry.get('host', 'unknown')} — {entry.get('url', '')}",
                location="runtime/network",
                mitre_techniques=CATEGORY_MITRE_MAP[Category.DATA_EXFIL],
                observation=ObservationSource.OBSERVED,
                detail={"url": entry.get("url"), "method": entry.get("method")},
            ))
        if entry.get("hijacked"):
            findings.append(L1Finding(
                engine="mitmproxy",
                category=Category.C2_COMMS,
                severity=Severity.HIGH,
                evidence=f"C2 response hijacked ({entry['hijacked']}): {entry.get('url', '')}",
                location="runtime/network",
                mitre_techniques=CATEGORY_MITRE_MAP[Category.C2_COMMS],
                observation=ObservationSource.OBSERVED,
                detail={"url": entry.get("url"), "hijack_type": entry["hijacked"]},
            ))
    return findings


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------

def _dedup(findings: list[L1Finding]) -> list[L1Finding]:
    """Remove duplicate findings (same engine+category+evidence)."""
    seen: set[tuple[str, str, str]] = set()
    out: list[L1Finding] = []
    for f in findings:
        key = (f.engine, f.category.value, f.evidence)
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def process(sha256: str,
            sandbox_dir: Path | None = None,
            out_root: Path | None = None) -> L1Report:
    """Process all raw sandbox artifacts for a given SHA256 and emit an L1Report.

    The sandbox stores artifacts keyed by *package name*, but L2 engine
    outputs are keyed by *sha256* (matching L0/L1 convention).

    Resolution order for raw sandbox data:
        1. explicit ``sandbox_dir``
        2. ``L2/artifacts/<sha256>/``       (already sha256-keyed)
        3. ``L2/sandbox/artifacts/<dir>/``  (package-keyed, searched via
           ``frida_hooks.jsonl`` presence)

    **Graceful degradation:** when none of the candidate directories contain
    any sandbox output, the function still writes a valid ``analysis.json``
    with zero findings and updates the spine with ``status=skipped``.  This
    means a pipeline run where the emulator never booted (T14) produces an
    honest record ("L2 never ran") rather than a crash or a silent gap.
    """

    candidates: list[Path] = []
    if sandbox_dir:
        candidates.append(Path(sandbox_dir))

    sha_dir = ARTIFACTS / sha256
    candidates.append(sha_dir)

    # Also try any package-keyed dirs under sandbox/artifacts — but ONLY the
    # one(s) whose dynamic.json records *this* sha256. The sandbox keys its dirs
    # by package name, so the sha is only recoverable from the dir's own
    # dynamic.json; globbing every dir unconditionally aggregated one sample's
    # report from another sample's leftover artifacts (the documented
    # cross-contamination bug — e.g. a later detonation's network_evidence.json
    # leaking into an unrelated sha's findings). A dir with no dynamic.json or a
    # mismatched sha is skipped; the explicit ``sandbox_dir`` above is always
    # honoured regardless, so a caller passing one by hand is unaffected.
    if SANDBOX_ARTIFACTS.exists():
        try:
            for d in sorted(SANDBOX_ARTIFACTS.iterdir()):
                if not (d.is_dir() and (d / "frida_hooks.jsonl").exists()):
                    continue
                dj = d / "dynamic.json"
                dir_sha = ""
                if dj.exists():
                    try:
                        dir_sha = str(json.loads(dj.read_text()).get("sha256", ""))
                    except (json.JSONDecodeError, OSError):
                        dir_sha = ""
                if dir_sha == sha256:
                    candidates.append(d)
        except OSError as exc:
            log.warning("failed to scan %s: %s", SANDBOX_ARTIFACTS, exc)

    # Aggregate findings from all candidate directories
    all_findings: list[L1Finding] = []
    sandbox_meta: dict[str, object] = {}

    for cand in candidates:
        dj = cand / "dynamic.json"
        if dj.exists() and not sandbox_meta:
            try:
                sandbox_meta = json.loads(dj.read_text())
            except (json.JSONDecodeError, OSError) as exc:
                log.warning("failed to parse %s: %s", dj, exc)
        all_findings.extend(_parse_dynamic_json(dj))
        all_findings.extend(_parse_frida_hooks(cand / "frida_hooks.jsonl"))
        all_findings.extend(_parse_network_evidence(cand / "network_evidence.json"))

    all_findings = _dedup(all_findings)

    # Build severity counts
    sev_counts: dict[str, int] = {s.value: 0 for s in Severity}
    for f in all_findings:
        sev_counts[f.severity.value] += 1
    cats: list[str] = sorted({f.category.value for f in all_findings})

    # Build L2 summary metadata
    sandbox_info: dict[str, object] = sandbox_meta.get("sandbox", {})  # type: ignore[assignment]
    network_info: dict[str, object] = sandbox_meta.get("network", {})  # type: ignore[assignment]
    confidence: dict[str, object] = sandbox_meta.get("confidence", {})  # type: ignore[assignment]

    summary: dict[str, object] = {
        "finding_count":       len(all_findings),
        "severity_counts":     sev_counts,
        "categories":          cats,
        "sandbox_type":        sandbox_info.get("type", "unknown"),
        "detonation_s":        sandbox_info.get("detonation_duration_s", 0),
        "evasion_bypassed":    sandbox_info.get("evasion_checks_bypassed", 0),
        "total_http_requests": network_info.get("total_requests", 0),
        "c2_count":            len(network_info.get("c2_endpoints", [])),  # type: ignore[arg-type]
        "confidence":          confidence.get("confidence_level", "unknown"),
    }

    report = L1Report(
        sha256=sha256,
        source_apk="",  # Not always known at L2 — L0 evidence has the path
        engine="l2_sandbox",
        track="dynamic",
        generated_at=datetime.now(timezone.utc).isoformat(),
        findings=all_findings,
        artifacts={
            "dynamic_json": str(sha_dir / "dynamic.json")
            if (sha_dir / "dynamic.json").exists() else "",
        },
        summary=summary,
    )

    out = (out_root or ARTIFACTS) / sha256 / "analysis.json"
    report.write(out)

    _update_spine(sha256, report, out)

    return report


def _update_spine(sha256: str, report: L1Report, artifact: Path) -> None:
    """Fold L2 results into the evidence spine.

    Follows the same pattern as L0/L1: ``spine.update_layer`` is the single
    writer.  Separated from ``process()`` so spine failures do not prevent
    the analysis.json artifact from being written.
    """
    import spine  # local import — spine depends on nothing in L2
    from L2 import promote

    doc = report.to_dict()
    status_str = promote.l2_status_for(doc)

    try:
        spine.update_layer(
            sha256, "l2",
            status=spine.LayerStatus(status_str),
            findings=promote.l2_findings(doc),
            summary=promote.l2_summary(doc),
            coverage=promote.l2_coverage(doc),
            gaps=promote.l2_gaps(doc),
            artifact=artifact,
        )
    except Exception:
        log.exception("spine update failed for %s", sha256)

    log.info("[L2] wrote %s  findings=%d  spine status=%s",
             artifact, len(report.findings), status_str)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: list[str]) -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
    )

    p = argparse.ArgumentParser(
        description="L2 Dynamic Analysis Engine -- parse sandbox output into schema"
    )
    p.add_argument("sha256", help="SHA256 of the APK (artifact directory key)")
    p.add_argument("--sandbox-dir", default=None,
                   help="Explicit path to raw sandbox artifacts (overrides auto-discovery)")
    p.add_argument("--out", default=None, help="L2 artifacts output root")
    args = p.parse_args(argv[1:])
    try:
        report = process(
            args.sha256,
            Path(args.sandbox_dir) if args.sandbox_dir else None,
            Path(args.out) if args.out else None,
        )
        n = len(report.findings)
        if n == 0:
            print("[L2] no sandbox artifacts found -- wrote skipped record "
                  "(emulator unavailable or detonation not attempted)")
        else:
            print(f"[L2] {n} finding(s) parsed and written")
    except Exception as exc:
        log.error("L2 engine failed: %s", exc, exc_info=True)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
