"""L2 Dynamic Analysis Engine.

Parses raw sandbox output (dynamic.json, frida_hooks.jsonl,
network_evidence.json) from a completed detonation run, normalises
findings into the shared L1Finding schema with observation=OBSERVED,
and writes a standardised analysis.json alongside the L0/L1 artifacts.

This module is invoked *after* the sandbox orchestrator has finished.
It bridges the gap between raw sandbox telemetry and the unified
evidence spine that the scoring layers (L3+) consume.

Usage:
    python l2_engine.py <sha256> [--sandbox-dir DIR] [--out DIR]
"""

from __future__ import annotations

import argparse
import json
import sys
import logging
from datetime import datetime, timezone
from pathlib import Path

_log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Resolve imports — L1 schema lives one level up
# ---------------------------------------------------------------------------
_REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO / "L1"))

from schema import (  # noqa: E402
    L1Finding,
    L1Report,
    Category,
    Severity,
    ObservationSource,
    CATEGORY_MITRE_MAP,
)

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
        1. L2/artifacts/<sha256>/           (already sha256-keyed)
        2. L2/sandbox/artifacts/<dir>/      (package-keyed, searched via dynamic.json presence)
        3. explicit `sandbox_dir`
    """

    candidates: list[Path] = []
    if sandbox_dir:
        candidates.append(Path(sandbox_dir))
    candidates.append(ARTIFACTS / sha256)

    # Also try any package-keyed dirs under sandbox/artifacts
    if SANDBOX_ARTIFACTS.exists():
        for d in SANDBOX_ARTIFACTS.iterdir():
            if d.is_dir() and (d / "frida_hooks.jsonl").exists():
                candidates.append(d)

    # Also check the sha256 dir itself (dynamic.json lives there)
    sha_dir = ARTIFACTS / sha256
    if sha_dir.exists():
        candidates.insert(0, sha_dir)

    # Aggregate findings from all candidate directories
    all_findings: list[L1Finding] = []
    sandbox_meta: dict = {}

    for cand in candidates:
        dj = cand / "dynamic.json"
        if dj.exists() and not sandbox_meta:
            sandbox_meta = json.loads(dj.read_text())
        all_findings.extend(_parse_dynamic_json(dj))
        all_findings.extend(_parse_frida_hooks(cand / "frida_hooks.jsonl"))
        all_findings.extend(_parse_network_evidence(cand / "network_evidence.json"))

    all_findings = _dedup(all_findings)

    # Build severity counts
    sev_counts = {s.value: 0 for s in Severity}
    for f in all_findings:
        sev_counts[f.severity.value] += 1
    cats = sorted({f.category.value for f in all_findings})

    # Build L2 summary metadata
    sandbox_info = sandbox_meta.get("sandbox", {})
    network_info = sandbox_meta.get("network", {})
    confidence = sandbox_meta.get("confidence", {})

    summary = {
        "finding_count":       len(all_findings),
        "severity_counts":     sev_counts,
        "categories":          cats,
        "sandbox_type":        sandbox_info.get("type", "unknown"),
        "detonation_s":        sandbox_info.get("detonation_duration_s", 0),
        "evasion_bypassed":    sandbox_info.get("evasion_checks_bypassed", 0),
        "total_http_requests": network_info.get("total_requests", 0),
        "c2_count":            len(network_info.get("c2_endpoints", [])),
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
            "dynamic_json": str(sha_dir / "dynamic.json") if (sha_dir / "dynamic.json").exists() else "",
        },
        summary=summary,
    )

    out = (out_root or ARTIFACTS) / sha256 / "analysis.json"
    report.write(out)
    _log.info("wrote %s  findings=%d", out, len(all_findings))
    return report


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(
        description="L2 Dynamic Analysis Engine — parse sandbox output into schema"
    )
    p.add_argument("sha256", help="SHA256 of the APK (artifact directory key)")
    p.add_argument("--sandbox-dir", default=None,
                   help="Explicit path to raw sandbox artifacts (overrides auto-discovery)")
    p.add_argument("--out", default=None, help="L2 artifacts output root")
    args = p.parse_args(argv[1:])
    try:
        process(args.sha256,
                Path(args.sandbox_dir) if args.sandbox_dir else None,
                Path(args.out) if args.out else None)
    except Exception as exc:
        _log.error("error: %s", exc)
        import traceback; traceback.print_exc()
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
