"""Debug utility: Pretty-print the complete pipeline evidence for an APK.

This is a DIAGNOSTIC tool — it reads the artifacts produced by L0, L1,
and L2 and prints a human-readable summary to stdout. It does NOT
participate in the pipeline flow; it simply inspects what the pipeline
has already produced.

Usage:
    python -m tools.debug.summarize_results <path_to_apk>
    python tools/debug/summarize_results.py <path_to_apk>
"""

import json
import sys
import hashlib
from pathlib import Path

# Resolve repo root (two levels up from tools/debug/)
_REPO = Path(__file__).resolve().parent.parent.parent


def _sha256_of(apk_path: Path) -> str:
    h = hashlib.sha256()
    with apk_path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _load_json(path: Path) -> dict:
    if path.exists():
        return json.loads(path.read_text())
    return {}


def _print_header(title: str, width: int = 60):
    print(f"\n{'=' * width}")
    print(f"  {title}")
    print(f"{'=' * width}")


def _print_section(title: str):
    print(f"\n[+] {title}")


def print_summary(sha256: str, apk_name: str = ""):
    """Print a complete pipeline summary for an APK by its SHA256."""

    # ------- L0 -------
    l0_evidence = _load_json(_REPO / "L0" / "artifacts" / sha256 / "evidence.json")

    _print_header(f"📊 REPORT FOR: {apk_name or l0_evidence.get('source_apk', sha256[:16])}")

    if l0_evidence:
        l0 = l0_evidence.get("l0", {})
        fp = l0.get("fingerprint", {})
        manifest = l0.get("manifest", {})

        _print_section("IDENTIFICATION")
        print(f"    SHA-256 : {fp.get('sha256', sha256)}")
        print(f"    Package : {manifest.get('package_name', 'N/A')}")
        print(f"    Label   : {manifest.get('app_label', 'N/A')}")

        imp = l0.get("impersonation", {})
        _print_section(f"L0 TRIAGE VERDICT: {imp.get('verdict', 'unknown').upper()}")

        if imp.get("matched_bank"):
            print(f"    Matched Bank: {imp['matched_bank']}")
        cert = imp.get("cert_signal", {})
        if cert.get("cert_detail"):
            print(f"    Cert Signal : {cert['cert_detail']} (Weight: {cert.get('cert_weight')})")
        for f in imp.get("findings", []):
            print(f"      - [{f['severity'].upper()}] {f['type']}: {f['detail']}")

        rep = l0.get("reputation", {})
        if rep.get("local_cache_hit"):
            print("    Reputation  : MATCH in local threat cache")
    else:
        _print_section("L0 TRIAGE: NO DATA")

    # ------- L1 -------
    l1 = _load_json(_REPO / "L1" / "artifacts" / sha256 / "analysis.json")
    has_l1 = bool(l1.get("findings"))

    _print_section(f"L1 STATIC ANALYSIS: {'COMPLETE' if has_l1 else 'NOT RUN / NO FINDINGS'}")

    if has_l1:
        stats = l1.get("summary", {})
        print(f"    Engine      : {l1.get('engine', 'unknown')}")
        print(f"    Findings    : {stats.get('finding_count', 0)}")

        for f in l1.get("findings", [])[:10]:
            engine = f.get("engine", "?")
            cat = f.get("category", "?")
            sev = f.get("severity", "?").upper()
            ev = f.get("evidence", "")[:80]
            print(f"      - [{sev}] [{engine}] {cat}")
            print(f"        {ev}...")

    # ------- L2 -------
    l2 = _load_json(_REPO / "L2" / "artifacts" / sha256 / "analysis.json")
    l2_dyn = _load_json(_REPO / "L2" / "artifacts" / sha256 / "dynamic.json")
    has_l2 = bool(l2.get("findings")) or bool(l2_dyn)

    _print_section(f"L2 DYNAMIC ANALYSIS: {'COMPLETE' if has_l2 else 'NOT RUN'}")

    if l2_dyn:
        sandbox = l2_dyn.get("sandbox", {})
        network = l2_dyn.get("network", {})
        behaviors = l2_dyn.get("runtime_behaviors", {})

        print(f"    Sandbox Type : {sandbox.get('type', 'unknown')}")
        print(f"    Detonation   : {sandbox.get('detonation_duration_s', 0)}s")
        print(f"    Evasions     : {sandbox.get('evasion_checks_bypassed', 0)} bypassed")

        print("\n    Network Activity:")
        print(f"      HTTP/S Requests : {network.get('total_requests', 0)}")
        if network.get("c2_endpoints"):
            print(f"      C2 Beacons      : {len(network['c2_endpoints'])}")
            for c2 in network["c2_endpoints"][:3]:
                print(f"        - {c2}")

        print("\n    Smoking Guns:")
        guns = [
            ("SMS Interception", behaviors.get("sms_intercepted", False)),
            ("Overlay Attack",   behaviors.get("overlay_displayed", False)),
            ("Payload Dropper",  behaviors.get("files_dropped", 0) > 0),
            ("Clipboard Hijack", behaviors.get("clipboard_hijacked", False)),
            ("Data Exfiltration", network.get("exfiltration_detected", False)),
        ]
        for name, detected in guns:
            status = "🚨 DETECTED" if detected else "✅ Clear"
            print(f"      - {name.ljust(20)} : {status}")

    if l2.get("findings"):
        print("\n    L2 Findings (OBSERVED):")
        for f in l2["findings"][:10]:
            cat = f.get("category", "?")
            sev = f.get("severity", "?").upper()
            ev = f.get("evidence", "")[:80]
            obs = f.get("observation", "observed").upper()
            print(f"      - [{sev}] [{obs}] {cat}")
            print(f"        {ev}...")

    # ------- Spine -------
    # The merged record. Unlike the per-layer sections above, every finding
    # here carries the evidence ID that a score or a report cites.
    spine_doc = _load_json(_REPO / "artifacts" / sha256 / "evidence.json")

    if spine_doc:
        counts = spine_doc.get("counts", {})
        _print_header("🧬 EVIDENCE SPINE")
        statuses = " ".join(
            f"{name}={block.get('status', '?')}"
            for name, block in spine_doc.get("layers", {}).items()
        )
        print(f"    Layers      : {statuses}")
        print(f"    Findings    : {counts.get('findings', 0)}"
              f"  (malware-category: {counts.get('malware_category', 0)},"
              f" cert-anomaly: {counts.get('certificate_anomaly', 0)})")
        gaps = spine_doc.get("analysis_gaps", [])
        print(f"    Coverage gaps: {', '.join(gaps) if gaps else 'none'}")

        for f in spine_doc.get("findings", []):
            print(f"      {f['id']} [{f['severity'].upper():8s}] "
                  f"{f['category']:24s} {f['engine']}")
            print(f"           {f.get('evidence', '')[:90]}")
            if f.get("mitre_techniques"):
                print(f"           MITRE: {', '.join(f['mitre_techniques'])}")
    else:
        _print_header("🧬 EVIDENCE SPINE: NOT BUILT")
        print("    Run L0 (and L1) to populate artifacts/<sha256>/evidence.json")

    # ------- Aggregate -------
    total_l1 = len(l1.get("findings", []))
    total_l2 = len(l2.get("findings", []))

    _print_header("📈 AGGREGATE")
    print(f"    L1 findings : {total_l1}")
    print(f"    L2 findings : {total_l2}")
    print(f"    Total       : {total_l1 + total_l2}")
    if total_l2 > 0:
        observed = sum(1 for f in l2.get("findings", [])
                       if f.get("observation") == "observed")
        print(f"    Observed    : {observed} (runtime-confirmed)")
    print(f"{'=' * 60}\n")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python tools/debug/summarize_results.py <path_to_apk>")
        sys.exit(1)

    apk = Path(sys.argv[1])
    if not apk.exists():
        print(f"[-] APK not found: {apk}")
        sys.exit(1)

    sha = _sha256_of(apk)
    print_summary(sha, apk.name)
