"""
APK Sentinel Pipeline Orchestrator.

Chains L0 → L1 → L2 sequentially, maintaining a single shared evidence.json
spine that each layer reads from and writes to.

Usage:
    python pipeline.py <apk_path> [--l2-timeout 90] [--l2-no-emulator] [--out DIR]

Output:
    <out>/<sha256>/evidence.json  (default: L0/artifacts/<sha256>/evidence.json)
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logging.basicConfig(level=logging.INFO, format="[%(name)s] %(levelname)s %(message)s")
_log = logging.getLogger("pipeline")

ROOT_DIR = Path(__file__).resolve().parent
L0_DIR = ROOT_DIR / "L0"
L1_DIR = ROOT_DIR / "L1"
L2_DIR = ROOT_DIR / "L2"

from cache import cached_analysis, cached_l1_analysis  # noqa: E402


def compute_sha256(apk_path: Path) -> str:
    h = hashlib.sha256()
    with apk_path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load_or_create_evidence(apk_path: Path, out_root: Path) -> dict:
    sha = compute_sha256(apk_path)
    evidence_path = out_root / sha / "evidence.json"
    if evidence_path.exists():
        return json.loads(evidence_path.read_text())
    return {
        "schema_version": "apk-sentinel-0.1",
        "generated_at": "",
        "source_apk": str(apk_path),
        "l0": {"status": "pending"},
        "l1": {"status": "pending"},
        "l2": {"status": "pending"},
        "l3": {"status": "pending"},
        "l4": {"status": "pending"},
        "l5": {"status": "pending"},
        "l6": {"status": "pending"},
    }


def save_evidence(evidence: dict, out_root: Path, sha: str) -> Path:
    evidence["generated_at"] = datetime.now(timezone.utc).isoformat()
    out_dir = out_root / sha
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "evidence.json"
    with out_path.open("w") as fh:
        json.dump(evidence, fh, indent=2)
    _log.info("Evidence written: %s", out_path)
    return out_path


def run_l0(apk_path: Path, out_root: Path, evidence: dict, env: dict) -> dict:
    sys.path.insert(0, str(L0_DIR))
    from ingest import run_l0 as l0_entry

    l0 = l0_entry(
        str(apk_path),
        out_path=str(out_root / compute_sha256(apk_path) / "evidence.json"),
        vt_api_key=env.get("VT_API_KEY"),
        mb_auth_key=env.get("MB_AUTH_KEY"),
        force_external=False,
        vision_key=env.get("GOOGLE_VISION_KEY"),
    )
    evidence["l0"] = l0
    evidence["l0"]["status"] = "complete"
    _log.info("L0 complete — routing: %s", l0.get("routing", {}).get("track", "unknown"))
    return l0


def run_l1(apk_path: Path, out_root: Path, evidence: dict, sha: str) -> dict:
    sys.path.insert(0, str(L1_DIR))
    from l1 import dispatch as l1_entry

    l0_artifacts = out_root / sha
    report = l1_entry(str(apk_path), l0_artifacts=l0_artifacts, out_root=l0_artifacts, sha256=sha)
    l1_dict = {
        "status": "complete",
        "engine": report.engine,
        "track": report.track,
        "finding_count": report.summary.get("finding_count", 0),
        "severity_counts": report.summary.get("severity_counts", {}),
        "categories": report.summary.get("categories", []),
        "findings": [f.to_dict() for f in report.findings],
        "artifacts": report.artifacts,
    }
    evidence["l1"] = l1_dict
    _log.info("L1 complete — %d findings", l1_dict["finding_count"])
    return l1_dict


def run_l2(apk_path: Path, out_root: Path, evidence: dict, l2_timeout: int, l2_no_emulator: bool) -> dict:
    sys.path.insert(0, str(L2_DIR))
    from orchestrator import detonate as l2_detonate
    from l2_engine import process as l2_process

    sha = compute_sha256(apk_path)

    if not l2_no_emulator:
        raw = l2_detonate(str(apk_path), timeout=l2_timeout, use_emulator=True)
    else:
        raw = {"status": "dry_run", "note": "No emulator available."}

    l2_processed = l2_process(sha, sandbox_dir=None, out_root=out_root)

    l2_dict = {
        "status": raw.get("status", "complete"),
        "raw_detonation": {
            "frida_event_count": raw.get("frida_event_count", 0),
            "api_call_count": raw.get("api_call_count", 0),
            "dropper_write_count": raw.get("dropper_write_count", 0),
            "sms_access_count": raw.get("sms_access_count", 0),
            "overlay_count": raw.get("overlay_count", 0),
            "dynamic_code_count": raw.get("dynamic_code_count", 0),
            "c2_beacon_count": raw.get("c2_beacon_count", 0),
            "anti_evasion_count": raw.get("anti_evasion_count", 0),
        },
        "processed": l2_processed.to_dict() if hasattr(l2_processed, 'to_dict') else l2_processed,
    }
    if raw.get("error"):
        l2_dict["error"] = raw["error"]

    evidence["l2"] = l2_dict
    _log.info("L2 complete — %d events", raw.get("frida_event_count", 0))
    return l2_dict


def run_pipeline(apk_path: str | Path, out_root: Path | None = None,
                 l2_timeout: int = 90, l2_no_emulator: bool = False,
                 skip_l2: bool = False, env: dict | None = None) -> dict:
    apk_path = Path(apk_path).resolve()
    if not apk_path.exists():
        raise FileNotFoundError(f"APK not found: {apk_path}")

    out_root = out_root or (L0_DIR / "artifacts")
    evidence = load_or_create_evidence(apk_path, out_root)
    sha = compute_sha256(apk_path)
    env = env or {}

    _log.info("=" * 60)
    _log.info("APK Sentinel Pipeline")
    _log.info("APK: %s", apk_path)
    _log.info("SHA256: %s", sha)
    _log.info("=" * 60)

    t0 = time.time()
    elapsed_l0 = 0.0
    elapsed_l1 = 0.0

    cached_l0 = cached_analysis(out_root, sha, "l0")
    if cached_l0:
        evidence["l0"] = cached_l0
        _log.info("--- L0: Cached (skipped) ---")
    else:
        _log.info("--- L0: Ingestion & Triage ---")
        run_l0(apk_path, out_root, evidence, env)
        save_evidence(evidence, out_root, sha)
        elapsed_l0 = time.time() - t0

    cached_l1_data = cached_l1_analysis(out_root, sha)
    if cached_l1_data:
        evidence["l1"] = cached_l1_data
        _log.info("--- L1: Cached (skipped, %d findings) ---",
                  cached_l1_data.get("finding_count", 0))
    else:
        _log.info("--- L1: Static Analysis ---")
        run_l1(apk_path, out_root, evidence, sha)
        save_evidence(evidence, out_root, sha)
        elapsed_l1 = time.time() - t0

    if not skip_l2:
        cached_l2 = cached_analysis(out_root, sha, "l2")
        if cached_l2:
            evidence["l2"] = cached_l2
            _log.info("--- L2: Cached (skipped) ---")
        else:
            _log.info("--- L2: Dynamic Analysis ---")
            run_l2(apk_path, out_root, evidence, l2_timeout, l2_no_emulator)
            save_evidence(evidence, out_root, sha)
    else:
        evidence["l2"] = {"status": "skipped"}
        _log.info("--- L2: Skipped ---")

    total = time.time() - t0
    _log.info("=" * 60)
    _log.info("Pipeline complete in %.1fs", total)
    _log.info("L0: %.1fs | L1: %.1fs | L2: %.1fs",
              elapsed_l0, elapsed_l1 - elapsed_l0, total - elapsed_l1)
    _log.info("Output: %s", out_root / sha / "evidence.json")

    return evidence


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(
        description="APK Sentinel — Full Pipeline (L0 → L1 → L2)"
    )
    p.add_argument("apk", help="Path to APK file to analyze")
    p.add_argument("--out", default=None, help="Output directory for artifacts")
    p.add_argument("--l2-timeout", type=int, default=90, help="L2 detonation window (seconds)")
    p.add_argument("--l2-no-emulator", action="store_true", help="Skip L2 emulator detonation")
    p.add_argument("--skip-l2", action="store_true", help="Skip L2 entirely")
    args = p.parse_args(argv[1:])

    env = {
        "VT_API_KEY": __import__("os").environ.get("VT_API_KEY", ""),
        "MB_AUTH_KEY": __import__("os").environ.get("MB_AUTH_KEY", ""),
        "GOOGLE_VISION_KEY": __import__("os").environ.get("GOOGLE_VISION_KEY", ""),
    }

    try:
        evidence = run_pipeline(
            args.apk, Path(args.out) if args.out else None,
            args.l2_timeout, args.l2_no_emulator, args.skip_l2, env
        )
    except Exception as e:
        _log.error("Pipeline failed: %s", e)
        return 1

    final_path = Path(args.out or (L0_DIR / "artifacts")) / compute_sha256(Path(args.apk)) / "evidence.json"
    print(f"\nSummary: {final_path}")
    l0 = evidence.get("l0", {})
    l1 = evidence.get("l1", {})
    l2 = evidence.get("l2", {})
    print(f"  L0: {l0.get('status', '?')}  routing={l0.get('routing', {}).get('track', '?')}")
    print(f"  L1: {l1.get('status', '?')}  findings={l1.get('finding_count', '?')}")
    print(f"  L2: {l2.get('status', '?')}  events={l2.get('raw_detonation', {}).get('frida_event_count', '?')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
