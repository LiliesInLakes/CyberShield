"""L1 dispatcher.

Reads an APK's L0 evidence.json (routing decision) and invokes the matching
engine (jadx / ghidra / combo). L0 decides the track; L1 does not re-derive.
Writes L1/artifacts/<sha256>/analysis.json for L2 (dynamic) to consume.

Usage:
    python l1.py <apk_path> [--l0-artifacts DIR] [--out DIR]
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

L1_DIR = Path(__file__).resolve().parent
REPO_ROOT = L1_DIR.parent
for _p in (str(L1_DIR), str(REPO_ROOT)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from schema import load_l0_evidence, L1Report, Severity  # noqa: E402
from engines.jadx_analyze import analyze as jadx_analyze  # noqa: E402
from engines.ghidra_analyze import analyze as ghidra_analyze  # noqa: E402
from engines.combo_analyze import analyze as combo_analyze  # noqa: E402
from engines.yara_scan import scan_apk, merge_findings, ruleset_version  # noqa: E402
from engines.ioc_extract import extract_from_apk as extract_iocs  # noqa: E402
from engines.ioc_extract import summarise as ioc_summary  # noqa: E402
import spine  # noqa: E402

#: Where L1 writes per-sample output — including ``jadx_src``, which is the
#: heaviest thing this project puts on disk. jadx writes and then deletes a
#: large tree of small files per sample; across a corpus run that churn is what
#: exhausted a fully-allocated btrfs ``/home`` mid-run (T30), stopping the
#: benign re-measurement at 245/604. Override it to put that traffic on a
#: roomier filesystem.
#:
#: The spine is unaffected by this: ``spine.update_layer`` is handed the report
#: in memory and always writes to ``artifacts/<sha>/evidence.json`` under the
#: repo, so everything downstream of L1 reads the same place either way.
ARTIFACTS = Path(os.environ.get("SENTINEL_L1_ARTIFACTS") or (L1_DIR / "artifacts"))


def _sha_of(apk_path: Path, l0: dict) -> str:
    fp = l0.get("fingerprint", {})
    if fp.get("sha256"):
        return fp["sha256"]
    import hashlib
    h = hashlib.sha256()
    h.update(apk_path.read_bytes())
    return h.hexdigest()


def dispatch(apk_path: str | Path, l0_artifacts: Path | None = None,
             out_root: Path | None = None) -> L1Report:
    apk_path = Path(apk_path)
    if not apk_path.exists():
        raise FileNotFoundError(f"APK not found: {apk_path}")
    l0 = load_l0_evidence(apk_path, l0_artifacts)
    sha = _sha_of(apk_path, l0)
    track = (l0.get("l0", {}).get("routing", {}) or {}).get("track", "track1_jadx")
    artifacts_root = out_root or ARTIFACTS

    print(f"[L1] sha256={sha[:12]} track={track} apk={apk_path.name}")
    try:
        if track in ("track2_ghidra",):
            report = ghidra_analyze(apk_path, sha, track, l0, artifacts_root)
        elif track in ("track1_jadx",):
            report = jadx_analyze(apk_path, sha, track, l0, artifacts_root)
        elif track in ("track1_jadx+track2_ghidra", "track1_jadx_then_track2_ghidra"):
            report = combo_analyze(apk_path, sha, track, l0, artifacts_root)
        else:
            report = jadx_analyze(apk_path, sha, track, l0, artifacts_root)
    except Exception as exc:  # noqa: BLE001
        # A sample L1 could not analyse must be *visible* as failed. Left out of
        # the spine entirely it is indistinguishable from one never attempted,
        # and a corpus run would quietly under-report its own coverage.
        spine.update_layer(
            sha, "l1",
            status=spine.LayerStatus.FAILED,
            findings=[],
            error=f"{type(exc).__name__}: {str(exc)[:300]}",
            gaps=["l1_engine_failed"],
        )
        raise

    # Merge the APK-scoped scan into the engine's findings. merge_findings()
    # collapses a rule that fired in several scopes into ONE finding, so the
    # source and APK passes can no longer produce paired duplicates.
    yara_apk = scan_apk(apk_path)
    report.findings = merge_findings(report.findings, yara_apk)
    report.summary["finding_count"] = len(report.findings)
    report.summary["apk_yara_rules"] = len(yara_apk)
    report.summary["severity_counts"] = {
        s.value: sum(1 for f in report.findings if f.severity is s) for s in Severity
    }
    report.summary["categories"] = sorted({f.category.value for f in report.findings})
    report.summary["ruleset_version"] = ruleset_version()

    # Blockable indicators. Deliberately NOT findings: an IOC is not a detection.
    # A benign app contacting a domain is normal, so these never contribute to
    # `counts.*` or to a score — they are what L6 exports once a sample has
    # already been judged, and what the LLM is forbidden to invent (main.tex §3.3).
    try:
        iocs = extract_iocs(apk_path)
    except Exception as exc:  # noqa: BLE001
        iocs = []
        report.summary["ioc_error"] = f"{type(exc).__name__}: {str(exc)[:120]}"
    report.artifacts["iocs"] = [i.to_dict() for i in iocs]
    report.summary.update(ioc_summary(iocs))

    out = artifacts_root / sha / "analysis.json"
    report.write(out)

    # Fold L1 into the spine. `partial` rather than `complete` whenever the
    # engine reported a coverage gap — a combo run without Ghidra genuinely did
    # not look at the native layer, and calling that "complete" is how a blind
    # spot turns into unearned confidence downstream.
    gaps = list(report.summary.get("analysis_gaps") or [])
    spine.update_layer(
        sha, "l1",
        status=spine.LayerStatus.PARTIAL if gaps else spine.LayerStatus.COMPLETE,
        findings=[f.to_dict() for f in report.findings],
        summary={
            "engine": report.engine,
            "track": report.track,
            "finding_count": report.summary.get("finding_count"),
            "categories": report.summary.get("categories", []),
            "severity_counts": report.summary.get("severity_counts", {}),
            "ruleset_version": report.summary.get("ruleset_version"),
        },
        coverage={
            "decompiled_files": report.summary.get("decompiled_files", 0),
            "source_findings": report.summary.get("source_findings", 0),
            "apk_yara_rules": report.summary.get("apk_yara_rules", 0),
            "ghidra_available": report.summary.get("ghidra_available", False),
            "ghidra_attempted": report.summary.get("ghidra_attempted", False),
            "ghidra_ok": report.summary.get("ghidra_ok", False),
            "ioc_count": report.summary.get("ioc_count", 0),
            "ioc_types": report.summary.get("ioc_types", {}),
        },
        gaps=gaps,
        artifact=out,
    )

    print(f"[L1] wrote {out}  findings={report.summary.get('finding_count')}")
    return report


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description="L1 static analysis dispatcher")
    p.add_argument("apk", help="path to APK to analyze")
    p.add_argument("--l0-artifacts", default=None, help="L0 artifacts dir (for evidence.json)")
    p.add_argument("--out", default=None, help="L1 artifacts output root")
    args = p.parse_args(argv[1:])
    try:
        dispatch(args.apk, args.l0_artifacts, Path(args.out) if args.out else None)
    except Exception as exc:
        print(f"[L1] error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
