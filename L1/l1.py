"""L1 dispatcher.

Reads an APK's L0 evidence.json (routing decision) and invokes the matching
engine (jadx / ghidra / combo). L0 decides the track; L1 does not re-derive.
Writes L1/artifacts/<sha256>/analysis.json for L2 (dynamic) to consume.

Usage:
    python l1.py <apk_path> [--l0-artifacts DIR] [--out DIR]
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from schema import load_l0_evidence, L1Report  # noqa: E402
from engines.jadx_analyze import analyze as jadx_analyze  # noqa: E402
from engines.ghidra_analyze import analyze as ghidra_analyze  # noqa: E402
from engines.combo_analyze import analyze as combo_analyze  # noqa: E402
from engines.yara_scan import scan_apk  # noqa: E402

L1_DIR = Path(__file__).resolve().parent
ARTIFACTS = L1_DIR / "artifacts"


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
    if track in ("track2_ghidra",):
        report = ghidra_analyze(apk_path, sha, track, l0, artifacts_root)
    elif track in ("track1_jadx",):
        report = jadx_analyze(apk_path, sha, track, l0, artifacts_root)
    elif track in ("track1_jadx+track2_ghidra", "track1_jadx_then_track2_ghidra"):
        report = combo_analyze(apk_path, sha, track, l0, artifacts_root)
    else:
        report = jadx_analyze(apk_path, sha, track, l0, artifacts_root)

    yara_apk = scan_apk(apk_path)
    if yara_apk:
        report.findings.extend(yara_apk)
        report.summary["finding_count"] = len(report.findings)
        report.summary["apk_yara_findings"] = len(yara_apk)
        for sev in {f.severity.value for f in yara_apk}:
            report.summary.setdefault("severity_counts", {}).setdefault(sev, 0)
            report.summary["severity_counts"][sev] = sum(
                1 for f in report.findings if f.severity.value == sev
            )
        report.summary["categories"] = sorted({f.category.value for f in report.findings})

    out = artifacts_root / sha / "analysis.json"
    report.write(out)
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
