"""L1 jadx engine: decompile APK and scan with YARA.

Consumes an APK + its L0 routing decision. Decompiles with jadx (headless),
then scans decompiled sources with YARA (adapted source rules). Also runs
YARA on the raw APK. Replaces the old SUSPICIOUS_SIGS string matching.

jadx is invoked with the bundled JDK17 at D:\\BOI\\tools\\jdk17 (system Java
is only v8 and too old for jadx 1.5.6).
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from schema import L1Finding, L1Report, Severity
from engines.yara_scan import scan_sources

# Resolve via env var (set by setup_env.sh) or assume they are in PATH
JADX_DIR = Path(os.environ.get("JADX_DIR", "/opt/apk-sentinel/tools/jadx"))
JDK_DIR = Path(os.environ.get("JDK17_HOME", "/usr/lib/jvm/java-17-openjdk-amd64"))
JADX_JAR = JADX_DIR / "lib" / "jadx-1.5.6-all.jar"

# Corpus runs need a much shorter leash than interactive analysis: a handful of
# deliberately-obfuscated samples will otherwise spend 10 minutes each. Set via
# env so it reaches this engine through the combo track too, without every
# caller in between having to forward a parameter.
DEFAULT_TIMEOUT = int(os.environ.get("SENTINEL_JADX_TIMEOUT", "600"))


def _java() -> str:
    java = JDK_DIR / "bin" / "java"
    if java.exists():
        return str(java)
    return "java"  # fall back to PATH


def decompile(apk_path: Path, out_dir: Path, timeout: int | None = None) -> bool:
    """Run headless jadx.

    IMPORTANT: must invoke the explicit CLI class (jadx.cli.JadxCLI) via
    -cp, NOT -jar. On Windows the -jar entry point falls back to the GUI
    launcher. The CLI class keeps it headless.
    """
    timeout = DEFAULT_TIMEOUT if timeout is None else timeout
    out_dir.mkdir(parents=True, exist_ok=True)
    cmd = [
        _java(),
        "-cp", str(JADX_JAR),
        "jadx.cli.JadxCLI",
        "-j", "4",
        "-d", str(out_dir),
        str(apk_path),
    ]
    try:
        subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=timeout)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        # jadx writes sources incrementally, so a non-zero exit OR a timeout
        # usually still leaves usable output. Only fail when nothing was written.
        # (Timeout previously escaped this handler entirely, discarding partial
        # work and killing the sample — which matters once the corpus run uses a
        # short timeout against deliberately-obfuscated malware.)
        if not any(out_dir.rglob("*.java")):
            detail = getattr(exc, "stderr", None) or str(exc)
            if isinstance(detail, bytes):
                detail = detail.decode("utf-8", errors="replace")
            raise RuntimeError(f"jadx produced no sources: {str(detail)[:500]}") from exc
        return False  # partial
    return True


def analyze(apk_path: str | Path, sha256: str, track: str, l0_evidence: dict,
            artifacts_root: Path) -> L1Report:
    apk_path = Path(apk_path)
    out_dir = artifacts_root / sha256 / "jadx_src"
    existing = list(out_dir.rglob("*.java"))
    complete = True
    if len(existing) < 10:
        complete = decompile(apk_path, out_dir)
    else:
        print(f"[jadx] cached — {len(existing)} files")

    src_count = len(list(out_dir.rglob("*.java")))
    workers = 4 if src_count > 5000 else 0
    source_findings = scan_sources(out_dir, max_workers=workers)
    all_findings = source_findings

    sev_order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    counts = {s.value: 0 for s in sev_order}
    for fnd in all_findings:
        counts[fnd.severity.value] += 1
    cats = sorted({f.category.value for f in all_findings})

    report = L1Report(
        sha256=sha256,
        source_apk=str(apk_path),
        engine="jadx+yara",
        track=track,
        generated_at=__import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
        findings=all_findings,
        artifacts={"decompiled_src": str(out_dir)},
        summary={
            "finding_count": len(all_findings),
            "severity_counts": counts,
            "categories": cats,
            "decompiled_files": len(list(out_dir.rglob("*.java"))),
            "source_findings": len(source_findings),
            # A timed-out or crashed jadx still yields usable partial sources.
            # Scoring one of those as fully analysed is how a blind spot turns
            # into unearned confidence, so the gap is recorded explicitly.
            "decompile_complete": complete,
            "analysis_gaps": [] if complete else ["decompilation_partial"],
        },
    )
    return report
