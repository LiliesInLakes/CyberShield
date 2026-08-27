"""L1 ghidra engine: native/.so + packed dex disassembly.

Uses ThreadPoolExecutor to analyse multiple .so in parallel.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from schema import L1Finding, L1Report, Severity, Category, CATEGORY_MITRE_MAP
from engines.yara_scan import scan_text

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent

# GHIDRA_HOME is set by source_env.sh (glob over tools/ghidra/ghidra_*_PUBLIC),
# consistent with how JADX_DIR/JDK17_HOME are resolved. The fallback here is
# only reached if that env var is unset (e.g. this module imported without
# sourcing the env script); it points at the same self-contained location
# rather than an absolute path from a different machine, which is what made
# _available() silently return False everywhere until Ghidra was actually
# installed at this path (2026-08-27).
GHIDRA_DIR = Path(os.environ.get("GHIDRA_HOME", str(_REPO_ROOT / "tools" / "ghidra" / "ghidra_12.1.3_PUBLIC")))
# On Linux it's just analyzeHeadless, on Windows .bat
_analyze_headless = "analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless"
ANALYZE_HEADLESS = GHIDRA_DIR / "support" / _analyze_headless
# Ghidra 12.x's own launcher rejects both an older JDK (17, used for jadx)
# and a newer one (25 was tried and rejected too) -- it wants a JDK actually
# built for the 21 line (application.java.min=21). source_env.sh bundles one
# at tools/jdk21 for exactly this reason; this fallback mirrors that path.
_JDK21 = Path(os.environ.get("JDK21_HOME", str(_REPO_ROOT / "tools" / "jdk21")))
# Ghidra 12.x dropped the bundled Jython interpreter for .py postScripts in
# favour of PyGhidra, a separate CPython bridge this install does not have
# ("Ghidra was not started with PyGhidra. Python is not available" -- headless
# log, 2026-08-27). A .java GhidraScript needs neither Jython nor PyGhidra --
# analyzeHeadless compiles and runs it directly -- so that's what this is.
# The class name must match the file name (ExportStrings.java / ExportStrings).
EXPORT_SCRIPT = r"""
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Data;
import java.io.PrintWriter;

public class ExportStrings extends GhidraScript {
    @Override
    public void run() throws Exception {
        String outPath = getScriptArgs()[0];
        PrintWriter out = new PrintWriter(outPath);
        try {
            Data d = getFirstData();
            while (d != null) {
                if (d.hasStringValue()) {
                    out.println(d.getDefaultValueRepresentation());
                }
                d = getDataAfter(d);
            }
        } finally {
            out.close();
        }
    }
}
"""


def _available() -> bool:
    return ANALYZE_HEADLESS.exists()


def _export_strings(target: Path, out_file: Path, timeout: int = 900) -> bool:
    proj = tempfile.mkdtemp(prefix="ghidra_")
    script = Path(proj) / "ExportStrings.java"
    script.write_text(EXPORT_SCRIPT)
    env = dict(__import__("os").environ)
    if _JDK21.exists():
        env["JAVA_HOME"] = str(_JDK21)
        env["PATH"] = f"{_JDK21}/bin{__import__('os').pathsep}{env.get('PATH', '')}"
    cmd = [
        str(ANALYZE_HEADLESS),
        proj, "l1proj",
        "-import", str(target),
        "-postScript", "ExportStrings.java", str(out_file),
        "-scriptPath", str(proj),
        "-deleteProject",
        "-readOnly",
        "-noanalysis",
    ]
    log = out_file.with_suffix(".ghidra.log")
    try:
        with log.open("w") as lf:
            subprocess.run(cmd, check=True, stdout=lf, stderr=lf, timeout=timeout, env=env)
    except subprocess.CalledProcessError as exc:
        if not out_file.exists():
            raise RuntimeError(f"ghidra failed — see {log}") from exc
    return True


def _extract_apk_native(apk_path: Path, out_dir: Path) -> list[Path]:
    import zipfile
    out_dir.mkdir(parents=True, exist_ok=True)
    extracted: list[Path] = []
    with zipfile.ZipFile(apk_path) as zf:
        for name in zf.namelist():
            if name.endswith(".so"):
                target = out_dir / Path(name).name
                if not target.exists():
                    target.write_bytes(zf.read(name))
                extracted.append(target)
    return extracted


def _analyse_one(so: Path, out_file: Path) -> list[L1Finding]:
    out_file.parent.mkdir(parents=True, exist_ok=True)
    if out_file.exists() and out_file.stat().st_size > 0:
        text = out_file.read_text(errors="ignore")
        return scan_text(text, source_label=f"ghidra_{so.stem}")
    try:
        _export_strings(so, out_file)
        text = out_file.read_text(errors="ignore")
        return scan_text(text, source_label=f"ghidra_{so.stem}")
    except Exception:
        return []


def analyze(apk_path: str | Path, sha256: str, track: str, l0_evidence: dict,
            artifacts_root: Path) -> L1Report:
    if not _available():
        raise RuntimeError(f"Ghidra not found at {ANALYZE_HEADLESS} "
                          f"(GHIDRA_HOME={os.environ.get('GHIDRA_HOME', '<unset>')})")
    apk_path = Path(apk_path)
    arts = {}
    findings: list[L1Finding] = []

    native_dir = artifacts_root / sha256 / "native_libs"
    natives = _extract_apk_native(apk_path, native_dir)

    if natives:
        seen_stems = set()
        uniq = []
        for so in natives:
            if so.stem not in seen_stems:
                seen_stems.add(so.stem)
                uniq.append(so)
        natives = uniq

        with ThreadPoolExecutor(max_workers=min(2, len(natives))) as pool:
            fut_map = {}
            for so in natives:
                out_file = artifacts_root / sha256 / f"ghidra_strings_{so.stem}.txt"
                fut = pool.submit(_analyse_one, so, out_file)
                fut_map[fut] = (so, out_file)
            for fut in as_completed(fut_map):
                so, out_file = fut_map[fut]
                f = fut.result()
                findings.extend(f)
                arts[f"strings_{so.stem}"] = str(out_file)

    for so in natives:
        text = so.read_bytes().decode("utf-8", errors="replace")
        if "JNI_OnLoad" in text or "Java_" in text:
            findings.append(L1Finding(
                engine="ghidra", category=Category.NATIVE_PAYLOAD, severity=Severity.MEDIUM,
                evidence=f"JNI native method present in {so.name}",
                location=f"native_export:{so.name}",
                mitre_techniques=CATEGORY_MITRE_MAP.get(Category.NATIVE_PAYLOAD, []),
            ))
            break

    if not findings:
        findings.append(L1Finding(
            engine="ghidra", category=Category.OTHER, severity=Severity.INFO,
            evidence="Ghidra analysis completed with no findings",
            location="ghidra_summary",
            mitre_techniques=[],
        ))

    counts = {s.value: 0 for s in [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]}
    for f in findings:
        counts[f.severity.value] += 1

    report = L1Report(
        sha256=sha256, source_apk=str(apk_path), engine="ghidra+yara", track=track,
        generated_at=__import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
        findings=findings, artifacts=arts,
        summary={"finding_count": len(findings), "severity_counts": counts,
                 "categories": sorted({f.category.value for f in findings}),
                 "native_libs_analyzed": len(natives)},
    )
    return report
