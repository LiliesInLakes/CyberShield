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
from config import get_path

GHIDRA_DIR = Path(get_path("ghidra_home", "/opt/apk-sentinel/tools/ghidra/ghidra_12.1.2_PUBLIC"))
_analyze_headless = "analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless"
ANALYZE_HEADLESS = GHIDRA_DIR / "support" / _analyze_headless
_JDK21 = Path(get_path("jdk21_home", "/usr/lib/jvm/java-21-openjdk-amd64"))
EXPORT_SCRIPT = r"""
from __future__ import print_function
f = open(r"{out}", "w")
for s in currentProgram.getListing().getDefinedStrings(True):
    f.write(s.getString(0, 200) + "\n")
f.close()
"""


def _available() -> bool:
    return ANALYZE_HEADLESS.exists()


def _export_strings(target: Path, out_file: Path, timeout: int = 900) -> bool:
    proj = tempfile.mkdtemp(prefix="ghidra_")
    script = Path(proj) / "export_strings.py"
    script.write_text(EXPORT_SCRIPT.format(out=str(out_file)))
    env = dict(__import__("os").environ)
    if _JDK21.exists():
        env["JAVA_HOME"] = str(_JDK21)
        env["PATH"] = f"{_JDK21}/bin{__import__('os').pathsep}{env.get('PATH', '')}"
    cmd = [
        str(ANALYZE_HEADLESS),
        proj, "l1proj",
        "-import", str(target),
        "-postScript", str(script),
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
        raise RuntimeError("Ghidra not found at D:\\BOI\\tools\\ghidra\\")
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
