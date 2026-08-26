"""L1 combo engine: jadx + ghidra union run in parallel.

Used when L0 routing marks both tracks (packed app with native payload).
Runs jadx and ghidra concurrently, merges findings, de-dupes by (category, evidence).
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from schema import L1Finding, L1Report, Severity
from engines.jadx_analyze import analyze as jadx_analyze
from engines.ghidra_analyze import analyze as ghidra_analyze
from engines.ghidra_analyze import _available as _ghidra_available
from engines.yara_scan import merge_findings


def _run_engines(apk_path: Path, sha256: str, track: str, l0: dict,
                 artifacts_root: Path) -> tuple[L1Report, L1Report | None]:
    jr = None
    gr = None
    errors: list[str] = []
    with ThreadPoolExecutor(max_workers=2) as pool:
        j_fut = pool.submit(jadx_analyze, apk_path, sha256, track, l0, artifacts_root)
        g_fut = pool.submit(ghidra_analyze, apk_path, sha256, track, l0, artifacts_root)
        for fut in as_completed([j_fut, g_fut]):
            which = "jadx" if fut is j_fut else "ghidra"
            try:
                result = fut.result()
            except Exception as exc:  # noqa: BLE001
                # Catch broadly, not just RuntimeError. A malformed archive raises
                # zipfile.BadZipFile, and deliberately-corrupted ZIP structure is a
                # documented anti-analysis technique in this threat model — it must
                # degrade one engine, not kill the whole sample.
                errors.append(f"{which}:{type(exc).__name__}:{str(exc)[:120]}")
                continue
            if which == "jadx":
                jr = result
            else:
                gr = result
    return jr, gr, errors


def analyze(apk_path: str | Path, sha256: str, track: str, l0_evidence: dict,
            artifacts_root: Path) -> L1Report:
    apk_path = Path(apk_path)
    jr, gr, errors = _run_engines(apk_path, sha256, track, l0_evidence, artifacts_root)

    if jr is None:
        raise RuntimeError(f"jadx engine failed — combo cannot proceed ({'; '.join(errors)})")

    merged = merge_findings(jr.findings, gr.findings if gr else [])

    counts = {s.value: sum(1 for f in merged if f.severity is s) for s in Severity}

    arts = dict(jr.artifacts)
    if gr:
        arts.update(gr.artifacts)

    # Carry the jadx summary forward rather than building a fresh dict — the
    # previous version constructed one from scratch, which is why coverage
    # metrics like decompiled_files vanished on exactly the combo track.
    summary = dict(jr.summary)
    summary.update({
        "finding_count": len(merged),
        "severity_counts": counts,
        "categories": sorted({f.category.value for f in merged}),
        "ghidra_available": _ghidra_available(),
        "ghidra_attempted": True,
        "ghidra_ok": gr is not None,
        "engine_errors": errors,
    })
    gaps = list(summary.get("analysis_gaps", []))
    if gr is None:
        gaps.append("ghidra_unavailable" if not _ghidra_available() else "ghidra_failed")
    summary["analysis_gaps"] = gaps

    return L1Report(
        sha256=sha256, source_apk=str(apk_path), engine="jadx+ghidra", track=track,
        generated_at=jr.generated_at, findings=merged, artifacts=arts,
        summary=summary,
    )
