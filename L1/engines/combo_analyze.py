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


def _run_engines(apk_path: Path, sha256: str, track: str, l0: dict,
                 artifacts_root: Path) -> tuple[L1Report, L1Report | None]:
    jr = None
    gr = None
    with ThreadPoolExecutor(max_workers=2) as pool:
        j_fut = pool.submit(jadx_analyze, apk_path, sha256, track, l0, artifacts_root)
        g_fut = pool.submit(ghidra_analyze, apk_path, sha256, track, l0, artifacts_root)
        for fut in as_completed([j_fut, g_fut]):
            try:
                result = fut.result()
                if fut == j_fut:
                    jr = result
                else:
                    gr = result
            except RuntimeError:
                if fut == g_fut:
                    gr = None
    return jr, gr


def analyze(apk_path: str | Path, sha256: str, track: str, l0_evidence: dict,
            artifacts_root: Path) -> L1Report:
    apk_path = Path(apk_path)
    jr, gr = _run_engines(apk_path, sha256, track, l0_evidence, artifacts_root)

    if jr is None:
        raise RuntimeError("jadx engine failed — combo cannot proceed")

    merged: list[L1Finding] = list(jr.findings)
    if gr:
        for f in gr.findings:
            merged.append(f)

    counts = {s.value: 0 for s in [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]}
    for f in merged:
        counts[f.severity.value] += 1

    arts = dict(jr.artifacts)
    if gr:
        arts.update(gr.artifacts)

    return L1Report(
        sha256=sha256, source_apk=str(apk_path), engine="jadx+ghidra", track=track,
        generated_at=jr.generated_at, findings=merged, artifacts=arts,
        summary={"finding_count": len(merged), "severity_counts": counts,
                 "categories": sorted({f.category.value for f in merged}),
                 "ghidra_run": gr is not None},
    )
