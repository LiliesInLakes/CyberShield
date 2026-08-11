"""L6 — the analyst service.

    source source_env.sh
    $SENTINEL_PYTHON -m uvicorn L6.api:app --host 127.0.0.1 --port 8000

Upload an APK, watch the pipeline run, read the verdict, pull the exports.

**Bound to localhost by default and never told to do otherwise.** This service
accepts uploaded Android malware. It writes every upload under
``SENTINEL_DATA_ROOT/uploads`` and never marks anything executable, but the only
real protection is not exposing the port, so the run command above is the
documented one and there is no convenience flag that binds 0.0.0.0.

**Nothing is executed.** Uploads are touched by ``androguard``, ``zipfile``,
YARA and jadx-under-the-JVM, exactly as in the corpus runner. Analysis is
static; L2 detonation is a separate, deliberate action and is not reachable
from here.

**The dashboard is one static file with no build step.** A React toolchain
would add a Node dependency, a lockfile and a build to a project whose whole
argument is reproducibility on an analyst's machine. The page is served from
``L6/web/index.html`` and talks to the JSON API below.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
import threading
import traceback
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
for _p in (str(REPO_ROOT), str(REPO_ROOT / "L0"), str(REPO_ROOT / "L1")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from fastapi import FastAPI, HTTPException, UploadFile, File  # noqa: E402
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse  # noqa: E402

import spine  # noqa: E402
from L6 import export as export_mod  # noqa: E402
from L6.export import spine_exists  # noqa: E402
from L6 import report as report_mod  # noqa: E402

DATA_ROOT = Path(os.environ.get("SENTINEL_DATA_ROOT", REPO_ROOT))
UPLOAD_DIR = DATA_ROOT / "uploads"
WEB_DIR = Path(__file__).resolve().parent / "web"

APK_MAGIC = b"PK\x03\x04"
MAX_UPLOAD_BYTES = 200 * 1024 * 1024

app = FastAPI(title="APK Sentinel", version="0.2")

# job_id -> {stage, steps[], sha256, error, done}
_JOBS: dict[str, dict[str, Any]] = {}
_JOBS_LOCK = threading.Lock()


def _job_update(job_id: str, **fields: Any) -> None:
    with _JOBS_LOCK:
        _JOBS.setdefault(job_id, {}).update(fields)


def _job_step(job_id: str, name: str, state: str, detail: str = "") -> None:
    with _JOBS_LOCK:
        job = _JOBS.setdefault(job_id, {"steps": []})
        steps = job.setdefault("steps", [])
        for s in steps:
            if s["name"] == name:
                s.update(state=state, detail=detail)
                break
        else:
            steps.append({"name": name, "state": state, "detail": detail})
        job["stage"] = name


def _run_pipeline(job_id: str, apk_path: Path) -> None:
    """L0 -> L1 -> L5 for one uploaded sample, in a worker thread."""
    try:
        from ingest import run_l0
        import l1 as l1_module
        from L5.score import load_policy, score_spine
        from L6 import __init__  # noqa: F401

        _job_step(job_id, "triage", "running")
        l0 = run_l0(apk_path)
        sha = l0["fingerprint"]["sha256"]
        _job_update(job_id, sha256=sha)
        # L0's manifest key is `package_name`, not `package` — the spine's
        # identity block renames it, and reading the spine's name here silently
        # produced "?" for every sample.
        _job_step(job_id, "triage", "done",
                  f"{l0['manifest'].get('package_name') or '?'} · "
                  f"{l0['impersonation'].get('verdict')}")

        _job_step(job_id, "static", "running")
        report = l1_module.dispatch(apk_path)
        _job_step(job_id, "static", "done",
                  f"{len(report.findings)} findings · "
                  f"{report.summary.get('ioc_count', 0)} indicators")

        _job_step(job_id, "scoring", "running")
        from L5.l5 import write_layer
        policy = load_policy()
        doc = spine.load_spine(sha)
        result = score_spine(doc, policy)
        write_layer(result)
        _job_step(job_id, "scoring", "done",
                  f"{result.score}/100 {result.band}"
                  + (" (unsupported)" if result.unsupported else ""))

        _job_update(job_id, done=True, score=result.score, band=result.band,
                    unsupported=result.unsupported)
    except Exception as exc:  # noqa: BLE001
        _job_step(job_id, _JOBS.get(job_id, {}).get("stage", "triage"), "failed",
                  f"{type(exc).__name__}: {exc}")
        _job_update(job_id, done=True,
                    error=f"{type(exc).__name__}: {exc}",
                    traceback=traceback.format_exc()[-2000:])
    finally:
        # The upload is kept: an analyst re-reading a verdict needs the artifact
        # it came from. It is never made executable and never run.
        pass


@app.get("/", response_class=HTMLResponse)
def dashboard() -> str:
    index = WEB_DIR / "index.html"
    if not index.is_file():
        return "<h1>APK Sentinel</h1><p>Dashboard asset missing.</p>"
    return index.read_text()


@app.post("/api/analyze")
async def analyze(file: UploadFile = File(...)) -> JSONResponse:
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    job_id = uuid.uuid4().hex[:12]
    dest = UPLOAD_DIR / f"{job_id}.apk"

    size = 0
    hasher = hashlib.sha256()
    with dest.open("wb") as fh:
        while chunk := await file.read(1 << 20):
            size += len(chunk)
            if size > MAX_UPLOAD_BYTES:
                fh.close()
                dest.unlink(missing_ok=True)
                raise HTTPException(413, f"upload exceeds {MAX_UPLOAD_BYTES} bytes")
            hasher.update(chunk)
            fh.write(chunk)

    # Magic, not extension — 45% of real corpus members are extensionless, and
    # a .apk name proves nothing in either direction.
    with dest.open("rb") as fh:
        if fh.read(4) != APK_MAGIC:
            dest.unlink(missing_ok=True)
            raise HTTPException(400, "not a ZIP/APK (magic bytes do not match)")
    dest.chmod(0o600)

    _JOBS[job_id] = {"steps": [], "done": False, "stage": "queued",
                     "filename": file.filename or "upload.apk",
                     "size": size, "sha256": hasher.hexdigest(),
                     "started_at": datetime.now(timezone.utc).isoformat()}
    threading.Thread(target=_run_pipeline, args=(job_id, dest), daemon=True).start()
    return JSONResponse({"job_id": job_id})


@app.get("/api/job/{job_id}")
def job_status(job_id: str) -> dict[str, Any]:
    job = _JOBS.get(job_id)
    if job is None:
        raise HTTPException(404, "unknown job")
    return job


@app.get("/api/samples")
def samples(limit: int = 100) -> list[dict[str, Any]]:
    """Scored samples, worst first. Unscored spines are included but sort last."""
    rows: list[dict[str, Any]] = []
    for doc in spine.iter_spines():
        l5 = (doc.get("layers", {}).get("l5") or {}).get("summary") or {}
        ident = doc.get("identity", {}) or {}
        rows.append({
            "sha256": doc.get("sha256"),
            "package": ident.get("package"),
            "app_label": ident.get("app_label"),
            "impersonates": ident.get("impersonates"),
            "score": l5.get("score"),
            "band": l5.get("band"),
            "confidence": l5.get("confidence"),
            "unsupported": l5.get("unsupported"),
            "findings": (doc.get("counts") or {}).get("findings", 0),
            "malware_category": (doc.get("counts") or {}).get("malware_category", 0),
        })
    rows.sort(key=lambda r: (r["score"] is None, -(r["score"] or 0)))
    return rows[:limit]


@app.get("/api/sample/{sha256}")
def sample(sha256: str) -> dict[str, Any]:
    if not spine_exists(sha256):
        raise HTTPException(404, "no evidence record for that hash")
    doc = spine.load_spine(sha256)
    score = REPO_ROOT / "L5" / "artifacts" / sha256 / "score.json"
    return {"spine": doc,
            "score": json.loads(score.read_text()) if score.is_file() else None,
            "iocs": export_mod.load_iocs(doc)}


@app.get("/api/report/{sha256}", response_class=HTMLResponse)
def report(sha256: str) -> str:
    if not spine_exists(sha256):
        raise HTTPException(404, "no evidence record for that hash")
    doc = spine.load_spine(sha256)
    return report_mod.render(doc)


@app.get("/api/export/{sha256}/{fmt}")
def export(sha256: str, fmt: str):
    if fmt not in export_mod.FORMATS:
        raise HTTPException(400, f"format must be one of {export_mod.FORMATS}")
    if not spine_exists(sha256):
        raise HTTPException(404, "no evidence record for that hash")
    doc = spine.load_spine(sha256)
    outputs = export_mod.export_all(export_mod.gather(doc), [fmt])
    if not outputs:
        # e.g. Sigma with no network indicators: an empty rule would sit in a
        # SIEM matching nothing and look like coverage.
        raise HTTPException(204, "nothing to export in this format")
    name, content = next(iter(outputs.items()))
    media = "application/json" if name.endswith(".json") else "text/plain"
    return PlainTextResponse(content, media_type=media, headers={
        "Content-Disposition": f'attachment; filename="{sha256[:12]}_{name}"'})


@app.get("/api/health")
def health() -> dict[str, Any]:
    from L5.score import load_policy
    try:
        policy = load_policy()
        weights = {"version": policy.weights_version,
                   "supported": not policy.unsupported}
    except SystemExit as exc:
        weights = {"error": str(exc)}
    return {
        "spines": sum(1 for _ in spine.iter_spines()),
        "schema": spine.SCHEMA_VERSION,
        "weights": weights,
        "jadx": bool(os.environ.get("JADX_DIR")),
    }
