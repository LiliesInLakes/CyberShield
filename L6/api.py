"""L6 — the analyst service (control panel + live sandbox view).

    source source_env.sh
    $SENTINEL_PYTHON -m uvicorn L6.api:app --host 127.0.0.1 --port 8000

Pick an app, choose which layers to run (skip L3/L4/the emulator freely),
watch the pipeline execute, watch the emulator navigation **live**, read the
verdict, pull the exports.

**Bound to localhost by default and never told to do otherwise.** This service
can now *detonate* a sample (L2), so exposing the port is worse than before, not
better. There is no convenience flag that binds 0.0.0.0.

**L2 is opt-in and explicit.** Static analysis (L0/L1/L3) never executes the
sample. L2 launches the emulator and runs the app; it is only reached when the
caller ticks the emulator layer, and the mitmproxy sandbox blocks unknown egress
by default (``SENTINEL_MITM_BLOCK_UNKNOWN``).

**The dashboard is one static file, no build step** (``L6/web/index.html``).
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import signal
import subprocess
import sys
import threading
import time
import traceback
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
for _p in (str(REPO_ROOT), str(REPO_ROOT / "L0"), str(REPO_ROOT / "L1")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from fastapi import Body, FastAPI, File, HTTPException, UploadFile  # noqa: E402
from fastapi.responses import (  # noqa: E402
    HTMLResponse, JSONResponse, PlainTextResponse, Response,
)

import spine  # noqa: E402
from L6 import export as export_mod  # noqa: E402
from L6.export import spine_exists  # noqa: E402
from L6 import report as report_mod  # noqa: E402

DATA_ROOT = Path(os.environ.get("SENTINEL_DATA_ROOT", REPO_ROOT))
UPLOAD_DIR = DATA_ROOT / "uploads"
WEB_DIR = Path(__file__).resolve().parent / "web"
L1_ARTIFACTS = Path(os.environ.get("SENTINEL_L1_ARTIFACTS", str(DATA_ROOT / "l1_artifacts")))
SANDBOX_ARTIFACTS = REPO_ROOT / "L2" / "sandbox" / "artifacts"
PYTHON = os.environ.get("SENTINEL_PYTHON", sys.executable)
EMULATOR_SERIAL = os.environ.get("SENTINEL_EMULATOR_SERIAL", "emulator-5554")

APK_MAGIC = b"PK\x03\x04"
MAX_UPLOAD_BYTES = 200 * 1024 * 1024

# Directories a caller may select an on-disk APK from. A selected path must
# resolve inside one of these — no path traversal to arbitrary files.
ALLOWED_APK_ROOTS = [
    (REPO_ROOT / "testing_apps").resolve(),
    (REPO_ROOT / "corpus" / "malware_raw").resolve(),
    UPLOAD_DIR.resolve(),
]

ALL_LAYERS = ["l0", "l1", "l2", "l3", "l4", "l5", "l6"]

app = FastAPI(title="APK Sentinel", version="0.3")

# job_id -> {stage, steps[], sha256, package, error, done, layers, navigator,
#            log[], stop_requested}
_JOBS: dict[str, dict[str, Any]] = {}
_JOBS_LOCK = threading.Lock()

# job_id -> the currently-live subprocess (L2 orchestrator or L4 deobfuscate),
# so a stop request can reach it. Kept OUT of _JOBS: a Popen is not
# JSON-serializable and every _JOBS read here feeds an API response.
_JOB_PROCS: dict[str, subprocess.Popen] = {}

_MAX_LOG_LINES = 4000


def _find_adb() -> str | None:
    found = shutil.which("adb")
    if found:
        return found
    sdk = os.environ.get("ANDROID_SDK_ROOT") or os.environ.get("ANDROID_HOME")
    if sdk:
        cand = Path(sdk) / "platform-tools" / "adb"
        if cand.is_file():
            return str(cand)
    return None


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


def _job_log(job_id: str, line: str) -> None:
    """Append one line to a job's live feed, capped so a long/chatty run
    cannot grow the buffer without bound."""
    if not line:
        return
    with _JOBS_LOCK:
        job = _JOBS.setdefault(job_id, {"log": []})
        log_lines = job.setdefault("log", [])
        log_lines.append(line)
        if len(log_lines) > _MAX_LOG_LINES:
            del log_lines[: len(log_lines) - _MAX_LOG_LINES]


def _stream_subprocess(job_id: str, cmd: list[str], *, cwd: Path,
                       env: dict[str, str] | None = None,
                       timeout_s: float = 600.0) -> str:
    """Run ``cmd``, streaming every stdout line into the job's live feed as it
    arrives (stderr merged in — both L2 and L4 write plain, unbuffered lines,
    see their own ``main()``s) instead of the old behaviour of capturing
    everything silently and only showing it after the process exited, which
    is exactly what made a multi-minute run look identical to a hang.

    Registers the ``Popen`` in ``_JOB_PROCS`` for the duration so
    ``/api/job/{id}/stop`` can reach it. Returns ``"ok"``, ``"failed"``, or
    ``"stopped"`` (the caller distinguishes a requested stop from a crash).
    """
    proc = subprocess.Popen(
        cmd, cwd=str(cwd), env=env, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, text=True, bufsize=1,
    )
    with _JOBS_LOCK:
        _JOB_PROCS[job_id] = proc
    start = time.monotonic()
    try:
        assert proc.stdout is not None
        for raw_line in proc.stdout:
            _job_log(job_id, raw_line.rstrip("\n"))
            if time.monotonic() - start > timeout_s:
                _job_log(job_id, f"INFO api: exceeded {timeout_s:.0f}s -- terminating")
                proc.terminate()
                break
        proc.wait(timeout=20)
    except subprocess.TimeoutExpired:
        _job_log(job_id, "WARNING api: process did not exit after terminate -- killing")
        proc.kill()
        proc.wait()
    finally:
        with _JOBS_LOCK:
            _JOB_PROCS.pop(job_id, None)

    if _JOBS.get(job_id, {}).get("stop_requested"):
        return "stopped"
    return "ok" if proc.returncode == 0 else "failed"


def _sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while chunk := fh.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()


def _package_of(apk_path: Path) -> str | None:
    """Package name for an APK, used when L2 is run without L0 in the same job.

    Falls back to L0's aapt-based recovery (same as harvest_manifest) when
    androguard can't read a deliberately-sabotaged manifest -- otherwise an
    anti-analysis sample run L2-only would skip detonation for lack of a
    package name, the exact gap the L0 fallback closes.
    """
    try:
        from androguard.core.apk import APK
        pkg = APK(str(apk_path)).get_package()
        if pkg:
            return pkg
    except Exception:  # noqa: BLE001
        pass
    try:
        from L0.ingest import _aapt_badging
        recovered = _aapt_badging(Path(apk_path))
        return recovered.get("package_name") if recovered else None
    except Exception:  # noqa: BLE001
        return None


# ---------------------------------------------------------------------------
# The layer-aware job runner
# ---------------------------------------------------------------------------

def _stopped(job_id: str) -> bool:
    return bool(_JOBS.get(job_id, {}).get("stop_requested"))


def _run_job(job_id: str, apk_path: Path, layers: list[str], navigator: str) -> None:
    """Run the requested subset of L0..L5 for one sample, in a worker thread.

    Every layer is independently skippable. A layer that fails degrades to a
    ``failed``/``skipped`` step and the job continues where it can, rather than
    aborting the whole run — an analyst who asked for L1+L5 should still get L5
    even if L3's model is missing. A stop request is checked between stages
    (``_run_l2``/``_run_l4`` also check it mid-run, live, via their subprocess)
    so a stop mid-L2 does not go on to spend the L3/L4/L5 window regardless.
    """
    enabled = set(layers)
    try:
        sha: str | None = None
        package: str | None = None

        # ---- L0 ---------------------------------------------------------
        if "l0" in enabled:
            from ingest import run_l0
            _job_step(job_id, "l0", "running")
            l0 = run_l0(apk_path)
            sha = l0["fingerprint"]["sha256"]
            package = l0["manifest"].get("package_name")
            _job_update(job_id, sha256=sha, package=package)
            _job_step(job_id, "l0", "done",
                      f"{package or '?'} · {l0['impersonation'].get('verdict')}")
        else:
            sha = _sha256_of(apk_path)
            package = _package_of(apk_path)
            _job_update(job_id, sha256=sha, package=package)

        # ---- L1 ---------------------------------------------------------
        if "l1" in enabled and not _stopped(job_id):
            import l1 as l1_module
            _job_step(job_id, "l1", "running")
            report = l1_module.dispatch(apk_path)
            _job_step(job_id, "l1", "done",
                      f"{len(report.findings)} findings · "
                      f"{report.summary.get('ioc_count', 0)} indicators")

        # ---- L2 (emulator detonation + live navigation) -----------------
        if "l2" in enabled and not _stopped(job_id):
            _run_l2(job_id, apk_path, package, sha, navigator)

        # ---- L3 ---------------------------------------------------------
        if "l3" in enabled and not _stopped(job_id):
            _job_step(job_id, "l3", "running")
            try:
                from L3.predict import load_model, predict_apk
                from L3.predict import write_layer as l3_write_layer
                model, calibrator, metrics = load_model()
                l3 = predict_apk(apk_path, model=model, calibrator=calibrator)
                l3_write_layer(sha, l3, metrics)
                prob = l3.get("prob_malicious")
                detail = (f"p(malicious)={prob:.4f}" if prob is not None
                          else f"skipped: {l3.get('reason')}")
                _job_step(job_id, "l3", "done", detail)
            except (Exception, SystemExit) as exc:  # noqa: BLE001
                _job_step(job_id, "l3", "skipped", f"{type(exc).__name__}: {exc}")

        # ---- L4 (GenAI reasoning) ---------------------------------------
        if "l4" in enabled and not _stopped(job_id):
            _run_l4(job_id, sha)

        # ---- L5 (scoring) — always attempted if requested, even after a
        # stop: it is fast, in-process, and read-only, so it is worth
        # reporting the best score obtainable from whatever layers did
        # complete rather than skipping it too. ------------------------
        if "l5" in enabled:
            from L5.l5 import write_layer
            from L5.score import load_policy, score_spine
            _job_step(job_id, "l5", "running")
            policy = load_policy()
            doc = spine.load_spine(sha)
            result = score_spine(doc, policy)
            write_layer(result)
            _job_step(job_id, "l5", "done",
                      f"{result.score}/100 {result.band}"
                      + (f" (+{result.ai_delta} AI)" if result.ai_delta else "")
                      + (" (unsupported)" if result.unsupported else ""))
            _job_update(job_id, score=result.score, band=result.band,
                        unsupported=result.unsupported, ai_delta=result.ai_delta)

        # ---- L6 recommend (post-verdict "what should the analyst do
        # next") — opt-in like L2/L4, not auto-run: it makes an LLM call
        # and needs L5's score already computed. -------------------------
        if "l6" in enabled and not _stopped(job_id):
            from L4.provider import CostLedger, get_provider
            from L5.score import load_policy, score_spine
            from L6.recommend import recommend, write_layer as write_recommend_layer
            _job_step(job_id, "l6", "running", "generating next-step recommendation")
            try:
                doc = spine.load_spine(sha)
                policy = load_policy()
                score = score_spine(doc, policy, include_ai=True)
                ledger = CostLedger(cap_usd=0.25)
                provider = get_provider("aicredits", ledger=ledger)
                rec = recommend(doc, score, provider)
                write_recommend_layer(rec)
                _job_step(job_id, "l6", "done",
                          f"{rec.priority_tier} · {len(rec.actions)} action(s), "
                          f"{len(rec.dropped)} dropped · ${rec.cost_usd:.4f}")
            except Exception as exc:  # noqa: BLE001
                # Advisory-only step -- a failure here must not take down a
                # run that already has a valid L0-L5 verdict.
                _job_step(job_id, "l6", "failed", f"{type(exc).__name__}: {exc}")

        _job_update(job_id, done=True, stopped=_stopped(job_id))
    except Exception as exc:  # noqa: BLE001
        _job_step(job_id, _JOBS.get(job_id, {}).get("stage", "l0"), "failed",
                  f"{type(exc).__name__}: {exc}")
        _job_update(job_id, done=True, error=f"{type(exc).__name__}: {exc}",
                    traceback=traceback.format_exc()[-2000:])


def _run_l2(job_id: str, apk_path: Path, package: str | None,
            sha: str | None, navigator: str) -> None:
    """Detonate via the orchestrator subprocess, then fold into the spine.

    Runs live: every stage the orchestrator logs (isolation, install, frida
    attach, navigator start...) streams into the job's live feed as it
    happens (see ``_stream_subprocess``), and the /api/emulator/screenshot +
    /api/job/{id}/nav endpoints show the navigation as it happens. A stop
    request (SIGTERM, handled gracefully by orchestrator.py's
    DetonationStopped) is reported as its own outcome, not a failure.
    """
    if not package:
        _job_step(job_id, "l2", "skipped", "no package name (need L0 or a parseable manifest)")
        return
    nav = "genai" if navigator == "genai" else "droidbot"
    # Where the live navigation log will appear, so the UI can poll it.
    _job_update(job_id, l2_package=package, l2_active=True)
    _job_step(job_id, "l2", "running", f"launching sentinel30 · {nav} navigator")
    env = dict(os.environ, SENTINEL_MITM_BLOCK_UNKNOWN="1")
    cmd = [PYTHON, str(REPO_ROOT / "L2" / "sandbox" / "orchestrator.py"),
           str(apk_path), package, "--navigator", nav,
           "--droidbot-time", "90", "--time", "120"]
    outcome = _stream_subprocess(job_id, cmd, cwd=REPO_ROOT, env=env, timeout_s=600)
    _job_update(job_id, l2_active=False)

    if outcome == "stopped":
        _job_step(job_id, "l2", "stopped", "stopped by request")
        return

    # Fold the raw sandbox output into the spine, best-effort — a genuine
    # detonation crash still leaves behind whatever artifacts it managed to
    # write, and those are worth folding rather than discarding.
    folded = 0
    try:
        sys.path.insert(0, str(REPO_ROOT / "L1"))
        from L2 import l2_engine
        rep = l2_engine.process(sha)
        folded = len(rep.findings)
    except Exception as exc:  # noqa: BLE001
        _job_step(job_id, "l2", "done" if outcome == "ok" else "failed",
                  f"detonated; fold failed: {type(exc).__name__}")
        return
    # Surface a couple of headline behaviours for the step detail.
    nav_summary = _nav_summary(package)
    _job_step(job_id, "l2", "done" if outcome == "ok" else "failed",
              f"{folded} runtime findings · {nav_summary}")


def _run_l4(job_id: str, sha: str | None) -> None:
    if not sha:
        _job_step(job_id, "l4", "skipped", "no sha")
        return
    src = L1_ARTIFACTS / sha / "jadx_src"
    if not src.is_dir():
        _job_step(job_id, "l4", "skipped", "no jadx_src (run L1 first)")
        return
    _job_step(job_id, "l4", "running", "GenAI reasoning (LLM) — see live feed for per-class progress")
    cmd = [PYTHON, str(REPO_ROOT / "L4" / "deobfuscate.py"), sha,
           "--src", str(src), "--limit", "4", "--budget", "1.5"]
    outcome = _stream_subprocess(job_id, cmd, cwd=REPO_ROOT, timeout_s=600)
    if outcome == "stopped":
        _job_step(job_id, "l4", "stopped", "stopped by request")
        return
    # The last "N classes explained..." summary line the CLI prints, if any —
    # everything before it already streamed into the live feed.
    log_lines = (_JOBS.get(job_id, {}).get("log") or [])
    summary = next((l for l in reversed(log_lines) if "classes explained" in l), "")
    _job_step(job_id, "l4", "done" if outcome == "ok" else "failed", summary)


def _nav_summary(package: str) -> str:
    steps = _read_nav(package)
    if not steps:
        return "no navigation log"
    taken = sum(1 for s in steps if "action" in s)
    stop = next((s["summary"].get("stop_reason") for s in steps if "summary" in s), "?")
    return f"{taken} nav steps ({stop})"


def _read_nav(package: str | None) -> list[dict[str, Any]]:
    if not package:
        return []
    log = SANDBOX_ARTIFACTS / package / "genai_nav.jsonl"
    if not log.is_file():
        return []
    out: list[dict[str, Any]] = []
    try:
        for line in log.read_text().splitlines():
            line = line.strip()
            if line:
                out.append(json.loads(line))
    except (OSError, json.JSONDecodeError):
        pass
    return out


# ---------------------------------------------------------------------------
# APK catalogue
# ---------------------------------------------------------------------------

def _catalogue() -> list[dict[str, Any]]:
    """A curated, selectable set of on-disk APKs, labelled by kind."""
    out: list[dict[str, Any]] = []

    def add(path: Path, kind: str, note: str = "") -> None:
        try:
            if path.is_file() and path.stat().st_size > 0:
                out.append({
                    "path": str(path.resolve()),
                    "name": path.name,
                    "kind": kind,
                    "note": note,
                    "size_kb": path.stat().st_size // 1024,
                })
        except OSError:
            pass

    for p in sorted((REPO_ROOT / "testing_apps" / "good_apps").glob("*.apk")):
        add(p, "benign", "benign control")
    for p in sorted((REPO_ROOT / "testing_apps" / "vuln").glob("*.apk")):
        add(p, "vulnerable", "deliberately-vulnerable test app")
    # A few known, on-disk malware families (loose, unencrypted).
    known = {
        "xbot": ("malware", "XBot — dropper + screen-locker + SMS"),
        "mazar_bot": ("malware", "Mazar BOT — SMS/overlay/admin"),
        "krep_banking_malware": ("malware", "krep — banking, SMS+admin"),
        "triada": ("malware", "Triada — modular dropper"),
    }
    mroot = REPO_ROOT / "corpus" / "malware_raw" / "android-malware"
    for fam, (kind, note) in known.items():
        d = mroot / fam
        if d.is_dir():
            for p in sorted(d.iterdir())[:1]:
                if p.is_file():
                    add(p, kind, note)
    return out


def _validate_selected(path_str: str) -> Path:
    p = Path(path_str).resolve()
    if not any(str(p).startswith(str(root) + os.sep) or p == root
               for root in ALLOWED_APK_ROOTS):
        raise HTTPException(400, "selected path is outside the allowed roots")
    if not p.is_file():
        raise HTTPException(404, "selected APK not found")
    return p


def _start_job(apk_path: Path, layers: list[str], navigator: str,
               filename: str, job_id: str | None = None) -> str:
    layers = [l for l in ALL_LAYERS if l in set(layers)]  # normalise + order
    job_id = job_id or uuid.uuid4().hex[:12]
    _JOBS[job_id] = {
        "steps": [], "done": False, "stage": "queued",
        "filename": filename, "layers": layers, "navigator": navigator,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "log": [], "stop_requested": False,
    }
    threading.Thread(target=_run_job,
                     args=(job_id, apk_path, layers, navigator),
                     daemon=True).start()
    return job_id


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
def dashboard() -> str:
    index = WEB_DIR / "index.html"
    if not index.is_file():
        return "<h1>APK Sentinel</h1><p>Dashboard asset missing.</p>"
    return index.read_text()


@app.get("/api/apks")
def apks() -> list[dict[str, Any]]:
    return _catalogue()


@app.post("/api/run")
def run(payload: dict[str, Any] = Body(...)) -> JSONResponse:
    """Start a job on an APK already on disk (chosen from /api/apks)."""
    apk_path = _validate_selected(str(payload.get("apk_path", "")))
    layers = payload.get("layers") or ["l0", "l1", "l5"]
    navigator = payload.get("navigator") or "genai"
    job_id = _start_job(apk_path, list(layers), navigator, apk_path.name)
    return JSONResponse({"job_id": job_id})


@app.post("/api/analyze")
async def analyze(file: UploadFile = File(...),
                  layers: str = "l0,l1,l3,l5",
                  navigator: str = "genai") -> JSONResponse:
    """Upload an APK and run the chosen layers on it."""
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    job_id = uuid.uuid4().hex[:12]
    dest = UPLOAD_DIR / f"{job_id}.apk"
    size = 0
    with dest.open("wb") as fh:
        while chunk := await file.read(1 << 20):
            size += len(chunk)
            if size > MAX_UPLOAD_BYTES:
                fh.close()
                dest.unlink(missing_ok=True)
                raise HTTPException(413, f"upload exceeds {MAX_UPLOAD_BYTES} bytes")
            fh.write(chunk)
    with dest.open("rb") as fh:
        if fh.read(4) != APK_MAGIC:
            dest.unlink(missing_ok=True)
            raise HTTPException(400, "not a ZIP/APK (magic bytes do not match)")
    dest.chmod(0o600)
    layer_list = [s.strip() for s in layers.split(",") if s.strip()]
    _start_job(dest, layer_list, navigator, file.filename or "upload.apk", job_id=job_id)
    return JSONResponse({"job_id": job_id})


@app.get("/api/job/{job_id}")
def job_status(job_id: str) -> dict[str, Any]:
    job = _JOBS.get(job_id)
    if job is None:
        raise HTTPException(404, "unknown job")
    # The live feed can grow to thousands of lines; a client polling this
    # every second for pipeline-step state shouldn't re-download all of it
    # every time. Fetch it incrementally from /api/job/{id}/log instead.
    return {k: v for k, v in job.items() if k != "log"}


@app.get("/api/job/{job_id}/log")
def job_log(job_id: str, since: int = 0) -> dict[str, Any]:
    """Incremental live feed: new lines since the caller's last ``next``."""
    job = _JOBS.get(job_id)
    if job is None:
        raise HTTPException(404, "unknown job")
    lines = job.get("log") or []
    since = max(0, since)
    return {"lines": lines[since:], "next": len(lines), "done": bool(job.get("done"))}


@app.post("/api/job/{job_id}/stop")
def stop_job(job_id: str) -> dict[str, Any]:
    """Request a running job stop as soon as safely possible.

    Marks ``stop_requested`` (checked between pipeline stages in
    ``_run_job``) and, if a subprocess is currently live (L2's detonation or
    L4's reasoning), sends it SIGTERM. For L2 this is caught by
    ``orchestrator.py``'s ``DetonationStopped`` handler, which runs its
    normal cleanup (isolation restore, mitmproxy/DroidBot teardown) rather
    than leaving the sandbox half torn-down — see that module's docstring.
    """
    job = _JOBS.get(job_id)
    if job is None:
        raise HTTPException(404, "unknown job")
    if job.get("done"):
        return {"stopping": False, "reason": "job already finished"}
    _job_update(job_id, stop_requested=True)
    proc = _JOB_PROCS.get(job_id)
    if proc is not None and proc.poll() is None:
        try:
            proc.terminate()
        except OSError:
            pass
        _job_log(job_id, "WARNING api: stop requested -- signalling the running subprocess")
    else:
        _job_log(job_id, "WARNING api: stop requested -- will stop before the next layer")
    return {"stopping": True}


@app.get("/api/job/{job_id}/nav")
def job_nav(job_id: str) -> dict[str, Any]:
    """Live navigation step log for a job's L2 phase."""
    job = _JOBS.get(job_id)
    if job is None:
        raise HTTPException(404, "unknown job")
    return {"active": bool(job.get("l2_active")),
            "package": job.get("l2_package"),
            "steps": _read_nav(job.get("l2_package"))}


@app.get("/api/emulator/screenshot")
def emulator_screenshot() -> Response:
    """A live PNG frame of the running emulator, or 204 if none is up."""
    adb = _find_adb()
    if not adb:
        return Response(status_code=204)
    try:
        proc = subprocess.run(
            [adb, "-s", EMULATOR_SERIAL, "exec-out", "screencap", "-p"],
            capture_output=True, timeout=10)
    except (subprocess.TimeoutExpired, OSError):
        return Response(status_code=204)
    if proc.returncode != 0 or not proc.stdout or proc.stdout[:4] != b"\x89PNG":
        return Response(status_code=204)
    return Response(content=proc.stdout, media_type="image/png",
                    headers={"Cache-Control": "no-store"})


@app.get("/api/samples")
def samples(limit: int = 100) -> list[dict[str, Any]]:
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
            "ai_delta": l5.get("ai_delta") or 0,
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


@app.get("/api/score/{sha256}")
def score(sha256: str, ai: int = 0) -> dict[str, Any]:
    """Re-score a sample with the L4 (AI) contribution on (``ai=1``) or off.

    A *view-time* recompute only — it never overwrites the persisted verdict,
    which stays AI-free by design. ``ai_available`` reports whether this sample
    even has an L4 layer to contribute; if not, the toggle has nothing to add.
    """
    if not spine_exists(sha256):
        raise HTTPException(404, "no evidence record for that hash")
    from L5.score import load_policy, score_spine
    doc = spine.load_spine(sha256)
    l4 = (doc.get("layers", {}).get("l4") or {}).get("summary") or {}
    ai_available = l4.get("max_score") is not None
    policy = load_policy()
    result = score_spine(doc, policy, include_ai=bool(ai) and ai_available)
    return {
        "sha256": sha256,
        "score": result.score,
        "band": result.band,
        "ai_delta": result.ai_delta,
        "ai_available": ai_available,
        "unsupported": result.unsupported,
    }


@app.get("/api/report/{sha256}", response_class=HTMLResponse)
def report(sha256: str) -> str:
    if not spine_exists(sha256):
        raise HTTPException(404, "no evidence record for that hash")
    doc = spine.load_spine(sha256)
    return report_mod.render(doc)


@app.get("/api/recommend/{sha256}")
def get_recommendation(sha256: str) -> dict[str, Any]:
    """Read a precomputed recommendation.json artifact -- does not run
    L6/recommend.py itself. Same read-a-precomputed-artifact shape as
    /api/export. Use POST /api/recommend/{sha256}/run to actually generate
    one (button-triggered from the UI, or via 'l6' in a pipeline run's
    layers)."""
    path = REPO_ROOT / "L6" / "artifacts" / sha256 / "recommendation.json"
    if not path.is_file():
        raise HTTPException(404, "no recommendation for that hash yet -- "
                                  "POST /api/recommend/{sha256}/run to generate one")
    return json.loads(path.read_text())


@app.post("/api/recommend/{sha256}/run")
def run_recommendation(sha256: str) -> dict[str, Any]:
    """Generate a recommendation for an already-scored sample, on demand.

    Synchronous, not a queued job: this is one small-context LLM call
    (~$0.04 measured, see docs/L6_RECOMMEND_EXPLAINER.md), the same
    "cheap enough to compute inline" shape as /api/score's view-time
    recompute -- no need for the job-polling machinery L2/L4 use for
    multi-minute work. Lets a sample scored *before* this feature existed
    (or one where "l6" wasn't ticked in the original run) get a
    recommendation later, without re-running L0-L5.
    """
    if not spine_exists(sha256):
        raise HTTPException(404, "no evidence record for that hash")
    from L4.provider import CostLedger, ProviderError, get_provider
    from L5.score import load_policy, score_spine
    from L6.recommend import recommend, write_layer as write_recommend_layer

    doc = spine.load_spine(sha256)
    policy = load_policy()
    score = score_spine(doc, policy, include_ai=True)
    ledger = CostLedger(cap_usd=0.25)
    try:
        provider = get_provider("aicredits", ledger=ledger)
        rec = recommend(doc, score, provider)
    except ProviderError as exc:
        raise HTTPException(502, f"recommendation provider unavailable: {exc}")
    write_recommend_layer(rec)
    return rec.to_dict()


@app.get("/api/export/{sha256}/{fmt}")
def export(sha256: str, fmt: str):
    if fmt not in export_mod.FORMATS:
        raise HTTPException(400, f"format must be one of {export_mod.FORMATS}")
    if not spine_exists(sha256):
        raise HTTPException(404, "no evidence record for that hash")
    doc = spine.load_spine(sha256)
    outputs = export_mod.export_all(export_mod.gather(doc), [fmt])
    if not outputs:
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
    adb = _find_adb()
    emulator_up = False
    if adb:
        try:
            out = subprocess.run([adb, "devices"], capture_output=True,
                                 text=True, timeout=5).stdout
            emulator_up = any("emulator-" in l and "device" in l
                              for l in out.splitlines()[1:])
        except (subprocess.TimeoutExpired, OSError):
            pass
    return {
        "spines": sum(1 for _ in spine.iter_spines()),
        "schema": spine.SCHEMA_VERSION,
        "weights": weights,
        "jadx": bool(os.environ.get("JADX_DIR")),
        "emulator_up": emulator_up,
    }
