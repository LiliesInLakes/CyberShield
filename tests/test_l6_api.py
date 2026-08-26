"""L6 service contract.

The security-relevant assertions here are the upload guards: this endpoint
accepts Android malware by design, so "rejects a non-APK", "rejects an
oversized upload" and "never marks an upload executable" are properties, not
conveniences.
"""

from __future__ import annotations

import io
import sys
import zipfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
for p in (str(REPO_ROOT), str(REPO_ROOT / "L1")):
    if p not in sys.path:
        sys.path.insert(0, p)

fastapi_testclient = pytest.importorskip("fastapi.testclient")


@pytest.fixture(scope="module")
def client():
    from L6.api import app
    return fastapi_testclient.TestClient(app)


def _minimal_apk() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("AndroidManifest.xml", "not really binary xml")
        zf.writestr("classes.dex", "dex\n035\x00")
    return buf.getvalue()


# --------------------------------------------------------------------------
# Read endpoints
# --------------------------------------------------------------------------

def test_health_reports_the_weights_support_stamp(client):
    """The dashboard renders its banner from this; if it silently defaulted to
    'supported' the UI would present unusable scores as evidence."""
    body = client.get("/api/health").json()
    assert "spines" in body and "weights" in body
    assert "supported" in body["weights"] or "error" in body["weights"]


def test_dashboard_is_self_contained(client):
    """It must open on an air-gapped workstation."""
    html = client.get("/").text
    assert "<title>APK Sentinel</title>" in html
    assert "<script src=" not in html
    assert "cdn." not in html
    assert "http://" not in html.replace("http://127.0.0.1", "")


def test_samples_sorts_scored_first_and_unscored_last(client):
    rows = client.get("/api/samples?limit=50").json()
    scores = [r["score"] for r in rows]
    scored = [s for s in scores if s is not None]
    assert scored == sorted(scored, reverse=True)
    if None in scores:
        assert scores.index(None) >= len(scored)


def test_unknown_hash_is_404_everywhere(client):
    missing = "0" * 64
    for path in (f"/api/sample/{missing}", f"/api/report/{missing}",
                 f"/api/export/{missing}/stix"):
        assert client.get(path).status_code == 404, path


def test_export_rejects_an_unknown_format(client):
    rows = client.get("/api/samples?limit=1").json()
    if not rows:
        pytest.skip("no spines available")
    assert client.get(f"/api/export/{rows[0]['sha256']}/docx").status_code == 400


# --------------------------------------------------------------------------
# Upload guards
# --------------------------------------------------------------------------

def test_non_apk_upload_is_rejected_by_magic_not_extension(client):
    """45% of real corpus members are extensionless; a .apk name proves nothing."""
    r = client.post("/api/analyze",
                    files={"file": ("evil.apk", b"not an apk at all",
                                    "application/octet-stream")})
    assert r.status_code == 400
    assert "magic" in r.json()["detail"]


def test_oversized_upload_is_refused(client, monkeypatch):
    import L6.api as api
    monkeypatch.setattr(api, "MAX_UPLOAD_BYTES", 512)
    payload = _minimal_apk() + b"\x00" * 4096
    r = client.post("/api/analyze",
                    files={"file": ("big.apk", payload, "application/octet-stream")})
    assert r.status_code == 413


def test_accepted_upload_is_stored_unexecutable(client, tmp_path, monkeypatch):
    """Nothing this service writes may ever be runnable.

    UPLOAD_DIR is redirected to a temp path: the default is shared with any
    uvicorn instance the developer happens to have running, and this assertion
    is about the handler's behaviour, not about whatever else is on disk.
    """
    import L6.api as api
    monkeypatch.setattr(api, "UPLOAD_DIR", tmp_path / "uploads")
    r = client.post("/api/analyze",
                    files={"file": ("t.apk", _minimal_apk(),
                                    "application/octet-stream")})
    assert r.status_code == 200
    path = (tmp_path / "uploads") / f"{r.json()['job_id']}.apk"
    assert path.is_file()
    assert path.stat().st_mode & 0o111 == 0, "upload must not be executable"


def test_unknown_job_is_404(client):
    assert client.get("/api/job/deadbeef").status_code == 404
