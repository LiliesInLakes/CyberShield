from __future__ import annotations

import json
import tempfile
from pathlib import Path

from pipeline import load_or_create_evidence, save_evidence, compute_sha256


def test_compute_sha256():
    path = Path(tempfile.mktemp(suffix=".apk"))
    try:
        path.write_bytes(b"hello" * 1000)
        h = compute_sha256(path)
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)
    finally:
        path.unlink(missing_ok=True)


def test_load_or_create_new(tmp_path):
    apk = tmp_path / "test.apk"
    apk.write_text("dummy")
    evidence = load_or_create_evidence(apk, tmp_path)
    assert evidence["schema_version"] == "apk-sentinel-0.1"
    assert evidence["l0"]["status"] == "pending"
    assert evidence["l1"]["status"] == "pending"
    assert evidence["l2"]["status"] == "pending"


def test_load_or_create_existing(tmp_path):
    apk = tmp_path / "test.apk"
    apk.write_text("dummy")
    sha = compute_sha256(apk)
    ev_dir = tmp_path / sha
    ev_dir.mkdir(parents=True)
    ev_path = ev_dir / "evidence.json"
    ev_path.write_text(json.dumps({"custom": True}))
    evidence = load_or_create_evidence(apk, tmp_path)
    assert evidence["custom"] is True


def test_cache_no_evidence(tmp_path):
    from cache import cached_analysis, cached_l1_analysis
    assert cached_analysis(tmp_path, "abcdef", "l0") is None
    assert cached_l1_analysis(tmp_path, "abcdef") is None


def test_cache_hit(tmp_path):
    from cache import cached_analysis
    sha = "deadbeef" * 4
    ev_dir = tmp_path / sha
    ev_dir.mkdir(parents=True)
    ev = {"l0": {"status": "complete", "fingerprint": {"sha256": sha}}}
    (ev_dir / "evidence.json").write_text(__import__("json").dumps(ev))
    result = cached_analysis(tmp_path, sha, "l0")
    assert result is not None
    assert result["status"] == "complete"


def test_cache_l1_hit(tmp_path):
    from cache import cached_l1_analysis
    sha = "cafebabe" * 4
    ev_dir = tmp_path / sha
    ev_dir.mkdir(parents=True)
    analysis = {"engine": "jadx+yara", "finding_count": 5}
    (ev_dir / "analysis.json").write_text(__import__("json").dumps(analysis))
    result = cached_l1_analysis(tmp_path, sha)
    assert result is not None
    assert result["finding_count"] == 5


def test_save_evidence(tmp_path):
    apk = tmp_path / "test.apk"
    apk.write_text("data")
    sha = compute_sha256(apk)
    evidence = {"test": True}
    out = save_evidence(evidence, tmp_path, sha)
    assert out.exists()
    loaded = json.loads(out.read_text())
    assert loaded["test"] is True
    assert "generated_at" in loaded
