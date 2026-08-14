"""Corpus runner contract tests.

Every fixture here is synthetic. The properties under test are exactly the ones
whose failure mode is *silence* — a sample skipped for the wrong reason, or a
resume key that collides — because those cost a multi-hour run before anyone
notices the count was wrong.

Run:  ./env/bin/python -m pytest tests/test_corpus_run.py -q
"""

from __future__ import annotations

import json
import sys
import zipfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "L0"))
sys.path.insert(0, str(REPO_ROOT / "tools"))

import corpus_run  # noqa: E402
import harvest_dataset  # noqa: E402


def make_apk(path: Path, *, manifest: bool = True, dex: bool = True) -> Path:
    """A minimal file that satisfies (or deliberately fails) the APK test."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w") as zf:
        if manifest:
            zf.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00binaryxml")
        if dex:
            zf.writestr("classes.dex", b"dex\n035\x00stub")
        zf.writestr("res/values/strings.xml", "<resources/>")
    return path


def make_archive(path: Path, members: dict[str, bytes]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w") as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return path


# ---------------------------------------------------------------------------
# Acceptance — the extension trap runs in both directions
# ---------------------------------------------------------------------------

def test_accepts_a_real_apk(tmp_path):
    assert corpus_run.classify(make_apk(tmp_path / "a.apk")) == (True, "ok")


def test_accepts_an_apk_with_no_extension(tmp_path):
    """42% of corpus members are extensionless; content is the only authority."""
    accepted, _ = corpus_run.classify(make_apk(tmp_path / "b5ccbfd13078a341"))
    assert accepted


def test_rejects_apk_named_file_that_is_not_an_archive(tmp_path):
    """4 loose corpus files are `.apk`-named but not ZIP-magic."""
    p = tmp_path / "lying.apk"
    p.write_bytes(b"\x7fELF not an apk at all")
    assert corpus_run.classify(p) == (False, "not_zip_magic")


def test_rejects_archive_without_manifest(tmp_path):
    accepted, reason = corpus_run.classify(make_apk(tmp_path / "c.apk", manifest=False))
    assert (accepted, reason) == (False, "no_manifest")


def test_rejects_archive_without_dex(tmp_path):
    accepted, reason = corpus_run.classify(make_apk(tmp_path / "d.apk", dex=False))
    assert (accepted, reason) == (False, "no_dex")


def test_rejection_always_carries_a_reason(tmp_path):
    """A silent skip is how 45% of a corpus goes missing unnoticed."""
    for factory in (lambda p: make_apk(p, manifest=False),
                    lambda p: make_apk(p, dex=False)):
        accepted, reason = corpus_run.classify(factory(tmp_path / "x"))
        assert not accepted and reason


# ---------------------------------------------------------------------------
# Enumeration
# ---------------------------------------------------------------------------

def test_zip_members_are_enumerated_without_reading_them(tmp_path):
    make_archive(tmp_path / "fam" / "a.zip", {
        "one.apk": b"PK\x03\x04payload",
        "two_no_extension": b"PK\x03\x04payload",
        "empty": b"",
    })
    samples = list(corpus_run.iter_zip_members(tmp_path))
    names = {s.member for s in samples}
    assert names == {"one.apk", "two_no_extension"}, "empty members are not candidates"
    assert all(s.kind == "zip_member" for s in samples)


def test_loose_enumeration_is_by_magic_not_extension(tmp_path):
    make_apk(tmp_path / "named.apk")
    make_apk(tmp_path / "unnamed")
    make_apk(tmp_path / "thing.jar")
    (tmp_path / "notes.md").write_text("# not a sample")
    make_archive(tmp_path / "archive.zip", {"x.apk": b"PK\x03\x04"})

    found = {s.path.name for s in corpus_run.iter_loose(tmp_path)}
    assert found == {"named.apk", "unnamed", "thing.jar"}
    assert "archive.zip" not in found, "archives are handled by the zip iterator"
    assert "notes.md" not in found


def test_directories_are_not_candidates(tmp_path):
    make_archive(tmp_path / "a.zip", {"dir/": b"", "dir/f.apk": b"PK\x03\x04x"})
    members = [s.member for s in corpus_run.iter_zip_members(tmp_path)]
    assert members == ["dir/f.apk"]


# ---------------------------------------------------------------------------
# Resume keys — CRC-32 is unusable (T13), so the key must not depend on it
# ---------------------------------------------------------------------------

def test_resume_key_does_not_depend_on_crc(tmp_path):
    """All 148 AES members are AE-2, whose spec mandates CRC-32 = 0."""
    make_archive(tmp_path / "a.zip", {"m1": b"PK\x03\x04aaa", "m2": b"PK\x03\x04bbb"})
    keys = [s.key for s in corpus_run.iter_zip_members(tmp_path)]
    assert len(set(keys)) == 2
    assert all("crc" not in k for k in keys)


def test_resume_keys_are_unique_and_stable(tmp_path):
    make_archive(tmp_path / "x" / "a.zip", {"same_name": b"PK\x03\x04a"})
    make_archive(tmp_path / "y" / "a.zip", {"same_name": b"PK\x03\x04b"})
    make_apk(tmp_path / "loose.apk")

    first = [s.key for s in corpus_run.iter_zip_members(tmp_path)] + \
            [s.key for s in corpus_run.iter_loose(tmp_path)]
    second = [s.key for s in corpus_run.iter_zip_members(tmp_path)] + \
             [s.key for s in corpus_run.iter_loose(tmp_path)]
    assert first == second, "keys must be stable across enumerations"
    assert len(set(first)) == len(first), "same member name in two archives must not collide"


def test_index_survives_a_crash_mid_write(tmp_path):
    path = tmp_path / "run_index.json"
    corpus_run.save_index(path, {"a": {"status": "ok"}})
    corpus_run.save_index(path, {"a": {"status": "ok"}, "b": {"status": "ok"}})
    assert set(json.loads(path.read_text())) == {"a", "b"}
    assert not list(tmp_path.glob("*.tmp")), "no temp file left behind"


def test_unreadable_index_does_not_lose_the_corpus(tmp_path):
    path = tmp_path / "run_index.json"
    path.write_text("{ truncated")
    assert corpus_run.load_index(path) == {}


# ---------------------------------------------------------------------------
# Extraction safety
# ---------------------------------------------------------------------------

def test_materialise_extracts_exactly_one_member(tmp_path):
    """`extractall` on a corpus archive puts live malware on disk in bulk."""
    archive = make_archive(tmp_path / "a.zip", {
        "wanted": b"PK\x03\x04wanted-bytes",
        "unwanted": b"PK\x03\x04unwanted-bytes",
    })
    sample = next(s for s in corpus_run.iter_zip_members(tmp_path) if s.member == "wanted")
    work = tmp_path / "work"
    out = corpus_run.materialise(sample, work)
    assert out.read_bytes() == b"PK\x03\x04wanted-bytes"
    assert [p.name for p in work.iterdir()] == ["sample.apk"], "only one member on disk"


def test_loose_samples_are_analysed_in_place_never_copied(tmp_path):
    """They are the corpus at rest, not an extraction — copying 0.69 GB is waste
    and deleting them would destroy the corpus."""
    original = make_apk(tmp_path / "loose.apk")
    sample = next(corpus_run.iter_loose(tmp_path))
    work = tmp_path / "work"
    assert corpus_run.materialise(sample, work) == original
    assert not work.exists(), "no work directory is created for a loose sample"


def test_open_encrypted_reads_a_password_protected_archive(tmp_path):
    import pyzipper

    path = tmp_path / "enc.zip"
    with pyzipper.AESZipFile(path, "w", encryption=pyzipper.WZ_AES) as zf:
        zf.setpassword(b"infected")
        zf.writestr("member", b"PK\x03\x04secret")
    with harvest_dataset.open_encrypted(path) as zf:
        assert zf.read("member") == b"PK\x03\x04secret"


def test_open_encrypted_still_reads_a_plain_archive(tmp_path):
    path = make_archive(tmp_path / "plain.zip", {"member": b"PK\x03\x04open"})
    with harvest_dataset.open_encrypted(path) as zf:
        assert zf.read("member") == b"PK\x03\x04open"


def test_aes_members_really_do_have_zero_crc(tmp_path):
    """The measurement behind T13, pinned so the resume key is never 'improved'
    back onto CRC-32."""
    import pyzipper

    path = tmp_path / "enc.zip"
    with pyzipper.AESZipFile(path, "w", encryption=pyzipper.WZ_AES) as zf:
        zf.setpassword(b"infected")
        zf.writestr("member", b"some content with a real crc")
    with zipfile.ZipFile(path) as zf:
        info = zf.infolist()[0]
    assert info.compress_type == 99
    assert info.CRC == 0


# ---------------------------------------------------------------------------
# Disk floors
#
# A run writes to two filesystems with wildly different loads: L1's artifacts
# root takes jadx's churn, the repo takes ~50 KB of spine and L0 evidence per
# sample. One floor covering both was wrong in both directions — it halted a
# run over the repo's 8 GB while the filesystem doing the actual writing had
# 255 GB free and was never looked at.
# ---------------------------------------------------------------------------

def test_heavy_floor_applies_to_the_l1_root_not_the_repo(monkeypatch, tmp_path):
    heavy = tmp_path / "l1"
    heavy.mkdir()

    def fake_usage(path):
        # Heavy root nearly full, repo roomy.
        free = 1 * 2**30 if str(path).startswith(str(heavy)) else 500 * 2**30
        return type("U", (), {"free": free, "total": 900 * 2**30 + len(str(path))})()

    monkeypatch.setattr(corpus_run.shutil, "disk_usage", fake_usage)
    with pytest.raises(corpus_run.DiskExhausted) as exc:
        corpus_run.check_disk(8.0, heavy)
    assert "L1 artifacts" in str(exc.value)


def test_repo_keeps_its_own_floor_even_when_the_heavy_root_is_empty(monkeypatch, tmp_path):
    heavy = tmp_path / "l1"
    heavy.mkdir()

    def fake_usage(path):
        free = 500 * 2**30 if str(path).startswith(str(heavy)) else 1 * 2**30
        return type("U", (), {"free": free, "total": 900 * 2**30 + len(str(path))})()

    monkeypatch.setattr(corpus_run.shutil, "disk_usage", fake_usage)
    with pytest.raises(corpus_run.DiskExhausted) as exc:
        corpus_run.check_disk(8.0, heavy)
    assert "repo" in str(exc.value)


def test_both_roomy_passes(monkeypatch, tmp_path):
    heavy = tmp_path / "l1"
    heavy.mkdir()
    monkeypatch.setattr(
        corpus_run.shutil, "disk_usage",
        lambda path: type("U", (), {"free": 500 * 2**30,
                                    "total": 900 * 2**30 + len(str(path))})(),
    )
    corpus_run.check_disk(8.0, heavy)  # must not raise
