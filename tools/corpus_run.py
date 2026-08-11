"""Batch L0 + L1 over the malware corpus, safely and resumably.

    source source_env.sh
    $SENTINEL_PYTHON tools/corpus_run.py --dry-run
    $SENTINEL_PYTHON tools/corpus_run.py --limit 20
    $SENTINEL_PYTHON tools/corpus_run.py                # the whole corpus

Design notes live in ``docs/plans/phase_a3_amendment.md``. The five that matter
while reading this file:

**Nothing is ever executed.** Sample bytes are touched only by ``zipfile`` /
``pyzipper``, ``androguard.APK()``, YARA, and jadx running under the JVM. No
file is made executable and no sample is invoked. This is a property of the
code, not a runtime check.

**One member at a time, never ``extractall``.** A zip member is streamed to its
own work directory, analysed, and deleted in a ``finally`` belonging to the
function that created the directory. Loose APKs are analysed **in place** —
they are the corpus at rest, not an extraction, so they are never copied and
never deleted.

**The disk constraint is decompiled sources, not samples.** jadx produces ~112 MB
per sample against a ~2 MB average APK; over 699 samples that is ~78 GB against
16 GB free. ``--keep-decompiled none`` (the default) reclaims ``jadx_src`` as
soon as the findings are durable. The samples themselves were never the problem.

**Resume never decrypts anything.** The index key comes from the zip central
directory (archive path + member name), which is readable without the password.
CRC-32 is unusable: all 148 AES members are WinZip AE-2, whose spec mandates
CRC-32 = 0.

**Extension proves nothing, in either direction.** 42% of members are
extensionless; some ``.apk``-named files are not archives at all. Acceptance is
ZIP magic + ``AndroidManifest.xml`` + at least one ``classes*.dex``, and every
rejection is recorded with a reason rather than skipped in silence.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
import time
import traceback
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

REPO_ROOT = Path(__file__).resolve().parent.parent
for _p in (str(REPO_ROOT), str(REPO_ROOT / "L0"), str(REPO_ROOT / "L1")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

CORPUS = REPO_ROOT / "corpus"
RAW = CORPUS / "malware_raw"
WORK = CORPUS / "_work"
RUNS = CORPUS / "runs"
INDEX_PATH = CORPUS / "run_index.json"

APK_MAGIC = b"PK\x03\x04"


# ---------------------------------------------------------------------------
# Sample sources
# ---------------------------------------------------------------------------

@dataclass
class Sample:
    """One candidate APK, from either population."""

    key: str                      # stable resume key; never requires decryption
    kind: str                     # "zip_member" | "loose"
    display: str
    archive: Path | None = None
    member: str | None = None
    path: Path | None = None      # loose samples only
    size: int = 0
    compress_size: int = 0


def iter_zip_members(raw: Path) -> Iterator[Sample]:
    """Every member of every archive, read from central directories only."""
    for archive in sorted(raw.rglob("*.zip")):
        rel = archive.relative_to(raw)
        try:
            with zipfile.ZipFile(archive) as zf:
                infos = zf.infolist()
        except Exception as exc:  # noqa: BLE001
            print(f"[corpus] unreadable archive {rel}: {exc}", file=sys.stderr)
            continue
        for info in infos:
            if info.is_dir() or info.file_size == 0:
                continue
            yield Sample(
                key=f"zip::{rel}::{info.filename}",
                kind="zip_member",
                display=f"{rel}!{Path(info.filename).name}",
                archive=archive,
                member=info.filename,
                size=info.file_size,
                compress_size=info.compress_size,
            )


def iter_loose(raw: Path) -> Iterator[Sample]:
    """Loose files under the corpus that are not archives we already iterate.

    The `android-malware` tree ships unencrypted samples, 32 of which are not
    named `.apk` at all. Filtering by extension here would drop them silently.
    """
    for path in sorted(raw.rglob("*")):
        if not path.is_file() or path.suffix.lower() == ".zip":
            continue
        try:
            with path.open("rb") as fh:
                if fh.read(4) != APK_MAGIC:
                    continue
        except OSError:
            continue
        rel = path.relative_to(raw)
        yield Sample(
            key=f"loose::{rel}",
            kind="loose",
            display=str(rel),
            path=path,
            size=path.stat().st_size,
        )


def classify(path: Path) -> tuple[bool, str]:
    """Is this really an APK? Returns (accepted, reason)."""
    try:
        with path.open("rb") as fh:
            if fh.read(4) != APK_MAGIC:
                return False, "not_zip_magic"
    except OSError as exc:
        return False, f"unreadable:{type(exc).__name__}"
    try:
        with zipfile.ZipFile(path) as zf:
            names = zf.namelist()
    except Exception as exc:  # noqa: BLE001
        return False, f"bad_zip:{type(exc).__name__}"
    if "AndroidManifest.xml" not in names:
        return False, "no_manifest"
    if not any(n.startswith("classes") and n.endswith(".dex") for n in names):
        return False, "no_dex"
    return True, "ok"


# ---------------------------------------------------------------------------
# Run index (resume) and log
# ---------------------------------------------------------------------------

def load_index(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError:
        print(f"[corpus] run index unreadable, starting fresh: {path}", file=sys.stderr)
        return {}


def save_index(path: Path, index: dict[str, Any]) -> None:
    """Atomic: a SIGKILL mid-write must not cost the whole run's resume state."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(index, indent=2, sort_keys=True))
    os.replace(tmp, path)


class RunLog:
    """Append-only JSONL, flushed per record so a crash keeps everything prior."""

    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self._fh = path.open("a")

    def write(self, record: dict[str, Any]) -> None:
        self._fh.write(json.dumps(record) + "\n")
        self._fh.flush()
        os.fsync(self._fh.fileno())

    def close(self) -> None:
        self._fh.close()


# ---------------------------------------------------------------------------
# Disk
# ---------------------------------------------------------------------------

def free_gb(path: Path) -> float:
    usage = shutil.disk_usage(path)
    return usage.free / 2**30


class DiskExhausted(RuntimeError):
    pass


def check_disk(min_free_gb: float) -> None:
    free = free_gb(REPO_ROOT)
    if free < min_free_gb:
        raise DiskExhausted(
            f"only {free:.1f} GB free, below --min-free-gb {min_free_gb}. "
            "Re-run to resume once space is reclaimed."
        )


# ---------------------------------------------------------------------------
# Analysis of one sample
# ---------------------------------------------------------------------------

def materialise(sample: Sample, work_dir: Path) -> Path:
    """Put exactly one sample on disk, streamed — never `extractall`."""
    if sample.kind == "loose":
        return sample.path  # already at rest on disk; do not copy
    work_dir.mkdir(parents=True, exist_ok=True)
    target = work_dir / "sample.apk"
    import harvest_dataset

    with harvest_dataset.open_encrypted(sample.archive) as zf:
        with zf.open(sample.member) as src, target.open("wb") as dst:
            shutil.copyfileobj(src, dst, length=1 << 20)
    return target


def analyse_one(sample: Sample, args: argparse.Namespace) -> dict[str, Any]:
    """L0 then L1 for a single sample. Always cleans up after itself."""
    import spine
    from ingest import run_l0
    import l1 as l1_module

    record: dict[str, Any] = {
        "key": sample.key,
        "kind": sample.kind,
        "display": sample.display,
        "size": sample.size,
        "started_at": datetime.now(timezone.utc).isoformat(),
    }
    started = time.monotonic()
    # sha1, not hash(): str.__hash__ is salted per process (PYTHONHASHSEED), so
    # two runs pick different work dirs for the same sample and two concurrent
    # runs can collide on one. A content-derived name is stable and unique.
    work_dir = WORK / f"s{hashlib.sha1(sample.key.encode()).hexdigest()[:12]}"
    apk_path: Path | None = None
    sha: str | None = None

    try:
        if sample.member and sample.member.lower().endswith(".zip"):
            record.update(status="skipped", reason="nested_zip")
            return record

        apk_path = materialise(sample, work_dir)
        accepted, reason = classify(apk_path)
        if not accepted:
            record.update(status="skipped", reason=reason)
            return record

        l0 = run_l0(apk_path)
        sha = l0["fingerprint"]["sha256"]
        imp = l0.get("impersonation", {})
        record.update(
            sha256=sha,
            package=l0["manifest"].get("package_name"),
            app_label=l0["manifest"].get("app_label"),
            l0_verdict=imp.get("verdict"),
            l0_entity=imp.get("claimed_entity"),
            l0_findings=len(imp.get("findings", [])),
        )

        try:
            report = l1_module.dispatch(apk_path)
            record.update(
                l1_findings=len(report.findings),
                l1_engine=report.engine,
                l1_categories=report.summary.get("categories", []),
                decompiled_files=report.summary.get("decompiled_files", 0),
            )
            record["status"] = "ok"
        except Exception as exc:  # noqa: BLE001
            # L0 succeeded and is already in the spine; L1 failing is a partial
            # result, not a lost sample. `dispatch` has recorded the failure.
            record.update(status="l1_failed",
                          error=f"{type(exc).__name__}: {str(exc)[:200]}")

        if sha:
            doc = spine.load_spine(sha)
            record["spine_findings"] = doc.get("counts", {}).get("findings", 0)
            record["malware_category"] = doc.get("counts", {}).get("malware_category", 0)
            record["analysis_gaps"] = doc.get("analysis_gaps", [])

    except Exception as exc:  # noqa: BLE001
        record.update(status="error", error=f"{type(exc).__name__}: {str(exc)[:200]}")
        if args.traceback:
            traceback.print_exc()
    finally:
        # Extracted samples never outlive their analysis. Loose samples are the
        # corpus itself and are left exactly as found.
        keep = (sample.kind == "zip_member"
                and args.keep_sources == "failed"
                and record.get("status") not in ("ok", "skipped"))
        if keep:
            record["kept_source"] = str(work_dir)
        else:
            shutil.rmtree(work_dir, ignore_errors=True)

        # The actual disk constraint: reclaim decompiled sources once findings
        # are durable in analysis.json and the spine.
        if sha and args.keep_decompiled != "all":
            keep_src = (args.keep_decompiled == "failed"
                        and record.get("status") not in ("ok", "skipped"))
            if not keep_src:
                shutil.rmtree(REPO_ROOT / "L1" / "artifacts" / sha / "jadx_src",
                              ignore_errors=True)

        record["duration_s"] = round(time.monotonic() - started, 1)
    return record


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------

def preflight() -> int:
    """Refuse to start when the toolchain cannot possibly work.

    Learned the expensive way: a run launched without ``source source_env.sh``
    leaves ``JADX_DIR`` at a default path that does not exist, so every sample
    fails with "Could not find or load main class jadx.cli.JadxCLI" — 600 of
    them, in four minutes, each one overwriting a good spine's L1 block with a
    failure. The environment was broken before the first sample; nothing about
    that needed 600 attempts to discover.

    This is T17 one level up: a run that proceeds over a broken environment is
    worse than one that refuses, because it manufactures plausible-looking
    results.
    """
    problems: list[str] = []

    jadx_jar = Path(os.environ.get("JADX_DIR", "")) / "lib" / "jadx-1.5.6-all.jar"
    if not os.environ.get("JADX_DIR"):
        problems.append("JADX_DIR is unset")
    elif not jadx_jar.is_file():
        problems.append(f"jadx jar not found at {jadx_jar}")

    java = Path(os.environ.get("JDK17_HOME", "")) / "bin" / "java"
    if not os.environ.get("JDK17_HOME"):
        problems.append("JDK17_HOME is unset")
    elif not java.is_file():
        problems.append(f"java not found at {java}")

    if problems:
        print("[corpus] REFUSING TO START — the toolchain is not usable:",
              file=sys.stderr)
        for p in problems:
            print(f"           {p}", file=sys.stderr)
        print("\n         Run `source source_env.sh` first, or every sample will "
              "fail\n         identically and overwrite good results with failures.",
              file=sys.stderr)
        return 2
    return 0


def corpus_root(args: argparse.Namespace) -> Path:
    return Path(getattr(args, "corpus_root", None) or RAW)


def index_path(args: argparse.Namespace) -> Path:
    """Resume index for this corpus.

    A second corpus needs a second index: sharing one would let a benign run's
    entries mask a malware sample with the same key, and resume would silently
    skip it. The malware corpus keeps the original filename so existing runs
    resume unchanged.
    """
    if getattr(args, "index", None):
        return Path(args.index)
    root = corpus_root(args).resolve()
    if root == RAW.resolve():
        return INDEX_PATH
    # Prefer the label: a directory called "apks" says nothing about which
    # corpus it holds, and these files outlive the shell that created them.
    stem = getattr(args, "label", None) or root.name
    return CORPUS / f"run_index_{stem}.json"


def collect(args: argparse.Namespace) -> list[Sample]:
    samples: list[Sample] = []
    root = corpus_root(args)
    if args.source in ("all", "zips"):
        samples.extend(iter_zip_members(root))
    if args.source in ("all", "loose"):
        samples.extend(iter_loose(root))
    if args.match:
        samples = [s for s in samples if args.match.lower() in s.display.lower()]
    return samples


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(
        description="Batch L0+L1 over the malware corpus (safe, resumable).")
    p.add_argument("--corpus-root", default=None,
                   help="corpus directory to run over (default: corpus/malware_raw)")
    p.add_argument("--index", default=None,
                   help="resume index (default: derived from --corpus-root)")
    p.add_argument("--label", default=None,
                   help="class label recorded per sample; read by tools/corpus_labels.py")
    p.add_argument("--source", choices=("all", "zips", "loose"), default="all",
                   help="which population to run (default: all)")
    p.add_argument("--match", default=None,
                   help="substring filter on the sample's display name")
    p.add_argument("--limit", type=int, default=None, help="stop after N samples")
    p.add_argument("--min-free-gb", type=float, default=5.0,
                   help="abort when free disk drops below this (default: 5)")
    p.add_argument("--jadx-timeout", type=int, default=180,
                   help="per-sample jadx timeout in seconds (default: 180)")
    p.add_argument("--keep-decompiled", choices=("none", "failed", "all"), default="none",
                   help="retain jadx_src. THE disk control — default none")
    p.add_argument("--keep-sources", choices=("none", "failed"), default="none",
                   help="retain extracted zip members (default: none)")
    p.add_argument("--force", action="store_true",
                   help="re-run samples already recorded as done")
    p.add_argument("--dry-run", action="store_true",
                   help="list what would run, touch nothing")
    p.add_argument("--traceback", action="store_true", help="print tracebacks on error")
    args = p.parse_args(argv[1:])

    # jadx's leash must be set before L1 imports the engine.
    os.environ["SENTINEL_JADX_TIMEOUT"] = str(args.jadx_timeout)
    # androguard logs every malformed resource at DEBUG through loguru; over
    # hundreds of samples that buries the run's own output entirely.
    try:
        from loguru import logger
        logger.remove()
    except Exception:  # noqa: BLE001
        pass

    root = corpus_root(args)
    idx_path = index_path(args)
    if not root.exists():
        print(f"[corpus] no corpus at {root}", file=sys.stderr)
        return 1

    if not args.dry_run and (rc := preflight()):
        return rc

    samples = collect(args)
    index = load_index(idx_path) if not args.force else {}

    import spine
    from engines.yara_scan import ruleset_version
    rules_v = ruleset_version()

    pending = []
    for s in samples:
        prior = index.get(s.key)
        if prior and prior.get("status") in ("ok", "skipped") \
                and prior.get("ruleset_version") == rules_v:
            continue
        pending.append(s)
    # Count what resume skipped *before* --limit truncates, or the two numbers
    # become indistinguishable and a working resume looks like a broken one.
    remaining = len(pending)
    done = len(samples) - remaining
    if args.limit:
        pending = pending[:args.limit]

    print(f"[corpus] candidates={len(samples)}  already done={done}  "
          f"remaining={remaining}  running now={len(pending)}  ruleset={rules_v}")
    print(f"[corpus] root={root}  index={idx_path.name}"
          + (f"  label={args.label}" if args.label else ""))
    print(f"[corpus] free disk={free_gb(REPO_ROOT):.1f} GB  keep-decompiled={args.keep_decompiled}  "
          f"jadx-timeout={args.jadx_timeout}s")

    if args.dry_run:
        for s in pending[:40]:
            print(f"    {s.kind:10s} {s.size/2**20:7.1f} MB  {s.display}")
        if len(pending) > 40:
            print(f"    … and {len(pending) - 40} more")
        return 0

    if not pending:
        print("[corpus] nothing to do")
        return 0

    WORK.mkdir(parents=True, exist_ok=True)
    run_dir = RUNS / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    log = RunLog(run_dir / "run_log.jsonl")
    print(f"[corpus] logging to {run_dir.relative_to(REPO_ROOT)}/run_log.jsonl")

    stats: dict[str, int] = {}
    started = time.monotonic()
    interrupted = False
    try:
        for i, sample in enumerate(pending, 1):
            try:
                check_disk(args.min_free_gb)
            except DiskExhausted as exc:
                print(f"\n[corpus] STOPPING: {exc}", file=sys.stderr)
                break

            record = analyse_one(sample, args)
            record["ruleset_version"] = rules_v
            if args.label:
                record["label"] = args.label
            log.write(record)
            index[sample.key] = {
                "status": record.get("status"),
                "sha256": record.get("sha256"),
                "ruleset_version": rules_v,
                "size": sample.size,
                "compress_size": sample.compress_size,
                "completed_at": datetime.now(timezone.utc).isoformat(),
            }
            if args.label:
                # The runner already knows which corpus it is running, so this
                # is the cheapest honest source of a class label — no inference,
                # no "everything not known benign is malware" default.
                index[sample.key]["label"] = args.label
            if i % 10 == 0 or i == len(pending):
                save_index(idx_path, index)

            status = record.get("status", "?")
            stats[status] = stats.get(status, 0) + 1
            flag = ""
            if record.get("l0_verdict") not in (None, "unknown", "trusted"):
                flag = f"  ⚑ {record['l0_verdict']}"
                if record.get("l0_entity"):
                    flag += f" -> {record['l0_entity']}"
            print(f"  [{i}/{len(pending)}] {status:10s} "
                  f"{record.get('spine_findings', '-'):>3} findings "
                  f"{record.get('duration_s', 0):>6.1f}s  "
                  f"{sample.display[:52]}{flag}")
    except KeyboardInterrupt:
        interrupted = True
        print("\n[corpus] interrupted — progress saved, re-run to resume", file=sys.stderr)
    finally:
        save_index(idx_path, index)
        log.close()
        shutil.rmtree(WORK, ignore_errors=True)

    elapsed = time.monotonic() - started
    done = sum(stats.values())
    print(f"\n[corpus] {done} sample(s) in {elapsed/60:.1f} min "
          f"({elapsed/max(done,1):.1f}s/sample)")
    for status, count in sorted(stats.items(), key=lambda kv: -kv[1]):
        print(f"    {status:12s} {count}")
    print(f"[corpus] free disk now {free_gb(REPO_ROOT):.1f} GB")
    print(f"[corpus] log: {run_dir / 'run_log.jsonl'}")
    return 130 if interrupted else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
