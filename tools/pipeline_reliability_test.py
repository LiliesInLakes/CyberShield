"""Functional + reliability sweep of the full pipeline (L0-L6) across every
readily-available APK, plus an opt-in pass over the encrypted malware corpus.

    source source_env.sh
    $SENTINEL_PYTHON tools/pipeline_reliability_test.py                    # default sample set
    $SENTINEL_PYTHON tools/pipeline_reliability_test.py --include-corpus   # + malware_raw/fdroid, L0+L1 only
    $SENTINEL_PYTHON tools/pipeline_reliability_test.py --layers l0,l1     # skip L4 (costs $, needs a key)

**What this checks, and what it deliberately does not.** Each layer is run
through its real CLI entrypoint via subprocess — the same commands a human
would type — not imported and called in-process, so a bug in argument
parsing or a broken `if __name__ == "__main__"` guard is caught too, not
just a bug in the importable function. It is a *reliability* sweep (does
every stage run to completion and produce the artifact the next stage
expects), not a *correctness* sweep (whether the findings are right) — that
is what the frozen baselines under `tests/baseline/` and the corpus-scale
measurements in `CLAUDE.md` are for.

**L2 is opt-in and defaults to the non-destructive checks only.** Live
detonation of a malware sample needs an explicit human go/no-go per
`CLAUDE.md` §4 and `todo.md`'s Blocked section — this script never installs
or runs a sample on an emulator on its own. `--attempt-l2-detonation` will
try it, but only for samples this script does not itself classify as
malware (see `_is_malware_sample`), and it still degrades to "skipped, no
emulator" rather than failing the run if no ADB device shows up.

**The default sample set never touches `corpus/malware_raw/`.** It sweeps
`testing_apps/*.apk` (real benign apps + intentionally-vulnerable-but-not-
malicious CTF targets) plus any standalone cached sample under
`/tmp/l2_test_sample/` if present. `--include-corpus` adds a real sweep of
the encrypted/loose malware corpus and the F-Droid benign set, but restricts
those to L0+L1 (same scope as `tools/corpus_run.py`, which this script calls
into for that part rather than re-deriving the corpus safety rules).
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
for _p in (str(REPO_ROOT),):
    if _p not in sys.path:
        sys.path.insert(0, _p)

DEFAULT_SAMPLE_DIRS = (
    REPO_ROOT / "testing_apps" / "good_apps",
    REPO_ROOT / "testing_apps" / "vuln",
)
CACHED_L2_SAMPLE_DIR = Path("/tmp/l2_test_sample")

# Samples this script will never let --attempt-l2-detonation touch, by
# filename substring -- belt-and-suspenders on top of the go/no-go rule
# above, in case a real malware sample ever lands in a default sample dir.
_KNOWN_MALWARE_MARKERS = ("l2_test_sample",)

LAYER_ORDER = ("l0", "l1", "l2", "l4", "l5", "l6")


@dataclass
class StageResult:
    layer: str
    status: str  # "pass" | "fail" | "skipped"
    elapsed_s: float = 0.0
    detail: str = ""


@dataclass
class SampleResult:
    apk: str
    sha256: str = ""
    stages: list[StageResult] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "apk": self.apk,
            "sha256": self.sha256,
            "stages": [{"layer": s.layer, "status": s.status,
                       "elapsed_s": round(s.elapsed_s, 2), "detail": s.detail[:2000]}
                      for s in self.stages],
        }


def _is_malware_sample(apk: Path) -> bool:
    return any(marker in str(apk) for marker in _KNOWN_MALWARE_MARKERS)


def _run(cmd: list[str], timeout: int) -> tuple[bool, str, float]:
    start = time.monotonic()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return False, f"timed out after {timeout}s: {' '.join(cmd)}", time.monotonic() - start
    elapsed = time.monotonic() - start
    if proc.returncode != 0:
        tail = (proc.stderr or proc.stdout or "")[-1500:]
        return False, f"exit {proc.returncode}: {tail}", elapsed
    return True, proc.stdout[-500:], elapsed


def _sha256_of(apk: Path) -> str:
    import hashlib
    digest = hashlib.sha256()
    with apk.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run_sample(apk: Path, layers: tuple[str, ...], python: str, *,
               attempt_l2_detonation: bool, budget: float,
               out_dir: Path) -> SampleResult:
    result = SampleResult(apk=str(apk))

    if "l0" in layers:
        ok, detail, elapsed = _run([python, "L0/ingest.py", str(apk)], timeout=120)
        result.stages.append(StageResult("l0", "pass" if ok else "fail", elapsed, detail))
        if not ok:
            return result  # nothing downstream can run without L0

    result.sha256 = _sha256_of(apk)

    if "l1" in layers:
        ok, detail, elapsed = _run([python, "L1/l1.py", str(apk)], timeout=300)
        result.stages.append(StageResult("l1", "pass" if ok else "fail", elapsed, detail))

    # T31: L1's real artifact root is $SENTINEL_L1_ARTIFACTS (the heavy jadx
    # writer moved off the repo partition), not L1/artifacts/ -- hardcoding
    # the latter here silently skipped L4 on every sample in the first run.
    import os
    l1_root = Path(os.environ.get("SENTINEL_L1_ARTIFACTS") or (REPO_ROOT / "L1" / "artifacts"))
    jadx_src = l1_root / result.sha256 / "jadx_src"

    if "l2" in layers:
        if not attempt_l2_detonation:
            result.stages.append(StageResult(
                "l2", "skipped",
                detail="live detonation not requested (default) -- run with "
                       "--attempt-l2-detonation to try it on non-malware samples"))
        elif _is_malware_sample(apk):
            result.stages.append(StageResult(
                "l2", "skipped",
                detail="malware sample -- live detonation requires an explicit "
                       "human go/no-go per CLAUDE.md §4, never attempted automatically"))
        else:
            ok, detail, elapsed = _run(
                [python, "-m", "L2.sandbox.orchestrator", str(apk),
                 _guess_package(apk) or "unknown.package", "--time", "20", "--droidbot-time", "20"],
                timeout=300,
            )
            # A GPU-less sandbox failing to boot an emulator is an environment
            # limit, not a pipeline bug -- surfaced distinctly so it doesn't
            # read as a false "fail" in the summary table.
            if not ok and ("EmulatorUnavailableError" in detail or "no ADB devices" in detail
                           or "did not finish booting" in detail):
                result.stages.append(StageResult(
                    "l2", "skipped", elapsed, "no emulator reachable in this environment"))
            else:
                result.stages.append(StageResult("l2", "pass" if ok else "fail", elapsed, detail))

    if "l4" in layers:
        if not jadx_src.is_dir():
            result.stages.append(StageResult(
                "l4", "skipped", detail="no jadx_src -- L1 did not run or produced nothing"))
        else:
            ok, detail, elapsed = _run(
                [python, "L4/deobfuscate.py", result.sha256, "--src", str(jadx_src),
                 "--budget", str(budget), "--explain"],
                timeout=600,
            )
            result.stages.append(StageResult("l4", "pass" if ok else "fail", elapsed, detail))

    if "l5" in layers:
        ok, detail, elapsed = _run(
            [python, "L5/l5.py", result.sha256, "--explain"], timeout=60)
        result.stages.append(StageResult("l5", "pass" if ok else "fail", elapsed, detail))

    if "l6" in layers:
        report_path = out_dir / f"report_{result.sha256[:12]}.html"
        ok, detail, elapsed = _run(
            [python, "L6/report.py", result.sha256, "--out", str(report_path)], timeout=60)
        if ok and not report_path.is_file():
            ok, detail = False, "report.py exited 0 but produced no file"
        result.stages.append(StageResult("l6", "pass" if ok else "fail", elapsed, detail))

    return result


def _guess_package(apk: Path) -> str | None:
    """Best-effort package name for the L2 CLI, which wants one positionally.
    Falls back to None (caller substitutes a placeholder) rather than
    importing androguard here just for this."""
    try:
        sys.path.insert(0, str(REPO_ROOT))
        from androguard.core.apk import APK  # type: ignore
        return APK(str(apk)).get_package()
    except Exception:  # noqa: BLE001
        return None


def collect_default_samples() -> list[Path]:
    samples: list[Path] = []
    for d in DEFAULT_SAMPLE_DIRS:
        if d.is_dir():
            samples.extend(sorted(d.rglob("*.apk")))
    if CACHED_L2_SAMPLE_DIR.is_dir():
        samples.extend(sorted(CACHED_L2_SAMPLE_DIR.glob("*.apk")))
    return samples


def print_summary(results: list[SampleResult]) -> None:
    print(f"\n{'sample':<55} " + " ".join(f"{l:>10}" for l in LAYER_ORDER))
    for r in results:
        by_layer = {s.layer: s.status for s in r.stages}
        row = " ".join(f"{by_layer.get(l, '-'):>10}" for l in LAYER_ORDER)
        print(f"{Path(r.apk).name:<55} {row}")

    total = sum(len(r.stages) for r in results)
    passed = sum(1 for r in results for s in r.stages if s.status == "pass")
    failed = sum(1 for r in results for s in r.stages if s.status == "fail")
    skipped = sum(1 for r in results for s in r.stages if s.status == "skipped")
    print(f"\n{passed}/{total} stage-runs passed, {failed} failed, {skipped} skipped "
          f"across {len(results)} samples")
    if failed:
        print("\nFailures:")
        for r in results:
            for s in r.stages:
                if s.status == "fail":
                    print(f"  {Path(r.apk).name} :: {s.layer} -- {s.detail[:200]}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--layers", default="l0,l1,l4,l5,l6",
                    help="comma-separated subset of l0,l1,l2,l4,l5,l6")
    ap.add_argument("--attempt-l2-detonation", action="store_true",
                    help="actually try live L2 detonation on non-malware samples "
                         "(default: skip, since no emulator is expected in this environment)")
    ap.add_argument("--budget", type=float, default=0.50,
                    help="USD cap per sample for L4 (default 0.50)")
    ap.add_argument("--include-corpus", action="store_true",
                    help="also sweep corpus/malware_raw + fdroid via tools/corpus_run.py, L0+L1 only")
    ap.add_argument("--corpus-limit", type=int, default=20,
                    help="cap on corpus samples when --include-corpus is set (default 20 -- "
                         "the full corpus is a ~57min run, see tools/corpus_run.py)")
    ap.add_argument("--out", default=None, help="JSON report path (default: timestamped, in this dir)")
    args = ap.parse_args(argv)

    layers = tuple(x.strip() for x in args.layers.split(",") if x.strip())
    python = sys.executable

    out_dir = REPO_ROOT / "tools" / "reliability_reports"
    out_dir.mkdir(parents=True, exist_ok=True)

    samples = collect_default_samples()
    if not samples:
        print("no samples found under testing_apps/ or /tmp/l2_test_sample/", file=sys.stderr)
        return 1

    print(f"running layers {layers} over {len(samples)} sample(s)")
    results = [
        run_sample(apk, layers, python, attempt_l2_detonation=args.attempt_l2_detonation,
                  budget=args.budget, out_dir=out_dir)
        for apk in samples
    ]

    if args.include_corpus:
        print(f"\n--include-corpus: delegating to tools/corpus_run.py --limit {args.corpus_limit} "
              f"(L0+L1 only, its own safety rules apply -- see CLAUDE.md §4)")
        ok, detail, elapsed = _run(
            [python, "tools/corpus_run.py", "--limit", str(args.corpus_limit)], timeout=1800)
        print(f"  corpus_run.py: {'ok' if ok else 'FAILED'} ({elapsed:.0f}s)")
        if not ok:
            print(f"  {detail[:1000]}")

    print_summary(results)

    out_path = Path(args.out) if args.out else (
        out_dir / f"reliability_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.json")
    out_path.write_text(json.dumps(
        {"generated": datetime.now(timezone.utc).isoformat(),
         "layers": layers, "samples": [r.to_dict() for r in results]},
        indent=2))
    print(f"\nfull report: {out_path}")

    any_failed = any(s.status == "fail" for r in results for s in r.stages)
    return 1 if any_failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
