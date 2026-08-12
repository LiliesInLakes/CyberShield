"""Score the L3 model on OUR labelled samples, not LAMDA's held-out years.

    source source_env.sh
    $SENTINEL_PYTHON tools/l3_on_our_corpus.py --n 150

LAMDA's own 2023–2025 splits say the model generalises across time *within
AndroZoo*. They say nothing about whether it transfers to this corpus, which is
a different population twice over: our malware is GitHub-sourced 2020–2022, and
our benign set is 2024–2026 F-Droid, where LAMDA's benign half came from
AndroZoo. Measured feature density on our samples is 0.4–1.8% against LAMDA's
2.5%, so the vocabulary overlap is partial.

**If the model is weak here, that is the number to report.** L3 is bounded to
±10 points precisely so a weak prior costs little; the failure mode to avoid is
tuning it until it looks useful on a corpus it was never fitted to.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import sys
import tempfile
from pathlib import Path
from typing import Any

import numpy as np

REPO_ROOT = Path(__file__).resolve().parent.parent
for _p in (str(REPO_ROOT), str(REPO_ROOT / "L1"), str(REPO_ROOT / "L0")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

DATA_ROOT = Path(os.environ.get("SENTINEL_DATA_ROOT", REPO_ROOT))
BENIGN_DIR = DATA_ROOT / "fdroid" / "apks"
MALWARE_RAW = REPO_ROOT / "corpus" / "malware_raw"


def iter_benign(limit: int, seed: int = 7) -> list[Path]:
    files = sorted(BENIGN_DIR.glob("*.apk"))
    random.Random(seed).shuffle(files)
    return files[:limit]


def iter_malware(limit: int, seed: int = 7) -> list[tuple[Path, str]]:
    """(archive, member) pairs, read from central directories only."""
    import zipfile
    out: list[tuple[Path, str]] = []
    for archive in sorted(MALWARE_RAW.rglob("*.zip")):
        try:
            with zipfile.ZipFile(archive) as zf:
                for info in zf.infolist():
                    if info.is_dir() or info.file_size < 10_000:
                        continue
                    out.append((archive, info.filename))
        except Exception:  # noqa: BLE001
            continue
    random.Random(seed).shuffle(out)
    return out[:limit * 3]          # over-sample; many members are not APKs


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--n", type=int, default=150, help="samples per class")
    ap.add_argument("--out", default=None)
    args = ap.parse_args(argv)

    try:
        from loguru import logger
        logger.remove()
    except Exception:  # noqa: BLE001
        pass

    import pyzipper

    from engines.ioc_extract import extract_from_apk as get_iocs
    from L3.features import Vocabulary, extract_from_apk, vectorise
    from L3.predict import load_model
    from tools.evaluate import auroc, bootstrap_auroc

    model, calibrator, metrics = load_model()
    vocab = Vocabulary.load()

    rows: list[dict[str, Any]] = []

    def score(path: Path, label: int, name: str) -> None:
        try:
            iocs = [i.to_dict() for i in get_iocs(path)]
            ex = extract_from_apk(path, iocs)
            vec, diag = vectorise(ex, vocab)
        except Exception as exc:  # noqa: BLE001
            rows.append({"name": name, "label": label, "error": str(exc)[:80]})
            return
        if not diag["plausible"]:
            rows.append({"name": name, "label": label, "skipped": "implausible",
                         "density": diag["density"]})
            return
        raw = float(model.predict_proba(vec.reshape(1, -1))[0, 1])
        p = float(calibrator.predict([raw])[0])
        rows.append({"name": name, "label": label, "p": p, "p_raw": raw,
                     "density": diag["density"], "nonzero": diag["nonzero"]})

    print(f"scoring {args.n} benign…", flush=True)
    for i, path in enumerate(iter_benign(args.n), 1):
        score(path, 0, path.name)
        if i % 50 == 0:
            print(f"  {i}", flush=True)

    print(f"scoring up to {args.n} malware…", flush=True)
    done = 0
    for archive, member in iter_malware(args.n):
        if done >= args.n:
            break
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "s.apk"
            try:
                with pyzipper.AESZipFile(archive) as zf:
                    zf.setpassword(b"infected")
                    data = zf.read(member)
                if not data.startswith(b"PK\x03\x04"):
                    continue
                p.write_bytes(data)
            except Exception:  # noqa: BLE001
                continue
            score(p, 1, f"{archive.name}!{Path(member).name}")
        done += 1
        if done % 50 == 0:
            print(f"  {done}", flush=True)

    scored = [r for r in rows if "p" in r]
    y = np.array([r["label"] for r in scored])
    p = np.array([r["p"] for r in scored])
    n_ben = int((y == 0).sum())
    n_mal = int((y == 1).sum())

    print(f"\nscored {len(scored)} ({n_mal} malware, {n_ben} benign); "
          f"{len(rows) - len(scored)} skipped or failed")
    if n_mal and n_ben:
        a = auroc(y, p)
        lo, hi = bootstrap_auroc(y, p, n=1000)
        print(f"  AUROC on OUR corpus   {a:.4f}   95% CI [{lo:.4f}, {hi:.4f}]")
        print(f"  mean p  malware {p[y == 1].mean():.4f}   benign {p[y == 0].mean():.4f}")
        print(f"  median  malware {np.median(p[y == 1]):.4f}   "
              f"benign {np.median(p[y == 0]):.4f}")
        lam = metrics.get("per_year", {})
        if lam:
            last = list(lam)[-1]
            print(f"\n  for comparison, LAMDA's own {last} holdout: "
                  f"AUROC {lam[last]['auroc']:.4f}")
        print(f"\n  feature density: malware "
              f"{np.mean([r['density'] for r in scored if r['label'] == 1]):.4f}  "
              f"benign {np.mean([r['density'] for r in scored if r['label'] == 0]):.4f}"
              f"   (LAMDA mean 0.0254)")

    out = Path(args.out) if args.out else (
        REPO_ROOT / "docs" / "reports" / "l3_transfer.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(
        {"n_malware": n_mal, "n_benign": n_ben,
         "auroc": auroc(y, p) if (n_mal and n_ben) else None,
         "rows": rows}, indent=2))
    print(f"\nwrote {out.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
