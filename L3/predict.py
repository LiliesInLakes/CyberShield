"""Apply the L3 prior to one APK and fold it into the spine.

    source source_env.sh
    $SENTINEL_PYTHON L3/predict.py <apk> --explain

**This layer returns a probability, never a verdict.** L5 converts it to a
point delta clipped to ±10 and refuses to let it reach Critical alone. LAMDA is
~99.6% non-banking, so a high probability here means "resembles Android malware
in general" — it is not evidence about banking, and the report must never
render it as such.

**A vector that did not really extract is refused, not scored.** If our token
spellings miss LAMDA's vocabulary the feature vector is all zeros, and a
gradient-boosted tree will happily return a confident constant for it. The
density check from ``L3/features.py`` runs first, and an implausible vector
produces ``status: skipped`` with a recorded reason rather than a number.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

import numpy as np

REPO_ROOT = Path(__file__).resolve().parent.parent
for _p in (str(REPO_ROOT), str(REPO_ROOT / "L1")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import spine  # noqa: E402
from L3.features import (  # noqa: E402
    Vocabulary, check_density, extract_from_apk, vectorise,
)

MODEL_DIR = REPO_ROOT / "L3" / "model"


class ModelMissing(RuntimeError):
    pass


def load_model(model_dir: Path = MODEL_DIR):
    import joblib

    path = model_dir / "lamda_lgbm.joblib"
    if not path.is_file():
        raise ModelMissing(
            f"no L3 model at {path}. Train one with:\n"
            "    $SENTINEL_PYTHON L3/train.py --train-until 2022")
    bundle = joblib.load(path)
    metrics_path = model_dir / "metrics.json"
    metrics = json.loads(metrics_path.read_text()) if metrics_path.is_file() else {}
    return bundle["model"], bundle["calibrator"], metrics


def predict_apk(apk_path: str | Path, *, model=None, calibrator=None,
                vocab: Vocabulary | None = None,
                iocs: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    vocab = vocab or Vocabulary.load()
    if model is None:
        model, calibrator, _ = load_model()

    extraction = extract_from_apk(apk_path, iocs)
    vec, diag = vectorise(extraction, vocab)

    if not diag["plausible"]:
        return {
            "status": "skipped",
            "reason": "feature_extraction_implausible",
            "detail": check_density(diag),
            "diagnostics": diag,
        }

    raw = float(model.predict_proba(vec.reshape(1, -1))[0, 1])
    p = float(calibrator.predict([raw])[0]) if calibrator is not None else raw
    return {
        "status": "complete",
        "prob_malicious": round(p, 4),
        "prob_uncalibrated": round(raw, 4),
        "diagnostics": diag,
    }


def promote(result: dict[str, Any], metrics: dict[str, Any]) -> dict[str, Any]:
    """L3's spine summary. Deliberately contains no verdict and no findings.

    L3 is a consumer layer: it produces a prior for L5 to bound, not evidence.
    Emitting a finding would put it in ``counts.*`` and let a generic model
    inflate the frozen malware-category headline.
    """
    summary: dict[str, Any] = {
        "prob_malicious": result.get("prob_malicious"),
        "model": "lamda_lgbm",
        "train_years": metrics.get("train_years"),
        "bounded_points": 10,
        "is_verdict": False,
        "scope": "generic_android_malware_prior",
        "caveat": ("LAMDA is ~99.6% non-banking; this probability is not "
                   "evidence about banking impersonation"),
    }
    if result.get("status") != "complete":
        summary["skipped_reason"] = result.get("reason")
    return summary


def write_layer(sha256: str, result: dict[str, Any], metrics: dict[str, Any]) -> None:
    status = (spine.LayerStatus.COMPLETE if result.get("status") == "complete"
              else spine.LayerStatus.SKIPPED)
    spine.update_layer(
        sha256, "l3",
        status=status,
        findings=[],                       # a prior is not a finding
        summary=promote(result, metrics),
        coverage={
            "features_set": result.get("diagnostics", {}).get("nonzero", 0),
            "feature_density": result.get("diagnostics", {}).get("density", 0.0),
            "families_hit": len(result.get("diagnostics", {})
                                .get("hits_by_family", {})),
        },
        gaps=None,                         # consumer layer — see L5/promote.py
    )


def main(argv: list[str] | None = None) -> int:
    import argparse
    import hashlib

    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("apk")
    ap.add_argument("--explain", action="store_true")
    ap.add_argument("--no-write", action="store_true", help="do not touch the spine")
    args = ap.parse_args(argv)

    try:
        from loguru import logger
        logger.remove()
    except Exception:  # noqa: BLE001
        pass

    try:
        model, calibrator, metrics = load_model()
    except ModelMissing as exc:
        print(exc, file=sys.stderr)
        return 2

    from engines.ioc_extract import extract_from_apk as get_iocs
    iocs = [i.to_dict() for i in get_iocs(args.apk)]
    result = predict_apk(args.apk, model=model, calibrator=calibrator, iocs=iocs)

    sha = hashlib.sha256(Path(args.apk).read_bytes()).hexdigest()
    if not args.no_write:
        write_layer(sha, result, metrics)

    if result["status"] != "complete":
        print(f"skipped: {result['detail']}")
        return 1

    print(f"p(malicious) = {result['prob_malicious']:.4f}   "
          f"(uncalibrated {result['prob_uncalibrated']:.4f})")
    print(f"  {check_density(result['diagnostics'])}")
    print("  bounded to ±10 points in L5; this is a generic prior, not a "
          "banking claim")
    if args.explain:
        print(json.dumps(result["diagnostics"], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
