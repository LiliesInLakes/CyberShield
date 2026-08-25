"""Apply the L3b banking prior to one APK and fold it into the spine.

    source source_env.sh
    $SENTINEL_PYTHON L3b/predict.py <apk> --explain

**This layer returns a probability, never a verdict** — same discipline as
L3 (``L3/predict.py``). L5 bounds it to ±10 points and, unless the training
run's held-out metric was family-disjoint-verified, refuses to let it move
the score at all (see ``L5/score.py::apply_banking_ml``).

**Two independent refusal paths, not one.** A sample is skipped if either the
LAMDA feature bridge is implausible (same check L3 uses) or the L0
impersonation block is unavailable (``L3b/features_ext.py``) — the second
check exists because zero-filling a missing impersonation block would read as
"no bank branding," a specific false claim, rather than "we never checked."
Requires L0 (and ideally L1, for IOC-derived URL-domain tokens) to have
already run on this sha256, i.e. this is meant to run after
``tools/corpus_run.py`` or ``L0/ingest.py`` + ``L1/l1.py``, not standalone on
an unanalysed APK.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import spine  # noqa: E402
from L3.features import Vocabulary, check_density, extract_from_apk, vectorise  # noqa: E402
from L3b.features_ext import concatenate, extract_from_spine  # noqa: E402

MODEL_DIR = REPO_ROOT / "L3b" / "model"


class ModelMissing(RuntimeError):
    pass


def load_model(model_dir: Path = MODEL_DIR):
    import joblib

    path = model_dir / "banking_lgbm.joblib"
    if not path.is_file():
        raise ModelMissing(
            f"no L3b model at {path}. Build the dataset and train one with:\n"
            "    $SENTINEL_PYTHON L3b/dataset.py\n"
            "    $SENTINEL_PYTHON L3b/train.py")
    bundle = joblib.load(path)
    metrics_path = model_dir / "metrics.json"
    metrics = json.loads(metrics_path.read_text()) if metrics_path.is_file() else {}
    return bundle["model"], bundle["calibrator"], metrics


def predict_apk(apk_path: str | Path, sha256: str, *, model=None, calibrator=None,
                vocab: Vocabulary | None = None) -> dict[str, Any]:
    vocab = vocab or Vocabulary.load()
    if model is None:
        model, calibrator, _ = load_model()

    doc = spine.load_spine(sha256)
    impersonation = extract_from_spine(doc)
    if not impersonation.available:
        return {
            "status": "skipped",
            "reason": impersonation.reason,
            "detail": "L0 impersonation block unavailable — run L0/ingest.py "
                      "on this sample first",
        }

    extraction = extract_from_apk(apk_path)
    lamda_vec, diag = vectorise(extraction, vocab)
    if not diag["plausible"]:
        return {
            "status": "skipped",
            "reason": "feature_extraction_implausible",
            "detail": check_density(diag),
            "diagnostics": diag,
        }

    vec = concatenate(lamda_vec, impersonation.vector)
    raw = float(model.predict_proba(vec.reshape(1, -1))[0, 1])
    p = float(calibrator.predict([raw])[0]) if calibrator is not None else raw
    return {
        "status": "complete",
        "prob_banking_malicious": round(p, 4),
        "prob_uncalibrated": round(raw, 4),
        "diagnostics": diag,
    }


def promote(result: dict[str, Any], metrics: dict[str, Any]) -> dict[str, Any]:
    """L3b's spine summary. Deliberately no verdict and no findings — same
    non-evidence treatment as L3 (``L3/predict.py::promote``), for the same
    reason: a finding here would enter ``counts.*`` and inflate the frozen
    malware-category headline with a small, partially-verified model's guess.
    """
    summary: dict[str, Any] = {
        "prob_banking_malicious": result.get("prob_banking_malicious"),
        "model": "banking_lgbm",
        "family_disjoint_status": metrics.get("family_disjoint_status"),
        "malware_sources": metrics.get("malware_sources"),
        "bounded_points": 10,
        "is_verdict": False,
        "scope": "banking_specific_prior",
        "caveat": ("trained on a small, partially family-verified banking-"
                   "trojan corpus; see family_disjoint_status before trusting "
                   "this as a banking-specific claim"),
    }
    if result.get("status") != "complete":
        summary["skipped_reason"] = result.get("reason")
    return summary


def write_layer(sha256: str, result: dict[str, Any], metrics: dict[str, Any]) -> None:
    status = (spine.LayerStatus.COMPLETE if result.get("status") == "complete"
              else spine.LayerStatus.SKIPPED)
    spine.update_layer(
        sha256, "l3b",
        status=status,
        findings=[],
        summary=promote(result, metrics),
        coverage={
            "features_set": result.get("diagnostics", {}).get("nonzero", 0),
            "feature_density": result.get("diagnostics", {}).get("density", 0.0),
        },
        gaps=None,
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

    sha = hashlib.sha256(Path(args.apk).read_bytes()).hexdigest()
    result = predict_apk(args.apk, sha, model=model, calibrator=calibrator)

    if not args.no_write:
        write_layer(sha, result, metrics)

    if result["status"] != "complete":
        print(f"skipped: {result['detail']}")
        return 1

    print(f"p(banking-malicious) = {result['prob_banking_malicious']:.4f}   "
         f"(uncalibrated {result['prob_uncalibrated']:.4f})")
    print(f"  family_disjoint_status: {metrics.get('family_disjoint_status')}")
    print("  bounded to ±10 points in L5; refused unless the split is "
         "family-disjoint-verified")
    if args.explain:
        print(json.dumps(result["diagnostics"], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
