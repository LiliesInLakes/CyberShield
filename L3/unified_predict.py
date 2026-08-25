"""Apply the unified L3 prior to one APK and fold it into the spine.

    source source_env.sh
    $SENTINEL_PYTHON L3/unified_predict.py <apk> --explain

Same ``layers.l3`` contract as ``L3/predict.py`` — a probability, never a
verdict, no findings — but features come from the corpus-derived vocabulary
(``L3/unified_features``) the model was actually trained on, extracted by the
same pipeline. There is therefore no train/serve vocabulary skew: prediction
runs ``extract_from_apk`` -> ``meaningful_tokens`` -> ``vectorise_unified``
against the persisted ``unified_vocab.json``, exactly as the trainer did.

A vector below the density floor is refused (``status: skipped``), not scored.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
for _p in (str(REPO_ROOT), str(REPO_ROOT / "L1")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import spine  # noqa: E402
from L3.features import extract_from_apk  # noqa: E402
from L3.unified_features import (  # noqa: E402
    CorpusVocabulary, augment_with_capabilities, meaningful_tokens, vectorise_unified,
)

MODEL_DIR = REPO_ROOT / "L3" / "model"
MODEL_PATH = MODEL_DIR / "unified_lgbm.joblib"
VOCAB_PATH = MODEL_DIR / "unified_vocab.json"
METRICS_PATH = MODEL_DIR / "unified_metrics.json"


class ModelMissing(RuntimeError):
    pass


def load_model(model_dir: Path = MODEL_DIR):
    import joblib

    if not MODEL_PATH.is_file():
        raise ModelMissing(
            f"no unified L3 model at {MODEL_PATH}. Train one with:\n"
            "    $SENTINEL_PYTHON tools/build_unified_dataset.py extract && \\\n"
            "    $SENTINEL_PYTHON tools/build_unified_dataset.py build && \\\n"
            "    $SENTINEL_PYTHON L3/unified_train.py")
    bundle = joblib.load(MODEL_PATH)
    vocab = CorpusVocabulary.load(bundle.get("vocab_path", VOCAB_PATH))
    metrics = json.loads(METRICS_PATH.read_text()) if METRICS_PATH.is_file() else {}
    return bundle["model"], bundle["calibrator"], vocab, metrics


def predict_apk(apk_path: str | Path, *, model=None, calibrator=None,
                vocab: CorpusVocabulary | None = None,
                iocs: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    if model is None:
        model, calibrator, vocab, _ = load_model()
    elif vocab is None:
        vocab = CorpusVocabulary.load(VOCAB_PATH)

    extraction = extract_from_apk(apk_path, iocs)
    feats = augment_with_capabilities(meaningful_tokens(extraction.tokens))
    vec, diag = vectorise_unified(feats, vocab)

    if not diag["plausible"]:
        return {
            "status": "skipped",
            "reason": "feature_extraction_implausible",
            "detail": f"{diag['nonzero']} of {vocab.size} columns set — below the "
                      "density floor; treat any probability as meaningless",
            "diagnostics": diag,
        }

    import numpy as np
    raw = float(model.predict_proba(vec.reshape(1, -1).astype(np.float32))[0, 1])
    p = float(calibrator.predict([raw])[0]) if calibrator is not None else raw
    return {
        "status": "complete",
        "prob_malicious": round(p, 4),
        "prob_uncalibrated": round(raw, 4),
        "diagnostics": diag,
    }


def promote(result: dict[str, Any], metrics: dict[str, Any]) -> dict[str, Any]:
    """L3's spine summary — no verdict, no findings (a prior is not evidence)."""
    summary: dict[str, Any] = {
        "prob_malicious": result.get("prob_malicious"),
        "model": "unified_lgbm",
        "bounded_points": 10,
        "is_verdict": False,
        "scope": "generic_android_malware_prior",
        "caveat": ("trained on a source-confounded corpus (benign=F-Droid, "
                   "malware=CICMalDroid, T27); a generic prior, not evidence "
                   "about banking impersonation"),
    }
    held = (metrics or {}).get("held_out", {})
    if "auroc" in held:
        summary["held_out_auroc"] = held["auroc"]
    if result.get("status") != "complete":
        summary["skipped_reason"] = result.get("reason")
    return summary


def write_layer(sha256: str, result: dict[str, Any], metrics: dict[str, Any]) -> None:
    status = (spine.LayerStatus.COMPLETE if result.get("status") == "complete"
              else spine.LayerStatus.SKIPPED)
    spine.update_layer(
        sha256, "l3",
        status=status,
        findings=[],
        summary=promote(result, metrics),
        coverage={
            "features_set": result.get("diagnostics", {}).get("nonzero", 0),
            "feature_density": result.get("diagnostics", {}).get("density", 0.0),
            "families_hit": len(result.get("diagnostics", {})
                                .get("hits_by_family", {})),
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
        model, calibrator, vocab, metrics = load_model()
    except ModelMissing as exc:
        print(exc, file=sys.stderr)
        return 2

    try:
        from engines.ioc_extract import extract_from_apk as get_iocs
        iocs = [i.to_dict() for i in get_iocs(args.apk)]
    except Exception:  # noqa: BLE001
        iocs = None
    result = predict_apk(args.apk, model=model, calibrator=calibrator,
                         vocab=vocab, iocs=iocs)

    sha = hashlib.sha256(Path(args.apk).read_bytes()).hexdigest()
    if not args.no_write:
        write_layer(sha, result, metrics)

    if result["status"] != "complete":
        print(f"skipped: {result['detail']}")
        return 1

    print(f"p(malicious) = {result['prob_malicious']:.4f}   "
          f"(uncalibrated {result['prob_uncalibrated']:.4f})")
    print(f"  {result['diagnostics']['nonzero']} of {vocab.size} columns set")
    print("  bounded to ±10 points in L5; a generic prior, not a banking claim")
    if args.explain:
        print(json.dumps(result["diagnostics"], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
