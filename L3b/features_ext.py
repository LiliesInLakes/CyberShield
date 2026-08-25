"""The one feature block LAMDA's vocabulary cannot express: brand impersonation.

L3's Drebin-style tokens (permissions, components, API calls, URL domains) have
no concept of "this app claims to be SBI." That claim is this project's actual
differentiator (``L0/impersonation.py``), and it is already computed — every
sample that has gone through L0 carries it in the spine at
``layers.l0.summary``. This module reads that block rather than re-deriving it
from the raw APK a second time, so ``L0/impersonation.py`` stays untouched and
a change to impersonation logic can never silently desync from what L3b saw.

**A sample with no L0 layer is refused, not zero-filled.** A zero vector here
reads as "no bank branding detected" — a specific, false claim — rather than
"we never checked." ``extract_impersonation_features`` returns
``available: False`` instead, and ``L3b/predict.py`` must skip the sample
rather than let a silent zero-fill understate the exact signal this block
exists to carry.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import numpy as np

# Order is the vector's column order. Never reorder without retraining —
# a model trained on one order silently misreads a different one.
FEATURE_NAMES: tuple[str, ...] = (
    "brand_claim_present",
    "cert_signer_anomaly",
    "cert_weight_negative",
    "sms_trifecta",
    "verdict_impersonation_likely",
    "verdict_impersonation_suspected",
)


@dataclass
class ImpersonationFeatures:
    available: bool
    vector: np.ndarray | None
    reason: str | None = None


def extract_from_spine(doc: dict[str, Any]) -> ImpersonationFeatures:
    """Pull the six-dimensional impersonation block out of an already-scored spine.

    ``doc`` is a full spine document (as returned by ``spine.load_spine``), not
    just the L0 block, so the "was L0 even run" check is explicit.
    """
    l0 = (doc.get("layers") or {}).get("l0") or {}
    if l0.get("status") != "complete":
        return ImpersonationFeatures(
            available=False, vector=None,
            reason=f"l0_status_{l0.get('status', 'missing')}")

    summary = l0.get("summary") or {}
    sgi = summary.get("smoking_gun_inputs") or {}
    cert_signal = summary.get("cert_signal") or {}
    verdict = summary.get("verdict")

    vec = np.array([
        bool(sgi.get("brand_claim")),
        bool(summary.get("cert_anomalies")),
        float(cert_signal.get("cert_weight", 0.0)) < 0,
        bool(sgi.get("sms_trifecta")),
        verdict == "impersonation_likely",
        verdict == "impersonation_suspected",
    ], dtype=np.float32)
    return ImpersonationFeatures(available=True, vector=vec)


def concatenate(lamda_vec: np.ndarray, impersonation_vec: np.ndarray) -> np.ndarray:
    """LAMDA's vector plus the impersonation block, in that fixed order.

    Kept as a free function (not folded into ``L3/features.py::vectorise``) so
    L3's own vector shape and vocabulary index are provably unaffected by
    anything L3b does.
    """
    return np.concatenate([lamda_vec.astype(np.float32), impersonation_vec])
