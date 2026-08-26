"""Corpus-derived, pipeline-native feature space for the unified L3 model.

Unlike ``L3/features.py``, which forces our tokens through LAMDA's fixed 4,561
column vocabulary (and loses 98% of them to a spelling mismatch — measured
density 0.4-1.8% vs LAMDA's 2.5%), this module builds the column space **from
the tokens our own extractor emits across our own corpus**. Train and serve
then use one extractor, so there is no vocabulary skew, and India-specific
tokens LAMDA never had can become columns.

The token producer is unchanged: ``L3.features.extract_from_apk`` (the same
call L3 and L3b already use). This module only decides *which* of those tokens
become columns, and turns a token set into a vector against that decision.

Design guards:

* **Document-frequency floor** (``min_df``): a token present in one app is a
  memorised sample id, not a feature. Dropping singletons is the main defence
  against overfitting on a ~3.7k-sample corpus with a naturally huge API-token
  vocabulary.
* **Document-frequency ceiling** (``max_df_ratio``): a token in ~every app
  (``AccessibilityService``-style, T23; ``self_signed``-style, T6) carries no
  discrimination. A learned model tolerates it, but dropping it keeps the
  matrix small and honest.
* The vocabulary is **frozen at build time and persisted**; prediction loads
  the exact same ``{token: col}`` map, or the vector means nothing.
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

import numpy as np

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# Below this fraction of columns set, treat the vector as extraction failure,
# not a genuinely featureless app (mirrors L3.features.MIN_PLAUSIBLE_DENSITY,
# but the corpus vocab is far denser per app so the floor is higher).
MIN_PLAUSIBLE_NONZERO = 5

# ---------------------------------------------------------------------------
# Token relevance filter.
#
# extract_from_apk emits one API token per *method* in every dex — for a modern
# app that is ~100k tokens, ~99% of them androidx/kotlin/com.google **library**
# signatures. Keeping them makes the vector a library fingerprint, and because
# our benign apps are all F-Droid and our malware all CICMalDroid, a model
# would learn "uses androidx -> benign" — the ML form of T27/T28, which does not
# survive contact with a real benign banking app. We therefore keep only the
# semantically meaningful tokens: the manifest families that are cross-app by
# nature, and API calls into the small set of framework classes that actually
# carry banking-malware capability (SMS, telephony, accessibility, device
# admin, dynamic code loading, crypto, install, screen capture, ...).
#
# The API allow-list is capability selection, not per-sample tuning: it is the
# same for every APK and names classes, never samples. Component *class-name*
# families (Activity/Service/Receiver) are dropped — they are app-specific
# names, not behaviour (intent-filter *actions* carry the behaviour instead).

_MANIFEST_KEEP = {
    "RequestedPermissionList", "UsedPermissionsList", "IntentFilterList",
    "HardwareComponentsList", "URLDomainList",
}
_API_FAMILIES = {"RestrictedApiList", "SuspiciousApiList"}

# Framework class prefixes whose methods indicate a security-relevant
# capability. Matched against the dotted class path of an API token.
_SECURITY_API_PREFIXES = (
    "android.telephony", "android.provider.telephony", "com.android.internal.telephony",
    "android.app.admin",                      # DevicePolicyManager
    "android.accessibilityservice", "android.view.accessibility",
    "android.content.pm",                     # PackageManager / PackageInstaller
    "android.app.notificationmanager", "android.service.notification",
    "android.content.clipboardmanager", "android.text.clipboardmanager",
    "android.app.keyguardmanager",
    "android.hardware.biometrics", "android.hardware.fingerprint",
    "android.media.projection",               # screen capture
    "android.webkit",                         # WebView overlays / JS bridges
    "android.location",
    "android.os.powermanager",                # wakelocks (persistence)
    "android.app.usage",
    "java.lang.runtime", "java.lang.processbuilder", "java.lang.reflect",
    "dalvik.system",                          # DexClassLoader et al.
    "javax.crypto", "java.security",
    "java.net", "android.net",
    "android.telecom",
)


def _api_class_dotted(family: str, value: str) -> str:
    """The dotted, lower-cased class path of an API token, for prefix matching.

    SuspiciousApiList is JVM-style (``Landroid/telephony/SmsManager.send``);
    RestrictedApiList is already dotted (``android.telephony.SmsManager.send``).
    """
    cls = value.rsplit(".", 1)[0]           # drop the method name
    if cls.startswith("L"):
        cls = cls[1:].replace("/", ".")
    return cls.lower()


def is_meaningful(token: str) -> bool:
    """Whether a raw extractor token should become a candidate column."""
    family, _, value = token.partition("_")
    if family in _MANIFEST_KEEP:
        return True
    if family in _API_FAMILIES:
        dotted = _api_class_dotted(family, value)
        return dotted.startswith(_SECURITY_API_PREFIXES)
    return False


def meaningful_tokens(tokens: Iterable[str]) -> set[str]:
    """Filter a raw token set down to the meaningful candidate columns."""
    return {t for t in tokens if is_meaningful(t)}


# ---------------------------------------------------------------------------
# Capability (absence) signals.
#
# The dataset analysis showed the strongest *real* discriminator is a capability
# being present or ABSENT — e.g. SMS capability is present in 79.9% of malware
# vs 10.8% of benign — while the model's easy win was a build-era artifact
# (modern androidx tokens present only in benign). Individual API tokens are
# brittle (one spelling, defeated by refactoring) and let that artifact
# dominate. A capability aggregate fires if ANY of several tokens for it is
# present, so it is robust to spelling, and its 0 is a first-class "capability
# absent" signal — exactly the absence-as-signal the analysis surfaced.
#
# These become synthetic `cap:<name>` columns, computed identically at train and
# predict time, so they carry no train/serve skew.

_CAPABILITY_GROUPS: dict[str, tuple[str, ...]] = {
    "cap:sms": ("smsmanager", "receive_sms", "read_sms", "send_sms",
                "sms_received", "provider.telephony"),
    "cap:phone_identity": ("getline1number", "getdeviceid", "getsubscriberid",
                           "getsimserialnumber", "read_phone_state"),
    "cap:accessibility": ("bind_accessibility_service", "accessibilityservice",
                          "accessibilitynodeinfo", "accessibilityevent"),
    "cap:device_admin": ("devicepolicymanager", "device_admin", "bind_device_admin"),
    "cap:dynamic_code": ("dexclassloader", "pathclassloader", "inmemorydexclassloader",
                         "dalvik.system"),
    "cap:reflection": ("java.lang.reflect", "ljava/lang/reflect"),
    "cap:crypto": ("javax.crypto", "ljavax/crypto", "java.security", "ljava/security"),
    "cap:overlay": ("system_alert_window", "type_application_overlay", "addview"),
    "cap:contacts": ("read_contacts", "contactscontract"),
    "cap:install_pkg": ("request_install_packages", "packageinstaller"),
    "cap:screen_capture": ("media.projection", "mediaprojection"),
    "cap:location": ("access_fine_location", "access_coarse_location", "android.location",
                     "landroid/location"),
    "cap:notification_listen": ("notificationlistenerservice", "bind_notification_listener"),
}


def capability_tokens(tokens: Iterable[str]) -> set[str]:
    """The `cap:<name>` aggregates present in a token set (case-insensitive)."""
    lowered = [t.lower() for t in tokens]
    out: set[str] = set()
    for cap, needles in _CAPABILITY_GROUPS.items():
        if any(any(nd in t for nd in needles) for t in lowered):
            out.add(cap)
    return out


def augment_with_capabilities(tokens: Iterable[str]) -> set[str]:
    """Meaningful tokens plus their capability aggregates — the final feature set.

    Applied identically by the dataset builder and the predictor so the columns
    a row is scored against always match the columns the model was trained on.
    """
    toks = set(tokens)
    return toks | capability_tokens(toks)


@dataclass
class CorpusVocabulary:
    """A ``{token: column}`` map learned from the corpus, not from LAMDA."""

    index: dict[str, int]
    names: list[str]
    document_frequency: dict[str, int]
    n_documents: int

    @property
    def size(self) -> int:
        return len(self.names)

    def save(self, path: str | Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({
            "names": self.names,
            "document_frequency": self.document_frequency,
            "n_documents": self.n_documents,
        }))

    @classmethod
    def load(cls, path: str | Path) -> "CorpusVocabulary":
        path = Path(path)
        if not path.is_file():
            raise SystemExit(
                f"unified vocabulary not found at {path}.\n"
                "Build it with:\n"
                "    $SENTINEL_PYTHON tools/build_unified_dataset.py build")
        raw = json.loads(path.read_text())
        names = list(raw["names"])
        return cls(
            index={name: i for i, name in enumerate(names)},
            names=names,
            document_frequency=dict(raw.get("document_frequency", {})),
            n_documents=int(raw.get("n_documents", 0)),
        )


def build_vocabulary(token_sets: Iterable[Iterable[str]], *,
                     min_df: int = 5, max_df_ratio: float = 0.98) -> CorpusVocabulary:
    """Learn the column space from per-sample token sets.

    ``token_sets`` is one iterable of tokens per document (deduplicated per
    document by construction — ``Extraction.tokens`` is a set). A token becomes
    a column iff ``min_df <= df <= max_df_ratio * N``. Column order is by
    descending document frequency then token name, so the ordering is stable
    and re-deriving the same corpus gives byte-identical columns.
    """
    df: Counter[str] = Counter()
    n_docs = 0
    for tokens in token_sets:
        n_docs += 1
        for tok in set(tokens):
            df[tok] += 1

    max_df = int(max_df_ratio * n_docs) if n_docs else 0
    kept = [(tok, c) for tok, c in df.items() if min_df <= c <= max_df]
    kept.sort(key=lambda tc: (-tc[1], tc[0]))

    names = [tok for tok, _ in kept]
    return CorpusVocabulary(
        index={tok: i for i, tok in enumerate(names)},
        names=names,
        document_frequency={tok: c for tok, c in kept},
        n_documents=n_docs,
    )


def vectorise_unified(tokens: Iterable[str],
                      vocab: CorpusVocabulary) -> tuple[np.ndarray, dict[str, Any]]:
    """Token set -> int8 vector over the corpus vocabulary, plus diagnostics."""
    vec = np.zeros(vocab.size, dtype=np.int8)
    hits_by_family: dict[str, int] = {}
    for tok in set(tokens):
        col = vocab.index.get(tok)
        if col is not None:
            vec[col] = 1
            fam = tok.split("_", 1)[0]
            hits_by_family[fam] = hits_by_family.get(fam, 0) + 1
    nonzero = int(vec.sum())
    return vec, {
        "nonzero": nonzero,
        "density": round(nonzero / vocab.size, 5) if vocab.size else 0.0,
        "hits_by_family": dict(sorted(hits_by_family.items())),
        "plausible": nonzero >= MIN_PLAUSIBLE_NONZERO,
    }
