"""Unit tests for the corpus-derived, pipeline-native L3 feature space.

These pin the guards that keep the unified model honest: the relevance filter
that drops library-signature noise (the ML form of T27/T28), the
document-frequency band that drops per-sample and base-rate tokens, and the
density floor that refuses a vector that did not really extract.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from L3.unified_features import (  # noqa: E402
    MIN_PLAUSIBLE_NONZERO, build_vocabulary, is_meaningful, meaningful_tokens,
    vectorise_unified,
)


# --- relevance filter -------------------------------------------------------

def test_permissions_and_intents_are_always_meaningful():
    assert is_meaningful("RequestedPermissionList_android.permission.RECEIVE_SMS")
    assert is_meaningful("IntentFilterList_android.provider.Telephony.SMS_RECEIVED")
    assert is_meaningful("HardwareComponentsList_android.hardware.telephony")


def test_security_apis_kept_library_and_app_calls_dropped():
    # SMS / dex-loading / crypto are capability signals -> kept
    assert is_meaningful("SuspiciousApiList_Landroid/telephony/SmsManager.sendTextMessage")
    assert is_meaningful("RestrictedApiList_dalvik.system.DexClassLoader.loadClass")
    assert is_meaningful("SuspiciousApiList_Ljavax/crypto/Cipher.doFinal")
    # androidx / kotlin / app-own library signatures -> dropped as noise
    assert not is_meaningful("SuspiciousApiList_Landroidx/appcompat/app/AppCompatActivity.onCreate")
    assert not is_meaningful("RestrictedApiList_kotlinx.coroutines.Job.cancel")
    assert not is_meaningful("SuspiciousApiList_Lcom/example/myapp/MainActivity.foo")


def test_component_class_names_are_dropped():
    # Activity/Service/Receiver class names are app-specific, not behaviour.
    assert not is_meaningful("ActivityList_com.example.myapp.MainActivity")
    assert not is_meaningful("ServiceList_.PayloadService")


def test_meaningful_tokens_filters_a_mixed_set():
    raw = {
        "RequestedPermissionList_android.permission.SEND_SMS",
        "SuspiciousApiList_Landroid/telephony/SmsManager.sendTextMessage",
        "SuspiciousApiList_Landroidx/core/app/NotificationCompat.build",
        "ActivityList_com.foo.Bar",
    }
    kept = meaningful_tokens(raw)
    assert "RequestedPermissionList_android.permission.SEND_SMS" in kept
    assert "SuspiciousApiList_Landroid/telephony/SmsManager.sendTextMessage" in kept
    assert len(kept) == 2


# --- vocabulary band --------------------------------------------------------

def _doc(*toks):
    return set(toks)


def test_singletons_and_ubiquitous_tokens_are_dropped():
    docs = [
        _doc("a", "b", "unique_to_doc0"),
        _doc("a", "b"),
        _doc("a", "b"),
        _doc("a", "b"),
        _doc("a", "b", "c"),
    ]
    # a,b are in every doc (ubiquitous); unique_to_doc0 appears once.
    vocab = build_vocabulary(docs, min_df=2, max_df_ratio=0.9)
    assert "unique_to_doc0" not in vocab.index      # below min_df
    assert "a" not in vocab.index and "b" not in vocab.index  # above max_df
    assert "c" not in vocab.index                   # df=1, below min_df=2


def test_vocabulary_is_ordered_by_descending_document_frequency():
    docs = [_doc("hi", "mid"), _doc("hi", "mid"), _doc("hi"), _doc("hi")]
    vocab = build_vocabulary(docs, min_df=1, max_df_ratio=1.0)
    assert vocab.names[0] == "hi"      # df 4 before df 2
    assert vocab.names.index("hi") < vocab.names.index("mid")


# --- vectorise / density floor ---------------------------------------------

def test_vectorise_sets_only_known_columns():
    docs = [_doc("x", "y"), _doc("x", "y"), _doc("x", "z"), _doc("x")]
    vocab = build_vocabulary(docs, min_df=1, max_df_ratio=1.0)
    vec, diag = vectorise_unified({"x", "unknown_token"}, vocab)
    assert vec[vocab.index["x"]] == 1
    assert diag["nonzero"] == 1          # unknown_token contributes nothing


def test_density_floor_marks_a_near_empty_vector_implausible():
    docs = [_doc(*[f"t{i}" for i in range(50)]) for _ in range(5)]
    vocab = build_vocabulary(docs, min_df=1, max_df_ratio=1.0)
    _, diag = vectorise_unified({"t0"}, vocab)      # one hit, below the floor
    assert diag["nonzero"] < MIN_PLAUSIBLE_NONZERO
    assert diag["plausible"] is False
    _, diag2 = vectorise_unified({f"t{i}" for i in range(10)}, vocab)
    assert diag2["plausible"] is True
