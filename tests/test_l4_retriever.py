"""L4 RAG retrieval — TF-IDF + cosine similarity over ``L4/knowledge/kb.json``.

Exercises the interface contract in ``decisions/plan_l4_agentic_verdicts.md``
§6 (``KBMatch`` shape, ``retrieve()`` signature) against the real built KB,
so a regression here also means the shipped ``kb.json`` stopped being able to
ground the canonical SMS-interception case (T1636.004) that the rest of the
L4 pipeline is verified against.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from L4.knowledge.retriever import KBMatch, retrieve  # noqa: E402


def test_sms_interception_query_matches_known_entry():
    matches = retrieve(
        "Registers a BroadcastReceiver for SMS_RECEIVED, reads the SMS PDU "
        "and forwards the OTP message body to a remote server using "
        "SmsManager and HttpURLConnection",
        top_k=3,
        min_sim=0.3,
    )

    assert matches, "expected at least one match above threshold for an SMS-interception query"
    assert all(isinstance(m, KBMatch) for m in matches)

    # At least one of the top matches should be identifiably SMS-related —
    # either the MITRE technique, the BFSI YARA rule, or the curated India
    # entry, all of which exist in the KB for exactly this behaviour.
    sms_related = [
        m for m in matches
        if "T1636.004" in m.mitre_techniques
        or "sms" in m.kb_id.lower()
        or "sms" in m.title.lower()
    ]
    assert sms_related, f"no SMS-related match in top results: {matches}"
    assert sms_related[0].similarity >= 0.3


def test_matches_are_sorted_descending_by_similarity():
    matches = retrieve(
        "overlay attack WindowManager addView TYPE_APPLICATION_OVERLAY fake login screen",
        top_k=5,
        min_sim=0.05,
    )
    sims = [m.similarity for m in matches]
    assert sims == sorted(sims, reverse=True)


def test_top_k_is_respected():
    matches = retrieve(
        "accessibility service abuse performGlobalAction dispatchGesture banking overlay sms",
        top_k=2,
        min_sim=0.0,
    )
    assert len(matches) <= 2

    matches_more = retrieve(
        "accessibility service abuse performGlobalAction dispatchGesture banking overlay sms",
        top_k=10,
        min_sim=0.0,
    )
    assert len(matches_more) <= 10
    assert len(matches_more) >= len(matches)


def test_returns_empty_list_below_threshold():
    # An absurdly high threshold that nothing can clear.
    matches = retrieve("SMS interception banking trojan", top_k=3, min_sim=0.999)
    assert matches == []


def test_irrelevant_query_returns_no_matches_at_default_threshold():
    matches = retrieve(
        "a recipe for baking chocolate chip cookies with butter and sugar",
        top_k=3,
        min_sim=0.3,
    )
    assert matches == []


def test_kbmatch_fields_populated_for_known_query():
    matches = retrieve(
        "accessibility service onAccessibilityEvent performGlobalAction "
        "dispatchGesture BIND_ACCESSIBILITY_SERVICE auto-click banking app",
        top_k=3,
        min_sim=0.3,
    )
    assert matches, "expected a match for an accessibility-abuse query"
    top = matches[0]
    assert isinstance(top.kb_id, str) and top.kb_id
    assert isinstance(top.title, str) and top.title
    assert isinstance(top.similarity, float)
    assert 0.0 <= top.similarity <= 1.0
    assert isinstance(top.mitre_techniques, list)


def test_min_sim_filters_out_weak_matches():
    query = "SMS interception OTP banking trojan"
    loose = retrieve(query, top_k=10, min_sim=0.0)
    strict = retrieve(query, top_k=10, min_sim=0.3)
    assert len(strict) <= len(loose)
    assert all(m.similarity >= 0.3 for m in strict)
