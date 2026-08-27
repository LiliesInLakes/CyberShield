"""L6/recommend_verify.py -- mechanical checking of proposed next-step
actions.

Same two-failure-direction discipline as ``tests/test_l4_verify.py``:
keeping a fabricated action/citation is dangerous (it puts an unsupported
recommendation in front of an analyst who may act on it), but dropping a
*valid* action is not the safe fallback either -- it silently makes the
system look less useful than it is and, at the limit, could suppress a
correct escalation. Both directions get positive AND negative tests here,
mirroring test_l4_verify.py's own explicit warning about testing only the
"drops bad claims" direction and missing "drops good claims too."
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from L6.recommend_verify import verify_actions  # noqa: E402

FINDING_IDS = {"F001", "F002"}
SOP_KB_IDS = {"sop:cert_in:6hr_reporting", "sop:mitre:M1011:T1636.004"}
IOC_VALUES = {"192.227.137.154", "http://evil.example/gate.php"}


def _base_kwargs():
    return dict(finding_ids=FINDING_IDS, sop_kb_ids=SOP_KB_IDS, ioc_values=IOC_VALUES)


# --------------------------------------------------------------------------
# Positive: a valid action survives unchanged
# --------------------------------------------------------------------------

def test_valid_action_with_valid_finding_citation_is_kept():
    proposed = [{
        "action": "escalate_cert_in",
        "rationale": "Confirmed malicious, matches CERT-In reportable criteria.",
        "citations": [{"kind": "finding", "id": "F001"}],
    }]
    result = verify_actions(proposed, **_base_kwargs())
    assert result.drop_count == 0
    assert len(result.kept) == 1
    assert result.kept[0]["action"] == "escalate_cert_in"
    assert result.kept[0]["citations"] == [{"kind": "finding", "id": "F001"}]


def test_valid_action_with_valid_kb_citation_is_kept():
    proposed = [{
        "action": "monitor_only",
        "rationale": "Grounded in SOP guidance.",
        "citations": [{"kind": "kb", "id": "sop:mitre:M1011:T1636.004"}],
    }]
    result = verify_actions(proposed, **_base_kwargs())
    assert result.drop_count == 0
    assert len(result.kept) == 1


def test_valid_block_ioc_with_real_ioc_is_kept():
    proposed = [{
        "action": "block_ioc",
        "rationale": "Known C2 endpoint.",
        "citations": [{"kind": "finding", "id": "F002"}],
        "ioc_value": "192.227.137.154",
    }]
    result = verify_actions(proposed, **_base_kwargs())
    assert result.drop_count == 0
    assert result.kept[0]["ioc_value"] == "192.227.137.154"


# --------------------------------------------------------------------------
# Negative: each of the four mechanical checks actually rejects
# --------------------------------------------------------------------------

def test_unknown_action_string_is_dropped():
    proposed = [{
        "action": "call_the_police",  # not in the fixed Action taxonomy
        "rationale": "x",
        "citations": [{"kind": "finding", "id": "F001"}],
    }]
    result = verify_actions(proposed, **_base_kwargs())
    assert result.drop_count == 1
    assert result.dropped[0]["reason"] == "unknown_action"
    assert result.kept == []


def test_citation_to_nonexistent_finding_is_dropped():
    proposed = [{
        "action": "escalate_cert_in",
        "rationale": "x",
        "citations": [{"kind": "finding", "id": "F999"}],  # doesn't exist
    }]
    result = verify_actions(proposed, **_base_kwargs())
    assert result.drop_count == 1
    assert result.dropped[0]["reason"] == "no_supporting_evidence"


def test_citation_to_nonexistent_kb_entry_is_dropped():
    proposed = [{
        "action": "monitor_only",
        "rationale": "x",
        "citations": [{"kind": "kb", "id": "sop:made:up:entry"}],
    }]
    result = verify_actions(proposed, **_base_kwargs())
    assert result.drop_count == 1
    assert result.dropped[0]["reason"] == "no_supporting_evidence"


def test_block_ioc_citing_unextracted_indicator_is_dropped():
    proposed = [{
        "action": "block_ioc",
        "rationale": "x",
        "citations": [{"kind": "finding", "id": "F001"}],
        "ioc_value": "10.10.10.10",  # never extracted from this sample
    }]
    result = verify_actions(proposed, **_base_kwargs())
    assert result.drop_count == 1
    assert result.dropped[0]["reason"] == "ioc_not_extracted"


def test_action_with_one_bad_and_one_good_citation_keeps_the_good_one():
    proposed = [{
        "action": "escalate_cert_in",
        "rationale": "x",
        "citations": [
            {"kind": "finding", "id": "F999"},  # fabricated
            {"kind": "finding", "id": "F001"},   # real
        ],
    }]
    result = verify_actions(proposed, **_base_kwargs())
    assert result.drop_count == 0
    assert result.kept[0]["citations"] == [{"kind": "finding", "id": "F001"}]


def test_action_with_only_bad_citations_is_dropped_entirely():
    proposed = [{
        "action": "escalate_cert_in",
        "rationale": "x",
        "citations": [{"kind": "finding", "id": "F999"}],
    }]
    result = verify_actions(proposed, **_base_kwargs())
    assert result.drop_count == 1
    assert result.dropped[0]["reason"] == "no_supporting_evidence"


def test_malformed_entry_does_not_crash():
    proposed = ["not a dict", 42, None, {"action": "monitor_only"}]  # last has no citations
    result = verify_actions(proposed, **_base_kwargs())
    # "not a dict"/42/None -> malformed_entry; the dict with no citations -> no_supporting_evidence
    assert result.drop_count == 4
    assert result.kept == []


def test_empty_proposed_list_is_fine():
    result = verify_actions([], **_base_kwargs())
    assert result.kept == []
    assert result.dropped == []
