"""L4's network content-correlation — match, no-match, and case-sensitivity behaviour.

Confirms `correlate` is a content match only (see `L4/network_correlation.py`
docstring for why this is not causal attribution), and that it tolerates the
shapes of `network_evidence` dict that actually exist in this codebase: the
assembled `dynamic.json` "network" block (`c2_endpoints`/`data_exfiltrated`)
and the raw mitmproxy log (`host`/`url` per entry).
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from L4.network_correlation import correlate  # noqa: E402


def test_matches_against_c2_endpoints():
    evidence = {"c2_endpoints": ["http://192.168.1.100/gate.php"]}
    result = correlate(["192.168.1.100", "unrelated_string"], evidence)
    assert result == ["192.168.1.100"]


def test_matches_against_data_exfiltrated():
    evidence = {"data_exfiltrated": ["evil-collector.example.com"]}
    result = correlate(["evil-collector.example.com"], evidence)
    assert result == ["evil-collector.example.com"]


def test_matches_against_raw_entries_host_and_url():
    evidence = {"entries": [
        {"host": "c2.badhost.ru", "url": "http://c2.badhost.ru/gate.php"},
        {"host": "cdn.google.com", "url": "http://cdn.google.com/ok.js"},
    ]}
    result = correlate(["c2.badhost.ru", "cdn.google.com"], evidence)
    assert set(result) == {"c2.badhost.ru", "cdn.google.com"}


def test_no_match_returns_empty_list():
    evidence = {"c2_endpoints": ["http://192.168.1.100/gate.php"]}
    result = correlate(["totally_unrelated_literal"], evidence)
    assert result == []


def test_no_network_evidence_returns_empty_list():
    result = correlate(["anything"], {})
    assert result == []


def test_non_dict_network_evidence_is_handled_safely():
    assert correlate(["anything"], None) == []  # type: ignore[arg-type]


def test_case_insensitive_match():
    evidence = {"c2_endpoints": ["http://EVIL.EXAMPLE.COM/gate.php"]}
    result = correlate(["evil.example.com"], evidence)
    assert result == ["evil.example.com"]

    evidence_lower = {"c2_endpoints": ["http://evil.example.com/gate.php"]}
    result_upper_literal = correlate(["EVIL.EXAMPLE.COM"], evidence_lower)
    assert result_upper_literal == ["EVIL.EXAMPLE.COM"]


def test_short_literals_are_skipped_to_avoid_coincidental_matches():
    evidence = {"c2_endpoints": ["http://a.io/x"]}
    # "a" and "io" are short obfuscated-identifier-shaped strings; they must
    # not "correlate" just because they happen to be substrings.
    result = correlate(["a", "io"], evidence)
    assert result == []


def test_substring_match_is_bidirectional():
    # class literal is a substring of the captured URL
    evidence = {"c2_endpoints": ["http://192.168.1.100/gate.php"]}
    assert correlate(["192.168.1.100"], evidence) == ["192.168.1.100"]

    # captured host is a substring of a longer class literal
    evidence2 = {"data_exfiltrated": ["badhost.ru"]}
    assert correlate(["www.badhost.ru/upload"], evidence2) == ["www.badhost.ru/upload"]


def test_deduplicates_matched_literals():
    evidence = {"c2_endpoints": ["http://192.168.1.100/gate.php"]}
    result = correlate(["192.168.1.100", "192.168.1.100"], evidence)
    assert result == ["192.168.1.100"]


def test_non_string_literals_are_ignored():
    evidence = {"c2_endpoints": ["http://192.168.1.100/gate.php"]}
    result = correlate([123, None, "192.168.1.100"], evidence)  # type: ignore[list-item]
    assert result == ["192.168.1.100"]
