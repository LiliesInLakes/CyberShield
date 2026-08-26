"""Structural tests for the 2024–2026 emerging-technique rules and for the
"two token groups maximum" repair of the previously dead rules.

These are structure tests, not detection tests. They exist because the three
ways this ruleset has broken before were all structural and all invisible to a
passing pipeline:

* a behaviour rule that reaches the raw ZIP container proves nothing and
  measured 82 benign false positives against 0 malware hits (T28);
* a rule keyed on one ~100%-base-rate primitive (`AccessibilityService`,
  `CookieManager`, MediaProjection) fires on everything (T6/T23);
* a rule requiring four or five co-located groups fires on nothing (B29), and
  nothing in the test suite noticed for a whole corpus run.

A detection *rate* cannot be asserted here — that needs the corpus and belongs
to `tools/rule_firing_report.py`.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
for _p in (str(REPO_ROOT), str(REPO_ROOT / "L1")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import spine  # noqa: E402
from engines import yara_scan  # noqa: E402

yara = pytest.importorskip("yara")

YARA_DIR = REPO_ROOT / "L1" / "yara_templates"
NEW_FILE = YARA_DIR / "apk_emerging_techniques_2026.yar"

# Rules whose over-conjunctive conditions were reduced to two token groups.
# Listed explicitly so that re-introducing a third group anywhere is a test
# failure rather than a quiet regression discovered at the next corpus run.
REPAIRED_RULES = {
    "Android_Ransomware_Generic_File_Encryption",
    "Android_Ransomware_Locker_Screen",
    "Android_Spyware_SMS_Call_Log_Harvester",
    "Android_Spyware_Generic_GPS_Surveillance",
    "Android_Suspicious_Command_Execution",
    "Android_Fraud_SMS_Subscription_Abuse",
    "Android_Fraud_Click_Jacking_Tapjacking",
    "Android_Evasion_Anti_Analysis_VirtualMachine",
    "Android_Dropper_Native_Library_Loader",
    "Android_Banking_Zanubis_AccessibilityOverlay",
    "Android_Banking_TaxiSpy_RAT",
    "Android_Banking_Ankara_Stealer",
    "Android_India_Drinik_ITR_Impersonation",
    "Android_India_UPI_Targeting",
    "Android_India_SMS_OTP_Stealer",
    "Android_India_FakeBank_App",
}

# Literals a regex string would match, so the T25 self-match check can build a
# buffer for rules whose groups are regex-only.
_REGEX_SAMPLES = {
    "Android_USSD_Shortcode_Abuse": ["*123*4#"],
}

_RULE_SPLIT = re.compile(r"(?=^rule\s+\w+)", re.M)


def _rule_blocks(text: str) -> list[tuple[str, str]]:
    out = []
    for block in _RULE_SPLIT.split(text):
        m = re.match(r"rule\s+(\w+)", block.strip())
        if m:
            out.append((m.group(1), block))
    return out


def _condition(block: str) -> str:
    m = re.search(r"condition:(.*?)\n\}", block, re.S)
    return m.group(1) if m else ""


def _top_level_and_clauses(cond: str) -> list[str]:
    """Split a condition on `and` at parenthesis depth 0 — one clause per group."""
    depth = 0
    clauses: list[str] = []
    buf = ""
    tokens = re.split(r"(\(|\)|\band\b)", cond)
    for tok in tokens:
        if tok == "(":
            depth += 1
            buf += tok
        elif tok == ")":
            depth -= 1
            buf += tok
        elif tok == "and" and depth == 0:
            clauses.append(buf)
            buf = ""
        else:
            buf += tok
    clauses.append(buf)
    return [c.strip() for c in clauses if c.strip()]


# ---------------------------------------------------------------------------
# The new file
# ---------------------------------------------------------------------------

def test_emerging_file_is_included_in_the_index():
    assert 'include "apk_emerging_techniques_2026.yar"' in (YARA_DIR / "index.yar").read_text()


def test_all_three_rulesets_still_compile():
    """Container / source / member rulesets are built by three different
    transformations of the same text; a rule can compile standalone and still
    break one of them (an unreferenced string after stripping, for example)."""
    assert yara_scan._compile_rules()
    assert yara_scan._compile_source_rules()
    assert yara_scan._compile_member_rules()


def test_emerging_rules_never_reach_the_container_pass():
    """T28: a behaviour conjunction evaluated over a deflated ZIP is meaningless,
    and the last time behaviour rules were allowed into the container pass one of
    them scored 82 benign hits against 0 malware hits."""
    container_only = yara_scan._filter_scope(NEW_FILE.read_text(),
                                             target_scope="apk", strict=True)
    assert not _rule_blocks(container_only), (
        'a rule in apk_emerging_techniques_2026.yar declares scope = "apk" and '
        "would be evaluated against the raw container")


def test_emerging_rules_declare_capitalised_severity_and_known_category():
    """T11 (severity map was case-sensitive) and T12 (a missing category hides a
    real detection in `other`, out of reach of the headline metric)."""
    known = spine.MALWARE_CATEGORIES | {"evasion", "packing_obfuscation",
                                        "notification_abuse", "screen_capture",
                                        "messaging_c2", "other"}
    blocks = _rule_blocks(NEW_FILE.read_text())
    assert len(blocks) == 8, "one rule per technique category from the gap research"
    for name, block in blocks:
        meta = block.split("strings:")[0]
        sev = re.search(r'severity\s*=\s*"(\w+)"', meta)
        cat = re.search(r'category\s*=\s*"(\w+)"', meta)
        assert sev, f"{name}: no severity"
        assert cat, f"{name}: no category"
        assert sev.group(1)[0].isupper(), f"{name}: severity must be capitalised"
        assert cat.group(1) in known, f"{name}: unknown category {cat.group(1)}"


def test_no_emerging_rule_fires_on_a_single_primitive():
    """Every capability in this file has a legitimate counterpart, several with a
    ~100% benign base rate (T23). No rule may be satisfiable by one group."""
    for name, block in _rule_blocks(NEW_FILE.read_text()):
        cond = _condition(block)
        assert len(_top_level_and_clauses(cond)) == 2, (
            f"{name}: expected exactly two token groups, got {cond.strip()!r}")


def test_emerging_strings_match_both_dex_and_java_representations():
    """T22: a dex records an invoke as an operand, jadx as a call expression.
    A bare method name is a substring of both; punctuation anchors one only."""
    for literal in re.findall(r'\$\w+\s*=\s*"([^"]+)"', NEW_FILE.read_text()):
        assert "(" not in literal and ";" not in literal, (
            f"{literal!r} is anchored to one representation")


def test_emerging_rules_self_match_their_own_strings():
    """T25: compile each rule alone against a buffer of its own declared string
    literals. A rule that cannot match that is broken; one that can is telling
    you something about the corpus instead."""
    for name, block in _rule_blocks(NEW_FILE.read_text()):
        body = block[:block.rfind("}") + 1]
        section = re.search(r"strings:(.*?)condition:", body, re.S)
        assert section, f"{name}: no strings section"
        literals = re.findall(r'\$\w+\s*=\s*"([^"]+)"', section.group(1))
        literals += _REGEX_SAMPLES.get(name, [])
        buf = "\n".join(literals).encode()
        rules = yara.compile(source=body)
        assert rules.match(data=buf), f"{name}: does not match its own strings"


# ---------------------------------------------------------------------------
# The repaired rules
# ---------------------------------------------------------------------------

def test_repaired_rules_use_at_most_two_token_groups():
    """B29's dead rules all failed the same way: four or five `N of ($group*)`
    clauses ANDed together, requiring a whole malware kit inside one class. The
    byte gates are stripped before the source and member passes, so they are
    stripped here too — only real token groups are counted."""
    blocks = _all_repaired_blocks()
    missing = REPAIRED_RULES - set(blocks)
    assert not missing, f"repaired rules no longer found in the ruleset: {missing}"
    for name, block in blocks.items():
        clauses = _top_level_and_clauses(_condition(block))
        assert len(clauses) <= 2, (
            f"{name}: {len(clauses)} token groups after repair — "
            f"over-conjunctive conditions are what made it dead: {clauses}")


def _all_repaired_blocks() -> dict[str, str]:
    blocks: dict[str, str] = {}
    for path in sorted(YARA_DIR.glob("*.yar")):
        if path.name == "index.yar":
            continue
        for name, block in _rule_blocks(yara_scan._strip_byte_checks(path.read_text())):
            if name in REPAIRED_RULES:
                blocks[name] = block
    return blocks


def test_clipboard_upi_regex_is_anchored_to_a_real_psp_handle():
    """`/[a-zA-Z0-9._-]+@[a-zA-Z]+/` matches every e-mail address in every licence
    header. Measured at A4: 100/604 benign against 6/640 malware, weight −2.97 —
    the most anti-discriminative signal in the system."""
    text = (YARA_DIR / "apk_clipboard_notification.yar").read_text()
    upi = re.search(r"\$upi_id\s*=\s*/(.+?)/\s", text)
    assert upi, "the UPI VPA pattern is gone — was it renamed?"
    assert "oksbi" in upi.group(1) or "ybl" in upi.group(1), (
        "the UPI pattern must require a real PSP handle, not any @word")
