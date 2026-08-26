"""Tests for the dex scan path and the BFSI rule set.

These pin the two properties that the 92%-gap fix depends on, both of which were
got wrong at least once while building it:

  * a **member** is not the **container**, so member scanning must not inherit the
    container's ZIP-magic gate; and
  * a **dex is the whole app concatenated**, so it must be scanned per class or it
    reproduces the batch-blob false positives that T2 fixed for Java sources.

Run:  ./env/bin/python -m pytest tests/test_dex_scanning.py -q
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest
import yara

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "L1"))

from engines import yara_scan  # noqa: E402
import spine  # noqa: E402

YARA_DIR = REPO_ROOT / "L1" / "yara_templates"


# ---------------------------------------------------------------------------
# The container gate
# ---------------------------------------------------------------------------

def test_member_ruleset_has_no_container_gates():
    """A classes.dex starts with `dex\\n035`; a rule gated on ZIP magic can never
    match it, which is what made the scanner blind to the app's own strings."""
    text = "\n".join(yara_scan._strip_byte_checks(t) for _, t in yara_scan._rule_sources())
    assert "uint32be(0) == 0x504B0304" not in text
    assert not re.search(r"filesize\s*<\s*\d+\s*MB", text)


def test_container_ruleset_keeps_its_gates():
    """Structural rules are *supposed* to assert ZIP geometry — on the container."""
    text = "\n".join(t for _, t in yara_scan._rule_sources())
    assert "uint32be(0) == 0x504B0304" in text


def test_member_and_container_rulesets_are_different_objects():
    assert yara_scan._get_rules() is not yara_scan._get_member_rules()


def test_structural_rules_are_excluded_from_the_member_ruleset():
    """Stripped of its gates, a pure-geometry rule has no condition left and would
    match every member of every APK."""
    degenerate = '''
    rule Pure_Structure {
        meta:
            description = "container geometry only"
        condition:
            uint32be(0) == 0x504B0304 and filesize < 50MB
    }
    '''
    assert not yara_scan._is_content_rule(degenerate)

    content = '''
    rule Real_Content {
        strings:
            $a = "SmsManager"
        condition:
            uint32be(0) == 0x504B0304 and $a
    }
    '''
    assert yara_scan._is_content_rule(content)


def test_a_gated_rule_cannot_match_a_dex_but_an_ungated_one_can():
    """The measurement the whole fix rests on, reproduced from first principles."""
    dex_like = b"dex\n035\x00" + b"Landroid/telephony/SmsManager;->sendTextMessage" * 3
    gated = yara.compile(source='''
        rule G { strings: $a = "SmsManager"
                 condition: uint32be(0) == 0x504B0304 and $a }''')
    ungated = yara.compile(source='''
        rule U { strings: $a = "SmsManager"
                 condition: $a }''')
    assert not gated.match(data=dex_like)
    assert ungated.match(data=dex_like)


# ---------------------------------------------------------------------------
# Per-class granularity
# ---------------------------------------------------------------------------

def test_dex_buffers_are_per_class_not_one_blob():
    """Regression for the FP that whole-dex scanning caused: an expense tracker
    matched both an OTP stealer and a ransomware rule because unrelated library
    classes supplied the other half of each condition."""
    apk = REPO_ROOT / "testing_apps" / "vuln" / "pivaa.apk"
    if not apk.exists():
        pytest.skip("sample APK not present")
    import zipfile
    with zipfile.ZipFile(apk) as zf:
        dex = next(zf.read(n) for n in zf.namelist()
                   if n.startswith("classes") and n.endswith(".dex"))
    buffers = yara_scan._dex_class_buffers(dex)
    assert len(buffers) > 20, "expected one buffer per class, not one per dex"
    assert all(isinstance(name, str) and isinstance(buf, bytes) for name, buf in buffers)
    joined = sum(len(b) for _, b in buffers)
    assert joined < len(dex) * 4, "buffers should summarise a class, not duplicate the dex"


def test_library_namespaces_are_excluded_from_dex_scanning():
    """Same exclusion list the source path uses — third-party SDK code is not the
    app's behaviour, and it is where the whole-dex false positives came from."""
    apk = REPO_ROOT / "testing_apps" / "good_apps" / "org.diekaiju.duckassist_245.apk"
    if not apk.exists():
        pytest.skip("sample APK not present")
    import zipfile
    with zipfile.ZipFile(apk) as zf:
        names = [n for n in zf.namelist() if n.startswith("classes") and n.endswith(".dex")]
        buffers = []
        for n in names:
            buffers += yara_scan._dex_class_buffers(zf.read(n))
    for cls_name, _ in buffers:
        assert not cls_name.startswith(yara_scan._EXCLUDE_SOURCE_PREFIXES)


def test_unparseable_dex_degrades_instead_of_raising():
    assert yara_scan._dex_class_buffers(b"not a dex at all") == []


# ---------------------------------------------------------------------------
# The BFSI rule set
# ---------------------------------------------------------------------------

def test_every_rule_declares_a_category():
    """A rule with no category falls back to a name regex and usually lands in
    `other`, where the malware-category metric cannot see it (T12)."""
    missing = []
    for path in sorted(YARA_DIR.glob("*.yar")):
        if path.name == "index.yar":
            continue
        for block in re.split(r"(?=^rule\s+\w+)", path.read_text(), flags=re.M):
            m = re.match(r"rule\s+(\w+)", block.strip())
            if m and "category" not in block.split("strings:")[0]:
                missing.append(m.group(1))
    assert not missing, f"rules without a category: {missing}"


def test_bfsi_rules_are_included_in_the_index():
    assert 'include "apk_bfsi_primitives.yar"' in (YARA_DIR / "index.yar").read_text()


def test_no_bfsi_rule_fires_on_a_single_primitive():
    """`AccessibilityService` appears in 4 of 4 benign apps — a ~100% base-rate
    token exactly like `self_signed` (T6). Any rule keyed on one primitive alone
    would fire on every benign app that ships an accessibility helper."""
    text = (YARA_DIR / "apk_bfsi_primitives.yar").read_text()
    conditions = re.findall(r"condition:\s*\n\s*(.+)", text)
    assert conditions, "no conditions parsed"
    for cond in conditions:
        assert " and " in cond, f"single-primitive BFSI condition: {cond!r}"


def test_bfsi_strings_match_both_dex_and_java_representations():
    """A dex records `Landroid/telephony/SmsManager;->sendTextMessage`; jadx emits
    `SmsManager.getDefault().sendTextMessage(`. Bare method names are substrings
    of both — a rule anchored to Java punctuation would only ever see one."""
    text = (YARA_DIR / "apk_bfsi_primitives.yar").read_text()
    for literal in re.findall(r'\$\w+\s*=\s*"([^"]+)"', text):
        assert "(" not in literal and ";" not in literal, (
            f"{literal!r} is anchored to one representation")


def test_bfsi_categories_are_recognised_malware_categories():
    text = (YARA_DIR / "apk_bfsi_primitives.yar").read_text()
    cats = set(re.findall(r'category\s*=\s*"(\w+)"', text))
    assert cats, "no categories declared"
    known = spine.MALWARE_CATEGORIES | {"evasion", "packing_obfuscation",
                                        "notification_abuse", "other"}
    assert cats <= known, f"unknown categories: {cats - known}"
    assert cats & spine.MALWARE_CATEGORIES, "BFSI rules must reach the headline metric"
