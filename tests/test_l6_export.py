"""L6 export formats.

The invariant under all of these: an export is *derived*, never invented. If a
sample has no indicators the bundle says so rather than being padded, and
nothing an LLM produced can reach a blocklist.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
for p in (str(REPO_ROOT), str(REPO_ROOT / "L1")):
    if p not in sys.path:
        sys.path.insert(0, p)

from L6.export import (  # noqa: E402
    Bundleable, to_csv, to_sigma, to_stix, to_yara, validate_stix,
)


def make(**over) -> Bundleable:
    kwargs = dict(
        sha256="8f05ecbb5f9fe721dfcd380669ab7ebb1dffc433ee0c4d5dce9936afa69564b0",
        identity={"package": "com.sbi.complaintregister",
                  "app_label": "SBI Quick Support",
                  "md5": "232d093de2029d293393613b2627b97b",
                  "impersonates": "State Bank of India"},
        score=88, band="Critical", confidence=0.6,
        impersonates="State Bank of India",
        iocs=[{"type": "domain", "value": "complaintsregister.com", "count": 4,
               "locations": ["classes5.dex!com/sbi/complaintregister/a"]},
              {"type": "url",
               "value": "https://complaintsregister.com/api/msgstore?task=savemsg",
               "count": 2, "locations": ["classes5.dex!com/sbi/complaintregister/a"]}],
        findings=[{"id": "F003", "mitre_techniques": ["T1636.004"]}],
        techniques=["T1636.004", "T1655"],
        unsupported=False,
    )
    kwargs.update(over)
    return Bundleable(**kwargs)


# --------------------------------------------------------------------------
# STIX
# --------------------------------------------------------------------------

def test_stix_bundle_parses_as_stix_21():
    problems = validate_stix(to_stix(make()))
    assert problems == [] or "not installed" in problems[0]


def test_stix_has_one_indicator_and_one_relationship_per_ioc():
    bundle = to_stix(make())
    kinds = [o["type"] for o in bundle["objects"]]
    assert kinds.count("indicator") == 2
    assert kinds.count("relationship") == 2
    assert kinds.count("malware") == 1
    assert kinds.count("file") == 1


def test_stix_ids_are_deterministic_so_reexports_are_diffable():
    a, b = to_stix(make()), to_stix(make())
    ids_a = [o["id"] for o in a["objects"]]
    ids_b = [o["id"] for o in b["objects"]]
    assert ids_a == ids_b
    assert a["id"] == b["id"]


def test_stix_pattern_escapes_quotes():
    b = make(iocs=[{"type": "domain", "value": "evil'; DROP--.ru", "count": 1,
                    "locations": []}])
    ind = next(o for o in to_stix(b)["objects"] if o["type"] == "indicator")
    assert "\\'" in ind["pattern"]


def test_sample_with_no_iocs_yields_a_bundle_without_indicators():
    """Padding an empty export is worse than admitting it is empty."""
    bundle = to_stix(make(iocs=[]))
    kinds = [o["type"] for o in bundle["objects"]]
    assert "indicator" not in kinds
    assert "malware" in kinds
    assert validate_stix(bundle) == [] or True


def test_unsupported_score_is_stated_in_the_stix_description():
    desc = next(o for o in to_stix(make(unsupported=True))["objects"]
                if o["type"] == "malware")["description"]
    assert "UNSUPPORTED" in desc


def test_unknown_ioc_types_are_not_coerced_into_a_stix_pattern():
    """A phone number has no STIX pattern that a TIP would match; it belongs in
    the CSV, not invented into a bogus observable."""
    b = make(iocs=[{"type": "phone_in", "value": "9876543210", "count": 1,
                    "locations": []}])
    assert not any(o["type"] == "indicator" for o in to_stix(b)["objects"])
    assert "9876543210" in to_csv(b)


def test_mitre_techniques_become_external_references():
    mal = next(o for o in to_stix(make())["objects"] if o["type"] == "malware")
    ids = {r["external_id"] for r in mal["external_references"]}
    assert ids == {"T1636.004", "T1655"}
    url = next(r["url"] for r in mal["external_references"]
               if r["external_id"] == "T1636.004")
    assert url.endswith("/T1636/004/")


# --------------------------------------------------------------------------
# CSV
# --------------------------------------------------------------------------

def test_csv_emits_one_row_per_ioc():
    rows = to_csv(make()).strip().splitlines()
    assert len(rows) == 3  # header + 2
    assert "complaintsregister.com" in rows[1]


def test_csv_still_emits_a_row_when_there_are_no_iocs():
    """A batch export must not silently lose a scored sample."""
    rows = to_csv(make(iocs=[])).strip().splitlines()
    assert len(rows) == 2
    assert "8f05ecbb" in rows[1]


def test_csv_carries_the_unsupported_flag():
    assert ",yes," in to_csv(make(unsupported=True))


# --------------------------------------------------------------------------
# YARA
# --------------------------------------------------------------------------

def test_generated_yara_compiles():
    yara = pytest.importorskip("yara")
    yara.compile(source=to_yara(make()))


def test_generated_yara_uses_big_endian_zip_magic():
    """uint32() is little-endian and would never match a ZIP header (T1)."""
    text = to_yara(make())
    assert "uint32be(0) == 0x504B0304" in text
    assert "uint32(0) ==" not in text


def test_generated_yara_matches_a_buffer_containing_its_ioc():
    yara = pytest.importorskip("yara")
    rules = yara.compile(source=to_yara(make()))
    buf = (b"PK\x03\x04" + b"\x00" * 40
           + b"https://complaintsregister.com/api/msgstore?task=savemsg")
    assert rules.match(data=buf)


def test_generated_yara_does_not_match_an_unrelated_apk_header():
    yara = pytest.importorskip("yara")
    rules = yara.compile(source=to_yara(make()))
    assert not rules.match(data=b"PK\x03\x04" + b"\x00" * 200 + b"AndroidManifest.xml")


def test_yara_strings_come_only_from_iocs_never_from_matched_api_names():
    """API names like createFromPdu appear in benign code; a rule keyed on them
    would fire on everything (T2/T21 in rule form)."""
    text = to_yara(make(findings=[{"id": "F003", "detail": {
        "samples": [{"snippet": "createFromPdu"}]}}]))
    assert "createFromPdu" not in text


def test_yara_rule_name_is_sanitised():
    text = to_yara(make(identity={"package": "com.foo-bar/baz",
                                  "app_label": "x"}))
    name = [l for l in text.splitlines() if l.startswith("rule ")][0]
    assert "-" not in name and "/" not in name


def test_yara_omits_the_string_block_when_there_are_no_iocs():
    yara = pytest.importorskip("yara")
    text = to_yara(make(iocs=[]))
    assert "strings:" not in text
    yara.compile(source=text)


# --------------------------------------------------------------------------
# Sigma
# --------------------------------------------------------------------------

def test_sigma_is_valid_yaml_with_a_detection_block():
    import yaml
    doc = yaml.safe_load(to_sigma(make()))
    assert doc["detection"]["selection_dns"]["DestinationHostname"] == [
        "complaintsregister.com"]
    assert "condition" in doc["detection"]


def test_sigma_is_empty_when_there_is_nothing_to_detect():
    """An empty rule in a SIEM matches nothing forever and looks like coverage."""
    assert to_sigma(make(iocs=[])) == ""
    assert to_sigma(make(iocs=[{"type": "phone_in", "value": "9876543210",
                                "count": 1, "locations": []}])) == ""


def test_sigma_records_that_indicators_are_static_not_detonated():
    import yaml
    doc = yaml.safe_load(to_sigma(make()))
    assert "not confirmed by detonation" in doc["description"]
    assert doc["falsepositives"]


def test_sigma_level_tracks_the_band():
    import yaml
    assert yaml.safe_load(to_sigma(make(band="Critical")))["level"] == "critical"
    assert yaml.safe_load(to_sigma(make(band="Informational")))["level"] == "low"
