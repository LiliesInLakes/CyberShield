"""IOC extraction — mostly regression tests for false positives.

Every assertion below that looks paranoid is one the benign controls actually
produced. The first version of this extractor reported three Indian mobile
numbers as SMS-exfil destinations in a confirmed banking trojan; they were byte
runs inside Material Design drawables present in every APK ever built against
AndroidX. That is T7's failure mode in a new detector, so the guards get tests.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
for p in (str(REPO_ROOT), str(REPO_ROOT / "L1")):
    if p not in sys.path:
        sys.path.insert(0, p)

from engines.ioc_extract import (  # noqa: E402
    IOC, SCOPE_CODE, SCOPE_RESOURCE, _is_infra_host, _is_private_ip,
    _plausible_host, extract_from_bytes, merge, summarise,
)


def run(data: bytes, scope: str = SCOPE_CODE) -> dict[str, set[str]]:
    sink: dict[tuple[str, str], IOC] = {}
    extract_from_bytes(data, "test", sink, scope)
    out: dict[str, set[str]] = {}
    for (kind, value) in sink:
        out.setdefault(kind, set()).add(value)
    return out


# --------------------------------------------------------------------------
# The real find
# --------------------------------------------------------------------------

def test_extracts_a_real_c2_url_and_its_host():
    """The actual exfil endpoint from the SBI Quick Support trojan."""
    data = b'\x00\x12https://complaintsregister.com/api/msgstore?task=savemsg\x00'
    got = run(data)
    assert "https://complaintsregister.com/api/msgstore?task=savemsg" in got["url"]
    assert "complaintsregister.com" in got["domain"]


def test_extracts_upi_vpa_the_indian_payment_rail():
    got = run(b'\x00pay to fraudster@okhdfcbank now\x00')
    assert "fraudster@okhdfcbank" in got["upi_vpa"]


def test_extracts_telegram_c2():
    got = run(b'\x00https://t.me/exfilbot99\x00')
    assert any("t.me/exfilbot99" in v for v in got["telegram"])


# --------------------------------------------------------------------------
# False positives the benign set caught
# --------------------------------------------------------------------------

def test_digit_patterns_are_not_extracted_from_resources():
    """8955078125 lives in res/drawable in every AndroidX app, not just malware."""
    data = b"\x00\x01\x02" + b"8955078125" + b"\x03\x04\x05"
    assert "phone_in" not in run(data, SCOPE_RESOURCE)
    # In application code the same string is a genuine constant.
    assert "8955078125" in run(data, SCOPE_CODE)["phone_in"]


def test_bare_ipv4_is_never_an_indicator():
    """1.3.6.1 and 1.3.14.3 are ASN.1 OIDs; 82 of one benign app's 121 'IOCs'."""
    got = run(b"\x00OID 1.3.6.1.4.1 and 1.3.14.3.2.26 and 203.0.113.45\x00")
    assert "ipv4" not in got


def test_an_ip_is_recorded_only_as_a_url_host():
    got = run(b"\x00http://203.0.113.45/gate.php\x00")
    assert "203.0.113.45" in got["ipv4"]
    assert "http://203.0.113.45/gate.php" in got["url"]


def test_private_and_reserved_ips_are_not_indicators():
    for ip in ("10.0.0.1", "192.168.1.1", "172.16.0.1", "127.0.0.1", "169.254.1.1"):
        assert _is_private_ip(ip), ip
    assert not _is_private_ip("203.0.113.45")
    assert "ipv4" not in run(b"\x00http://192.168.1.100/gate.php\x00")


def test_bitcoin_is_not_extracted_at_all():
    """Base58 without checksum validation matched two non-addresses in a
    benign note-taking app, one inside a Material Design class."""
    got = run(b"\x00 1r7Y4hRSo4F1Esrbw5SdK9GHD3Q 1xRHSY8o1yNAW8kZYA2Z7MsfdeE \x00")
    assert "bitcoin" not in got


def test_code_identifiers_that_look_like_hosts_are_rejected():
    """btn.click and clicktarget.click are UI code; .click is a real TLD."""
    got = run(b"\x00btn.click clicktarget.click measurement.ga measurement.store\x00")
    assert "domain" not in got or not (
        got["domain"] & {"btn.click", "clicktarget.click",
                         "measurement.ga", "measurement.store"})


def test_package_names_are_not_hostnames():
    got = run(b"\x00com.example.myapp org.jetbrains.kotlin android.util.Log\x00")
    assert "domain" not in got


def test_framework_infrastructure_is_filtered():
    for host in ("schemas.android.com", "www.w3.org", "apache.org",
                 "firebaseio.com", "crashlytics.com", "googleapis.com",
                 "fonts.gstatic.com"):
        assert _is_infra_host(host), host
    got = run(b"\x00https://schemas.android.com/apk/res/android\x00")
    assert not got.get("domain")


def test_infra_filter_is_suffix_matched_not_substring():
    """'notandroid.com' must not be filtered because it ends in 'android.com'
    as a substring — only a real label boundary counts."""
    assert _is_infra_host("foo.android.com")
    assert not _is_infra_host("notandroid.com")
    assert not _is_infra_host("evil-android.com.attacker.ru")


# --------------------------------------------------------------------------
# Host plausibility
# --------------------------------------------------------------------------

def test_bare_hosts_use_a_stricter_tld_set_than_url_hosts():
    # `.click` is fine when a scheme proves it is an endpoint...
    assert _plausible_host("evil.click", bare=False)
    # ...but not when it is a bare string in code.
    assert not _plausible_host("btn.click", bare=True)


def test_implausible_tlds_are_rejected():
    assert not _plausible_host("foo.notarealtld", bare=True)
    assert not _plausible_host("single", bare=True)


# --------------------------------------------------------------------------
# Aggregation
# --------------------------------------------------------------------------

def test_merge_sums_counts_and_unions_locations():
    a = [IOC("domain", "evil.ru", {"classes.dex!a"}, 2)]
    b = [IOC("domain", "evil.ru", {"classes.dex!b"}, 3)]
    merged = merge(a, b)
    assert len(merged) == 1
    assert merged[0].count == 5
    assert merged[0].locations == {"classes.dex!a", "classes.dex!b"}


def test_summarise_counts_distinct_indicators_by_type():
    s = summarise([IOC("domain", "a.ru", set(), 1), IOC("domain", "b.ru", set(), 1),
                   IOC("url", "http://a.ru/x", set(), 1)])
    assert s == {"ioc_count": 3, "ioc_types": {"domain": 2, "url": 1}}


def test_locations_are_recorded_so_a_claim_can_be_checked():
    sink: dict[tuple[str, str], IOC] = {}
    extract_from_bytes(b"\x00https://evil.ru/x\x00", "classes.dex!com/x/Y", sink)
    ioc = next(v for k, v in sink.items() if k[0] == "url")
    assert ioc.locations == {"classes.dex!com/x/Y"}


def test_empty_and_binary_input_do_not_raise():
    assert run(b"") == {}
    assert isinstance(run(bytes(range(256)) * 8), dict)
