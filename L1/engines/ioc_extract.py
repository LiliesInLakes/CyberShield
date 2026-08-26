"""Extract blockable indicators from an APK.

The proposal's third design commitment is *operationalizable output* — "blockable
IOCs, auto-generated YARA/Sigma rules, STIX export". Measured before writing
this: across 1,248 spines there were **zero** network indicators of any kind.
The YARA rules match API names and behavioural primitives (``createFromPdu``,
``sendTextMessage``), which is what they are for; nothing in the pipeline was
looking for a C2 address. So there was nothing to export, and the STIX bundle
would have been an empty envelope with a schema.

This closes that gap. It runs over the same buffers L1 already builds — dex
class strings and decompiled sources — so it costs one extra pass, not another
decompilation.

**The hard part is not extraction, it is the denominator.** A naive URL regex
over a decompiled Android app returns hundreds of hits per sample, essentially
all of them framework and SDK boilerplate: ``schemas.android.com``,
``www.w3.org``, ``apache.org/licenses``, Firebase endpoints, Gradle metadata.
An IOC list that a bank cannot act on is worse than none, because someone will
eventually act on it. Everything here is therefore filtered against a
denylist of infrastructure that appears in effectively every app, and each
indicator records *where it came from* so an analyst can check the call.

Nothing here is an LLM output. The proposal is explicit that the model may
never assert an IOC the deterministic layers did not extract, and this is the
layer that extracts them.
"""

from __future__ import annotations

import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

_REPO = Path(__file__).resolve().parent.parent.parent
if str(_REPO / "L1") not in sys.path:
    sys.path.insert(0, str(_REPO / "L1"))

# --------------------------------------------------------------------------
# Patterns
# --------------------------------------------------------------------------

URL_RE = re.compile(rb"https?://[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]{4,200}")
# A bare host, only accepted when the TLD looks real (see _PLAUSIBLE_TLD).
HOST_RE = re.compile(rb"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.){1,4}"
                     rb"[a-zA-Z]{2,18}\b")
IPV4_RE = re.compile(rb"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
                     rb"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b")
# Indian mobile numbers and shortcodes — the SMS-exfil destination in BFSI malware.
PHONE_RE = re.compile(rb"\b(?:\+91[\-\s]?)?[6-9]\d{9}\b")
EMAIL_RE = re.compile(rb"\b[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,255}\.[A-Za-z]{2,18}\b")
# UPI virtual payment address: the payee identifier in Indian payment fraud.
UPI_RE = re.compile(rb"\b[A-Za-z0-9.\-_]{2,64}@(?:ok[a-z]+|[a-z]{2,20}bank|upi|paytm|ybl|axl|ibl)\b")
TG_RE = re.compile(rb"(?:https?://)?(?:t\.me|telegram\.me)/[A-Za-z0-9_]{3,64}")

# Bitcoin is deliberately NOT extracted. A base58 pattern without checksum
# validation matched two non-addresses in a benign note-taking app (one of them
# inside a Material Design class), and BTC is not the payment rail for Indian
# BFSI fraud in the first place -- UPI is, and UPI_RE covers it. An unvalidated
# pattern that produces a "cryptocurrency address" in an incident report is a
# liability, not a feature.

# Hosts that appear in essentially every Android app. Suffix-matched.
INFRA_SUFFIXES: tuple[str, ...] = (
    "android.com", "google.com", "googleapis.com", "gstatic.com", "googlesource.com",
    "google-analytics.com", "googletagmanager.com", "firebaseio.com", "firebase.com",
    "crashlytics.com", "doubleclick.net", "googleadservices.com", "admob.com",
    "w3.org", "apache.org", "eclipse.org", "gnu.org", "fsf.org", "opensource.org",
    "creativecommons.org", "mozilla.org", "oracle.com", "sun.com", "java.net",
    "github.com", "githubusercontent.com", "gitlab.com", "bitbucket.org",
    "jquery.com", "json.org", "xml.org", "ietf.org", "rfc-editor.org",
    "schema.org", "purl.org", "unicode.org", "iana.org", "example.com",
    "kotlinlang.org", "jetbrains.com", "gradle.org", "maven.org", "sonatype.org",
    "slf4j.org", "qos.ch", "reactivex.io", "squareup.com", "bumptech.github.io",
    "facebook.com", "fb.com", "twitter.com", "x.com", "localhost",
    "f-droid.org", "wikipedia.org", "wikimedia.org", "openstreetmap.org",
    "mit-license.org", "gpl.html", "sqlite.org", "zlib.net", "openssl.org",
)

# Reserved / non-routable space: never a blockable indicator.
def _is_private_ip(ip: str) -> bool:
    try:
        a, b, *_ = (int(p) for p in ip.split("."))
    except ValueError:
        return True
    if a in (0, 10, 127, 169, 224, 240, 255):
        return True
    if a == 172 and 16 <= b <= 31:
        return True
    if a == 192 and b == 168:
        return True
    if a == 100 and 64 <= b <= 127:
        return True
    return False


# `onion` (Tor hidden service — never resolvable via normal DNS, so its
# presence alone is a stronger malice signal than a clearnet TLD) was missing
# here until 2026-08-27: `L4/verify.py`'s `_INDICATOR_RE` (a *different*,
# independently-maintained TLD list used only to judge whether an LLM-decoded
# string looks indicator-shaped) already included it, so L4 correctly flagged
# `http://pc35hiptpcwqezgs.onion` in the Mazar BOT sample as a claimed IOC —
# and this list then dropped it as "not extracted by a deterministic layer"
# (the standing rule that the model may never introduce an indicator on its
# own). Two lists encoding the same fact drift; this is that drift, caught by
# a real sample rather than found in review.
_PLAUSIBLE_TLD = frozenset("""
com net org io co in app dev me info biz xyz online site club top live shop store
ru cn br uk de fr it es nl pl tr ua jp kr vn th id ph my sg pk bd lk np
cc tk ml ga cf gq pw su icu vip work fun link click space website host press onion
""".split())

# A *bare* hostname (one not preceded by a scheme) needs a much more
# conservative TLD set than a URL host does. Measured false positives from the
# permissive list: `btn.click` and `clicktarget.click` (UI code identifiers --
# `.click` is a real TLD), and `measurement.id` / `measurement.ga` /
# `measurement.store` (Firebase Analytics field names). A host seen inside an
# `https://…` is proven to be an endpoint by its scheme; a bare one is only a
# string that looks like a domain, so it has to earn it.
# onion included even bare (unlike the code-identifier-prone .click/.id
# TLDs this list is otherwise conservative about): a 16- or 56-char base32
# Tor address has no resemblance to a Java identifier or resource name, so it
# does not carry the same false-positive risk documented above.
_BARE_HOST_TLD = frozenset("""
com net org io in co info biz ru cn br uk de fr it es nl pl tr ua jp kr vn th
id ph my sg pk bd lk np xyz top online site me app dev cc tk pw su icu onion
""".split())

# Class/method-name noise that looks like a hostname (e.g. "android.util.Log").
_CODE_PREFIXES = ("java.", "javax.", "android.", "androidx.", "kotlin.", "kotlinx.",
                  "com.google.", "com.android.", "org.jetbrains.", "dalvik.", "sun.",
                  "org.w3c.", "org.xml.", "org.json.", "junit.", "org.junit.")


@dataclass
class IOC:
    type: str
    value: str
    locations: set[str] = field(default_factory=set)
    count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {"type": self.type, "value": self.value, "count": self.count,
                "locations": sorted(self.locations)[:10]}


def _is_infra_host(host: str) -> bool:
    h = host.lower().rstrip(".")
    return any(h == s or h.endswith("." + s) for s in INFRA_SUFFIXES)


def _host_of(url: str) -> str:
    m = re.match(r"https?://([^/:?#]+)", url, re.I)
    return (m.group(1) if m else "").lower()


def _plausible_host(host: str, bare: bool = False) -> bool:
    h = host.lower().rstrip(".")
    if not h or len(h) > 253 or h.startswith(_CODE_PREFIXES):
        return False
    parts = h.split(".")
    allowed = _BARE_HOST_TLD if bare else _PLAUSIBLE_TLD
    if len(parts) < 2 or parts[-1] not in allowed:
        return False
    # "com.example.myapp" is a package name read backwards, not a host.
    if parts[0] in ("com", "org", "net", "io", "app", "dev") and len(parts) >= 3:
        return False
    return True


def _decode(b: bytes) -> str:
    return b.decode("utf-8", "replace").strip().rstrip('".,;)\'')


# --------------------------------------------------------------------------
# What the benign controls killed
# --------------------------------------------------------------------------
#
# Patterns made only of digits match compiled binary resources constantly. The
# first version of this module extracted three "Indian mobile numbers" —
# 8955078125, 7619934082, 9705627482 — from the SBI banking trojan, which looked
# like exactly the SMS-exfil destinations we were hunting for.
#
# They appear in **every app**, including both benign controls. They are byte
# runs inside `res/anim/btn_checkbox_to_checked_box…xml` and
# `res/drawable/btn_radio_off_mtrl.xml` — standard Material Design resources
# shipped with every APK built against AndroidX.
#
# Bare IPv4 was worse: `1.3.6.1` and `1.3.14.3` are ASN.1 object identifiers
# from crypto code, and 82 of PennyWise's 121 "indicators" were OIDs and version
# strings.
#
# A printable-neighbourhood heuristic did not save either pattern, because
# compiled AXML has long printable runs by construction. So the loose patterns
# are restricted to dex class buffers, where a match is a genuine string
# constant in application code, and bare IPv4 is dropped entirely — an IP is
# only recorded when it appears as the host of a URL.
#
# This is the T7 lesson applied to a new detector: the benign set is what
# turned a plausible C2 phone number into a Material Design drawable.

# Buffers where a digit-only match plausibly means what it looks like.
SCOPE_CODE = "code"       # dex class buffers, decompiled sources
SCOPE_RESOURCE = "resource"  # res/, assets/, manifests — structured, but binary


def extract_from_bytes(data: bytes, location: str,
                       sink: dict[tuple[str, str], IOC],
                       scope: str = SCOPE_CODE) -> None:
    """Accumulate indicators found in one buffer into ``sink``.

    ``scope`` gates the digit-only patterns; see the note above. Resource
    buffers contribute URLs and hostnames only.
    """

    def add(kind: str, value: str) -> None:
        if not value:
            return
        key = (kind, value)
        ioc = sink.get(key)
        if ioc is None:
            ioc = sink[key] = IOC(type=kind, value=value)
        ioc.count += 1
        if len(ioc.locations) < 10:
            ioc.locations.add(location)

    for m in URL_RE.findall(data):
        url = _decode(m)
        host = _host_of(url)
        if not host or _is_infra_host(host):
            continue
        if IPV4_RE.fullmatch(host.encode()):
            if _is_private_ip(host):
                continue
            add("ipv4", host)
        elif not _plausible_host(host):
            continue
        else:
            add("domain", host)
        add("url", url)

    # Bare IPv4 is deliberately not extracted: ASN.1 OIDs (1.3.6.1, 1.3.14.3)
    # and version strings dominate it. An IP is recorded only as a URL host,
    # above, where the surrounding scheme proves it is an endpoint.

    for m in HOST_RE.findall(data):
        host = _decode(m).lower()
        if _plausible_host(host, bare=True) and not _is_infra_host(host):
            add("domain", host)

    for m in EMAIL_RE.findall(data):
        email = _decode(m)
        domain = email.split("@")[-1]
        if not _is_infra_host(domain) and _plausible_host(domain):
            add("email", email)

    for m in UPI_RE.findall(data):
        add("upi_vpa", _decode(m))

    for m in TG_RE.findall(data):
        add("telegram", _decode(m))

    if scope != SCOPE_CODE:
        return

    # Digit-only patterns, application code only. In resources these matched
    # Material Design drawables in every app ever built.
    for m in PHONE_RE.findall(data):
        add("phone_in", _decode(m))




def extract_from_apk(apk_path: str | Path, max_member_bytes: int = 64 << 20
                     ) -> list[IOC]:
    """Indicators from an APK's dex classes and interesting members."""
    import zipfile

    from engines.yara_scan import _dex_class_buffers  # reuse L1's own splitter

    sink: dict[tuple[str, str], IOC] = {}
    try:
        with zipfile.ZipFile(apk_path) as zf:
            for info in zf.infolist():
                if info.is_dir() or info.file_size > max_member_bytes:
                    continue
                name = info.filename
                # resources.arsc (2026-08-27): a Tor C2 address is not always a
                # dex string constant. Measured on the Mazar BOT sample: its
                # `res/values/strings.xml` has `<string name="server_url">
                # http://pc35hiptpcwqezgs.onion</string>`, compiled into this
                # binary resource table and referenced from code by resource
                # ID — invisible to a dex-only scan. It is not XML/JSON/plain
                # text, but it is a flat, mostly-uncompressed string pool, so
                # the same raw byte-regex pass that works on dex class buffers
                # recovers plain-ASCII strings from it directly (verified: the
                # scheme+host URL_RE match survives untouched).
                interesting = (
                    name.startswith("classes") and name.endswith(".dex")
                ) or name in ("resources.arsc",) or name.endswith(
                    (".xml", ".json", ".properties", ".txt", ".js",
                     ".html", ".cfg", ".ini"))
                if not interesting:
                    continue
                try:
                    data = zf.read(info)
                except Exception:  # noqa: BLE001
                    continue
                if name.startswith("classes") and name.endswith(".dex"):
                    try:
                        for cls, buf in _dex_class_buffers(data):
                            extract_from_bytes(buf, f"{name}!{cls}", sink,
                                               SCOPE_CODE)
                        continue
                    except Exception:  # noqa: BLE001
                        pass
                extract_from_bytes(data, name, sink, SCOPE_RESOURCE)
    except zipfile.BadZipFile:
        # Deliberately-corrupted archives are an anti-analysis technique; the
        # rest of the pipeline tolerates them, so this does too.
        return []
    return sorted(sink.values(), key=lambda i: (-i.count, i.type, i.value))


def extract_from_sources(src_dir: str | Path, max_files: int = 4000) -> list[IOC]:
    """Indicators from decompiled java sources."""
    sink: dict[tuple[str, str], IOC] = {}
    root = Path(src_dir)
    if not root.is_dir():
        return []
    for n, path in enumerate(root.rglob("*.java")):
        if n >= max_files:
            break
        try:
            data = path.read_bytes()
        except OSError:
            continue
        try:
            rel = str(path.relative_to(root))
        except ValueError:
            rel = path.name
        extract_from_bytes(data, rel, sink, SCOPE_CODE)
    return sorted(sink.values(), key=lambda i: (-i.count, i.type, i.value))


def merge(*groups: Iterable[IOC]) -> list[IOC]:
    sink: dict[tuple[str, str], IOC] = {}
    for group in groups:
        for ioc in group:
            key = (ioc.type, ioc.value)
            existing = sink.get(key)
            if existing is None:
                sink[key] = IOC(ioc.type, ioc.value, set(ioc.locations), ioc.count)
            else:
                existing.count += ioc.count
                existing.locations |= ioc.locations
    return sorted(sink.values(), key=lambda i: (-i.count, i.type, i.value))


def summarise(iocs: list[IOC]) -> dict[str, Any]:
    by_type: dict[str, int] = defaultdict(int)
    for i in iocs:
        by_type[i.type] += 1
    return {"ioc_count": len(iocs), "ioc_types": dict(sorted(by_type.items()))}


def main(argv: list[str] | None = None) -> int:
    import argparse
    import json

    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("apk")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    iocs = extract_from_apk(args.apk)
    if args.json:
        print(json.dumps([i.to_dict() for i in iocs], indent=2))
        return 0
    print(f"{len(iocs)} indicators")
    for i in iocs[:60]:
        loc = sorted(i.locations)[0] if i.locations else "-"
        print(f"  {i.type:10s} {i.value[:70]:70s} x{i.count}  {loc[:40]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
