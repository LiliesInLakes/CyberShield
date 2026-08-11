"""Mechanically check what the model claimed, before any of it is reported.

This is the primary anti-hallucination control for L4, and it is deliberately
*not* retrieval. RAG grounds claims about the threat landscape; it cannot touch
a claim about **this sample**, which is where the dangerous errors live.

The worked example is from our own model selection. Given the literal
``aHR0cDovLzE5Mi4xNjguMS4xMDAvZ2F0ZS5waHA=``, one candidate model asserted it
decoded to ``http://192.168.1.100/get.php``. The true value is ``gate.php``.
That claim is fluent, plausible, precisely the shape of a real finding — and
refuted by one call to ``base64.b64decode``. No amount of retrieved threat
intelligence would have caught it.

So every claim class that a decoder, a parser, or a substring search can settle
is settled that way:

======================= ==================================================
claim                   check
======================= ==================================================
``decoded_strings``     re-decode the literal ourselves and compare
``renamed``             the obfuscated identifier must occur in the code
``api_calls``           the API name must occur in the code
``iocs``                must already be in L1's extracted indicator list
``behaviours``          free text — carried as *unverified*, never as fact
======================= ==================================================

A claim that fails its check is **dropped**, not down-weighted, and the drop is
recorded. A claim that has no mechanical check is carried with
``verified: false`` so a reader can see which parts of a narrative rest on the
model's word alone.
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass, field
from typing import Any, Iterable

# Claim kinds that survive only if a check passes.
CHECKABLE = ("decoded_strings", "renamed", "api_calls", "iocs")


@dataclass
class Verdict:
    kept: dict[str, Any] = field(default_factory=dict)
    dropped: list[dict[str, Any]] = field(default_factory=list)
    unverified: dict[str, Any] = field(default_factory=dict)

    @property
    def drop_count(self) -> int:
        return len(self.dropped)

    def drop(self, kind: str, claim: Any, reason: str, expected: Any = None) -> None:
        entry = {"kind": kind, "claim": claim, "reason": reason}
        if expected is not None:
            entry["expected"] = expected
        self.dropped.append(entry)

    def summary(self) -> dict[str, Any]:
        return {
            "kept": {k: len(v) if isinstance(v, (list, dict)) else 1
                     for k, v in self.kept.items()},
            "dropped": self.drop_count,
            "unverified_fields": sorted(self.unverified),
        }


def _try_decode(literal: str) -> set[str]:
    """Every plausible decoding of a literal, for comparison against a claim."""
    out: set[str] = set()
    s = literal.strip()

    for pad in ("", "=", "==", "==="):
        try:
            raw = base64.b64decode(s + pad, validate=True)
        except (binascii.Error, ValueError):
            continue
        try:
            out.add(raw.decode("utf-8"))
        except UnicodeDecodeError:
            pass
        break

    if re.fullmatch(r"(?:[0-9a-fA-F]{2})+", s):
        try:
            out.add(bytes.fromhex(s).decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            pass

    # ROT13 and simple XOR are common in droppers; only single-byte XOR is
    # cheap enough to brute force, and only printable results are kept.
    try:
        raw = s.encode("latin-1")
        for key in range(1, 256):
            cand = bytes(b ^ key for b in raw)
            if all(32 <= c < 127 for c in cand) and len(cand) > 6:
                text = cand.decode("ascii")
                if re.search(r"https?://|\.(com|net|ru|cn|php|apk)\b", text):
                    out.add(text)
    except UnicodeEncodeError:
        pass

    return out


def verify_decoded_strings(claims: dict[str, str], verdict: Verdict) -> dict[str, str]:
    """Re-decode each literal ourselves. This is the `gate.php` check."""
    kept: dict[str, str] = {}
    for literal, claimed in (claims or {}).items():
        if not isinstance(literal, str) or not isinstance(claimed, str):
            verdict.drop("decoded_strings", {literal: claimed}, "non_string")
            continue
        truth = _try_decode(literal)
        if not truth:
            verdict.drop("decoded_strings", {literal: claimed},
                         "literal_is_not_decodable")
            continue
        if claimed.strip() in truth:
            kept[literal] = claimed.strip()
        else:
            verdict.drop("decoded_strings", {literal: claimed},
                         "decoding_does_not_match", expected=sorted(truth)[:3])
    return kept


def _occurs(needle: str, haystacks: Iterable[str]) -> bool:
    """Substring match, for dotted API names and other multi-token strings."""
    if not needle or len(needle) < 2:
        return False
    return any(needle in h for h in haystacks)


def _occurs_as_identifier(needle: str, haystacks: Iterable[str]) -> bool:
    """Word-boundary match, for identifiers.

    Obfuscators emit exactly the names a length floor would reject — `a`, `b`,
    `zz` — so identifiers cannot be checked with a minimum length. They also
    cannot be checked with a substring search, because `a` occurs inside
    `class`, `java` and almost every word in the file. Word boundaries are the
    only thing that answers "is this identifier really here".
    """
    if not needle:
        return False
    pattern = re.compile(rf"(?<![A-Za-z0-9_$]){re.escape(needle)}(?![A-Za-z0-9_$])")
    return any(pattern.search(h) for h in haystacks)


def verify_renamed(claims: dict[str, str], code: list[str],
                   verdict: Verdict) -> dict[str, str]:
    """A rename is only meaningful if the original identifier is really there."""
    kept: dict[str, str] = {}
    for original, suggested in (claims or {}).items():
        if not isinstance(original, str) or not isinstance(suggested, str):
            verdict.drop("renamed", {original: suggested}, "non_string")
            continue
        if _occurs_as_identifier(original, code):
            kept[original] = suggested
        else:
            verdict.drop("renamed", {original: suggested},
                         "identifier_not_present_in_code")
    return kept


def _api_forms(api: str) -> list[str]:
    """How a fully-qualified API name can legitimately appear in Java source.

    Decompiled Java writes ``Log.i(...)`` and ``new Date()``; a model reasonably
    reports ``android.util.Log.i`` and ``java.util.Date.<init>``. Matching only
    the trailing component fails twice over: the tail of ``android.util.Log.i``
    is ``i``, which matches nothing safely, and ``<init>`` never appears at all.

    This was measured, not imagined — the first version of this function
    dropped four true claims (``Log.i``, ``Log.e``, ``Log.d``, ``Date.<init>``)
    on a class that plainly contains all four.
    """
    parts = [p for p in api.split(".") if p]
    if not parts:
        return []
    forms = {api}
    if parts[-1] == "<init>" and len(parts) >= 2:
        # Constructor: appears as `new Date(`.
        forms.add(f"new {parts[-2]}")
        forms.discard(api)
        return sorted(forms)
    if len(parts) >= 2:
        forms.add(f"{parts[-2]}.{parts[-1]}")      # Log.i, SmsManager.sendTextMessage
    if len(parts[-1]) >= 3:
        forms.add(parts[-1])                        # sendTextMessage
    return sorted(forms)


def verify_api_calls(claims: list[str], code: list[str],
                     verdict: Verdict) -> list[str]:
    kept: list[str] = []
    for api in claims or []:
        if not isinstance(api, str):
            verdict.drop("api_calls", api, "non_string")
            continue
        forms = _api_forms(api)
        if any(_occurs(f, code) for f in forms):
            kept.append(api)
        else:
            verdict.drop("api_calls", api, "api_not_present_in_code",
                         expected=forms)
    return kept


def verify_iocs(claims: list[str], extracted: Iterable[str],
                verdict: Verdict) -> list[str]:
    """The model may never introduce an indicator the deterministic layers missed.

    This is a standing rule from the proposal, and it is the one that matters
    operationally: an IOC export is loaded into a blocklist.
    """
    known = {str(v).lower() for v in extracted}
    kept: list[str] = []
    for ioc in claims or []:
        if isinstance(ioc, str) and ioc.lower() in known:
            kept.append(ioc)
        else:
            verdict.drop("iocs", ioc, "not_extracted_by_a_deterministic_layer")
    return kept


def verify(claims: dict[str, Any], *, code: list[str],
           extracted_iocs: Iterable[str] = ()) -> Verdict:
    """Check a model response against the artifact it claims to describe."""
    v = Verdict()

    v.kept["decoded_strings"] = verify_decoded_strings(
        claims.get("decoded_strings") or {}, v)
    v.kept["renamed"] = verify_renamed(claims.get("renamed") or {}, code, v)
    v.kept["api_calls"] = verify_api_calls(claims.get("api_calls") or [], code, v)
    v.kept["iocs"] = verify_iocs(claims.get("iocs") or [], extracted_iocs, v)

    # Everything else is narrative. It is kept, but marked, so a reader can see
    # exactly which sentences rest on the model's word.
    for key, value in claims.items():
        if key not in CHECKABLE and value:
            v.unverified[key] = value

    return v
