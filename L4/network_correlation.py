"""Content correlation between a class's literal strings and captured network traffic.

**This is a content match, not causation.** `L2/sandbox/mitm_addon.py` records
`host`/`url` per HTTP flow and `dynamic_hooks.js` sends findings with no
call-stack capture — there is currently no mechanism that attributes a
network call to the class or method that made it (documented limitation, see
`decisions/plan_l4_agentic_verdicts.md` §"What changes" point 3 and §4). True
code-to-network attribution would need a new Frida hook capturing
``Java.use("java.lang.Exception").$new().getStackTrace()`` at the socket/URL
call site, plus a jadx-location resolver for the resulting frames — real work,
filed as future work, not done here.

What this module actually establishes: a string literal (or a string this
sample's decoded output turned into) that appears in one of this class's
source strings also shows up somewhere in the network traffic this sample's
sandbox run captured. That correlation is worth surfacing to the analyst as
context — it is exactly the kind of thing a human reviewer would notice — but
every caller must present it as "this class contains a string that also
appears in captured traffic," never as "this class made this call."

**Where the network evidence dict comes from.** `L2/sandbox/orchestrator.py`
assembles `dynamic.json`'s ``"network"`` block from the raw
``network_evidence.json`` mitmproxy log (a flat list of ``{"host", "url",
"alert"?, "hijacked"?}`` entries — see `L2/sandbox/mitm_addon.py`) into:

    {
        "total_requests": int,
        "c2_endpoints": [<url str>, ...],       # entries with "hijacked" set
        "exfiltration_detected": bool,
        "data_exfiltrated": [<host str>, ...],  # entries with alert == CREDENTIAL_EXFILTRATION
    }

`L1/l2_engine.py::_parse_network_evidence` reads the same raw log directly
(not the assembled block) for its own finding promotion. Because two shapes
of "network evidence" exist in this codebase — the raw flat list and the
assembled package-level dict — :func:`correlate` accepts either, plus the
one other shape a caller might reasonably have on hand: a dict with an
``"entries"`` key holding the raw list. This is deliberately permissive
rather than tied to one exact caller, since the L2 producer of this dict is
owned by a different layer and is not this file's contract to pin down.
"""

from __future__ import annotations

from typing import Any, Iterable

# Keys, anywhere in a network_evidence dict, whose *string list* values are
# treated as correlation targets (hosts, URLs, exfil destinations).
_LIST_TARGET_KEYS = ("c2_endpoints", "data_exfiltrated", "exfiltration_targets")

# Keys, on an individual raw log entry, that carry a matchable string.
_ENTRY_TARGET_KEYS = ("host", "url")

# A literal shorter than this is dropped before matching: single characters
# and short obfuscated identifiers ("a", "IV") would otherwise "correlate"
# against almost anything by pure chance, the same false-positive shape T7
# and T23 already document elsewhere in this codebase.
MIN_LITERAL_LEN = 4


def _collect_targets(network_evidence: dict) -> set[str]:
    """Every matchable string in a network_evidence dict, lower-cased."""
    targets: set[str] = set()

    for key in _LIST_TARGET_KEYS:
        values = network_evidence.get(key)
        if isinstance(values, list):
            targets.update(str(v).lower() for v in values if isinstance(v, str) and v)

    # Raw mitmproxy log, either as the dict itself (unlikely, since the
    # signature types network_evidence as dict) or nested under "entries".
    entries = network_evidence.get("entries")
    if not isinstance(entries, list):
        entries = None
    if entries is not None:
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            for key in _ENTRY_TARGET_KEYS:
                value = entry.get(key)
                if isinstance(value, str) and value:
                    targets.add(value.lower())

    return targets


def correlate(class_literals: Iterable[str], network_evidence: dict) -> list[str]:
    """Literal strings in ``class_literals`` that also appear in captured network traffic.

    ``class_literals`` should be every string worth checking from one class:
    raw string constants, plus anything already mechanically decoded (never
    an LLM's *claimed* decoding — that claim has not been checked yet, and
    checking it is `L4/verify.py`'s job, not this module's).

    ``network_evidence`` is the package-level network summary for this
    sample (see module docstring for the shapes accepted). It is never
    class-scoped — L2 does not attribute network calls to source locations.

    Matching is substring-based and case-insensitive in both directions: a
    literal that is a substring of a captured host/URL counts (e.g. a class
    literal ``"192.168.1.100"`` against a captured URL
    ``"http://192.168.1.100/gate.php"``), and vice versa, since either the
    class or the traffic may hold the more specific string. Literals shorter
    than :data:`MIN_LITERAL_LEN` are skipped to avoid coincidental matches.

    Returns the matched **class literals** (not the network-side strings, and
    not necessarily in the order given), deduplicated, so a caller can report
    exactly what in the class's own source triggered the flag.
    """
    if not isinstance(network_evidence, dict):
        return []

    targets = _collect_targets(network_evidence)
    if not targets:
        return []

    matched: list[str] = []
    seen: set[str] = set()
    for literal in class_literals:
        if not isinstance(literal, str):
            continue
        candidate = literal.strip()
        if len(candidate) < MIN_LITERAL_LEN or candidate.lower() in seen:
            continue
        needle = candidate.lower()
        if any(needle in target or target in needle for target in targets):
            matched.append(candidate)
            seen.add(needle)

    return matched
