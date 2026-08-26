"""L1 YARA scanning engine.

Scans raw APK and decompiled Java sources using the YARA rule set
in L1/yara_templates/. Replaces the naive SUSPICIOUS_SIGS string matching.

Two modes:
  - APK scan: rules as-is, catches format anomalies, embedded payloads, IOCs
  - Source scan: rules with byte-level checks (filesize, uint32) stripped,
    catches behavioral patterns in decompiled Java code
"""

from __future__ import annotations

import hashlib
import re
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yara

from schema import L1Finding, Severity, Category, CATEGORY_MITRE_MAP

_SEV_ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]

# Library path prefixes to exclude from source scanning (never app code)
_EXCLUDE_SOURCE_PREFIXES = (
    "androidx/",
    "android/support/",
    "kotlin/",
    "org/apache/",
    "com/tom_roush/",
    "com/android/dx/",
    "com/android/dex/",
    "com/android/multidex/",
    "com/google/android/gms/",
    "com/google/firebase/",
    "okhttp3/internal/",
    "okio/",
)

YARA_DIR = Path(__file__).resolve().parent.parent / "yara_templates"
INDEX_FILE = YARA_DIR / "index.yar"

_SEV_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}

_CATALOG: list[tuple[re.Pattern, Category]] = [
    (re.compile(r"ransomware|ransom|locker|encrypt.*file", re.I), Category.RANSOMWARE),
    (re.compile(r"overlay|tapjack|click.?jack|window.*inject", re.I), Category.OVERLAY),
    (re.compile(r"accessibility.*abuse|keylog|accessibility.*overlay", re.I), Category.ACCESSIBILITY_ABUSE),
    (re.compile(r"c2|command.*control|websocket|network.*com|beacon", re.I), Category.C2_COMMS),
    (re.compile(r"exfil|spyware|surveillance|stalk|harvest|gps.*track", re.I), Category.DATA_EXFIL),
    (re.compile(r"dropper|loader|payload|download.*exec|stage|dexclass|native.*lib", re.I), Category.NATIVE_PAYLOAD),
    (re.compile(r"evasion|obfuscat|anti.*analysis|anti.*debug|root.*detect|emulat.*detect|string.*obfuscat", re.I), Category.EVASION),
    (re.compile(r"phish|imperson|spoof|lookalike", re.I), Category.PHISHING_IMPERSONATION),
    (re.compile(r"sms.*intercept|sms.*fraud|premium.*number|subscription.*abuse", re.I), Category.SMS_INTERCEPT),
    (re.compile(r"adware|click.*fraud|ad.*inject", re.I), Category.OTHER),
    (re.compile(r"permission.*cluster|dangerous.*perm", re.I), Category.OTHER),
    (re.compile(r"suspicious.*command|shell.*access|exec", re.I), Category.PRIVILEGE_ESCALATION),
    (re.compile(r"package.*install|sideload", re.I), Category.NATIVE_PAYLOAD),
    (re.compile(r"format|structure|certificate|dex.*file", re.I), Category.OTHER),
]


def _categorize(name: str, meta: dict[str, Any]) -> Category:
    """Resolve a finding category.

    Rule metadata wins: a rule may declare `category = "sms_intercept"` directly.
    The regex catalog below is only a fallback for rules that have not yet been
    annotated, and guesses from the rule name — which is why several Category
    members were previously unreachable.
    """
    declared = (meta.get("category") or "").strip().lower()
    if declared:
        try:
            return Category(declared)
        except ValueError:
            pass
    combined = f"{name} {meta.get('description', '')}"
    for pattern, cat in _CATALOG:
        if pattern.search(combined):
            return cat
    return Category.OTHER


def _severity(meta: dict[str, Any]) -> Severity:
    """Case-insensitive severity lookup.

    Rule files are inconsistent: `apk_vulnerabilities.yar` uses lowercase while
    the 35 malware-behaviour rules use Title Case. Without folding, every
    Title-Cased rule silently degraded to MEDIUM.
    """
    return _SEV_MAP.get(str(meta.get("severity", "medium")).strip().lower(), Severity.MEDIUM)


# ---------------------------------------------------------------------------
# Per-rule accumulation
#
# A YARA rule's condition is the unit of detection (`3 of them`, ...), so a rule
# that fires is ONE finding regardless of how many strings or files it matched.
# Emitting one finding per matched string inflated counts by up to 7x and made
# any count-based score meaningless. Breadth is preserved as detail fields.
# ---------------------------------------------------------------------------

_MAX_LOCATIONS = 20
_MAX_SAMPLES = 8


@dataclass
class _RuleHit:
    rule: str
    meta: dict[str, Any]
    scopes: set[str] = field(default_factory=set)
    locations: list[str] = field(default_factory=list)
    string_ids: set[str] = field(default_factory=set)
    match_count: int = 0
    samples: list[dict[str, Any]] = field(default_factory=list)
    rule_file: str = ""

    def absorb(self, result: Any, scope: str, location: str) -> None:
        self.scopes.add(scope)
        if location and location not in self.locations:
            self.locations.append(location)
        for sm in getattr(result, "strings", None) or []:
            self.string_ids.add(sm.identifier)
            for inst in sm.instances:
                self.match_count += 1
                if len(self.samples) < _MAX_SAMPLES:
                    try:
                        snippet = inst.matched_data.decode("utf-8", errors="replace")[:120]
                    except Exception:  # noqa: BLE001
                        snippet = ""
                    self.samples.append({
                        "id": sm.identifier,
                        "location": location,
                        "snippet": snippet,
                    })

    def to_finding(self) -> L1Finding:
        cat = _categorize(self.rule, self.meta)
        desc = self.meta.get("description", self.rule)
        primary = self.locations[0] if self.locations else self.rule
        lead = self.samples[0]["snippet"] if self.samples else ""
        evidence = f"[{self.rule}] {desc}" + (f" -> {lead}" if lead else "")
        return L1Finding(
            engine="yara",
            category=cat,
            severity=_severity(self.meta),
            evidence=evidence,
            location=primary,
            mitre_techniques=CATEGORY_MITRE_MAP.get(cat, []),
            detail={
                "yara_rule": self.rule,
                "rule_file": self.rule_file,
                "scopes": sorted(self.scopes),
                "locations": self.locations[:_MAX_LOCATIONS],
                "location_count": len(self.locations),
                "matched_string_ids": sorted(self.string_ids),
                "match_count": self.match_count,
                "samples": self.samples,
            },
        )


def _accumulate(matches: list, scope: str, location: str,
                acc: dict[str, _RuleHit]) -> None:
    for result in matches:
        hit = acc.get(result.rule)
        if hit is None:
            hit = _RuleHit(rule=result.rule, meta=dict(result.meta),
                           rule_file=str((result.meta or {}).get("rule_file", "")))
            acc[result.rule] = hit
        hit.absorb(result, scope, location)


def _acc_to_findings(acc: dict[str, _RuleHit]) -> list[L1Finding]:
    return [acc[r].to_finding() for r in sorted(acc)]


def merge_findings(*groups: list[L1Finding]) -> list[L1Finding]:
    """Merge finding lists so a rule that fired in several scopes is ONE finding.

    This is what makes cross-engine dedup structural rather than a post-hoc
    filter: `yara_source` and `yara_apk` hits for the same rule collapse here by
    construction, instead of both reaching the report and being deduped by a
    fragile evidence-string comparison.
    Non-YARA findings (no `yara_rule` in detail) pass through untouched.
    """
    by_rule: dict[str, L1Finding] = {}
    passthrough: list[L1Finding] = []
    for group in groups:
        for f in group:
            rule = (f.detail or {}).get("yara_rule")
            if not rule:
                passthrough.append(f)
                continue
            existing = by_rule.get(rule)
            if existing is None:
                by_rule[rule] = f
                continue
            ed, nd = existing.detail, f.detail
            ed["scopes"] = sorted(set(ed.get("scopes", [])) | set(nd.get("scopes", [])))
            locs = list(dict.fromkeys(ed.get("locations", []) + nd.get("locations", [])))
            ed["locations"] = locs[:_MAX_LOCATIONS]
            ed["location_count"] = ed.get("location_count", 0) + nd.get("location_count", 0)
            ed["matched_string_ids"] = sorted(
                set(ed.get("matched_string_ids", [])) | set(nd.get("matched_string_ids", []))
            )
            ed["match_count"] = ed.get("match_count", 0) + nd.get("match_count", 0)
            ed["samples"] = (ed.get("samples", []) + nd.get("samples", []))[:_MAX_SAMPLES]
            if _SEV_ORDER.index(f.severity) > _SEV_ORDER.index(existing.severity):
                existing.severity = f.severity
    return sorted(by_rule.values(), key=lambda f: f.detail["yara_rule"]) + passthrough


# Bump when the *scanner* changes what a given rule set produces, even though
# no .yar file was edited. `corpus_run.py` resumes on ruleset_version, so a
# behaviour change that leaves this constant alone silently reuses stale
# findings — which is how the container-scope fix below would have shipped
# without ever being applied to a single sample.
SCANNER_BEHAVIOUR_VERSION = "2"   # 2: container pass restricted to scope="apk"


def ruleset_version() -> str:
    """Stable hash over the compiled rule corpus *and* the scanner's behaviour.

    Recorded in the evidence spine so it is unambiguous when a change in
    findings is due to a ruleset edit rather than a change in the sample.
    """
    h = hashlib.sha1()
    for path in sorted(YARA_DIR.rglob("*.yar")):
        h.update(path.name.encode())
        h.update(path.read_bytes())
    h.update(b"|scanner=" + SCANNER_BEHAVIOUR_VERSION.encode())
    return h.hexdigest()[:12]


def _strip_byte_checks(source: str) -> str:
    """Remove filesize, uint32(0), and hex-string checks from YARA conditions.

    Handles:
      - 'filesize < NMB' lines
      - 'uint32(0) == 0x...' lines
      - 'or $hex_xxx' or '(1 of ($hex_xxx*))' within expressions
      - Removes dangling 'and' after removed lines
    """
    lines = source.split("\n")
    out: list[str] = []
    in_condition = False
    first_cond_line = False

    _RE_BYTE_LINE = re.compile(
        r"^(filesize\s*<\s*\d+\s*MB\s*"             # filesize < N
        r"|uint32(?:be|le)?\(0\)\s*==\s*0x[0-9A-Fa-f]+\s*"  # uint32(0)/uint32be(0) == 0x...
        r")$"
    )

    _RE_HEX_INLINE = re.compile(r"\$hex_\w+")  # matches $hex_xxx anywhere in line

    def _has_hex_ref(s: str) -> bool:
        return bool(_RE_HEX_INLINE.search(s)) or bool(re.search(r'#hex_\w+', s))

    def _strip_hex(cond: str) -> str:
        """Remove hex-string references from a condition expression."""
        cond = re.sub(r'\s+or\s+\$?hex_\w+\*?', '', cond)
        cond = re.sub(r'\s+and\s+\$?hex_\w+\*?', '', cond)
        cond = re.sub(r'\$?hex_\w+\*?\s+or\s+', '', cond)
        cond = re.sub(r'\$?hex_\w+\*?\s+and\s+', '', cond)
        cond = re.sub(r'#hex_\w+\s*>=\s*\d+', '', cond)  # #hex_xxx >= N
        cond = re.sub(r'\$hex_\w+\s+at\s+\d+', '', cond)  # $hex_xxx at 0
        cond = re.sub(r'\$hex_\w+\*?', '', cond)      # $hex_xxx or $hex_xxx*
        cond = re.sub(r'#hex_\w+', '', cond)
        # Remove (1 of ()) or (1 of (*)) BEFORE removing individual empty parens
        cond = re.sub(r'\(1\s+of\s*\(\**\)\)', '', cond)  # (1 of ()) or (1 of (*))
        cond = re.sub(r'\(\s*\)', '', cond)  # empty parens like ()
        cond = re.sub(r'\(\s*or\s+', '(', cond)  # (or ... -> (...)
        cond = re.sub(r'\s+or\s+\)', ')', cond)   # ... or ) -> ...)
        cond = re.sub(r'^\s+and\s+', '', cond)    # leading 'and ' on first line
        cond = re.sub(r'^\s+or\s+', '', cond)     # leading 'or ' on first line
        cond = re.sub(r'\s+and\s*$', '', cond)    # trailing 'and' at end
        cond = re.sub(r'\s+or\s*$', '', cond)     # trailing 'or' at end
        cond = re.sub(r'^\s*,\s*', '', cond)      # leading comma
        cond = re.sub(r',\s*$', '', cond)         # trailing comma
        cond = cond.strip()
        if re.match(r'^(and|or)\s*$', cond):
            return ''
        return cond

    for i, line in enumerate(lines):
        s = line.strip()

        if not in_condition and re.match(r"^\s*condition:\s*$", line):
            in_condition = True
            first_cond_line = True
            out.append(line)
            continue

        if not in_condition:
            out.append(line)
            continue

        if re.match(r"^\s*rule\s+", s) or re.match(r"^\s*include\s+", s) or s.startswith("//"):
            in_condition = False
            out.append(line)
            continue

        if re.match(_RE_BYTE_LINE, s):
            first_cond_line = True
            continue

        m = re.match(r"^and\s+(.+)", s)
        if m and re.match(_RE_BYTE_LINE, m.group(1)):
            continue

        nxt = lines[i + 1].strip() if i + 1 < len(lines) else ""
        if re.match(_RE_BYTE_LINE, nxt):
            if s.rstrip().endswith("and") or s.rstrip().endswith("and("):
                first_cond_line = True
                continue

        if _has_hex_ref(s):
            s = _strip_hex(s)
            if not s:
                first_cond_line = True
                continue
            indent = line[:len(line) - len(line.lstrip())]
            line = indent + s

        if first_cond_line and s.startswith("and ") and not s[4:].lstrip().startswith("not"):
            indent = line[:len(line) - len(line.lstrip())]
            line = indent + s[4:].lstrip()
        first_cond_line = False
        out.append(line)

    # Remove hex string definitions (they reference byte patterns not in Java source)
    result = "\n".join(out)
    result = re.sub(r'^\s+\$hex_\w+\s*=.*$', '', result, flags=re.MULTILINE)
    result = re.sub(r'\n{3,}', '\n\n', result)
    return result


def _rule_sources() -> list[tuple[str, str]]:
    """Read every rule file referenced by index.yar. Returns (filename, text)."""
    index_text = INDEX_FILE.read_text(encoding="utf-8")
    out: list[tuple[str, str]] = []
    for inc in re.findall(r'include\s+"(.+\.yar)"', index_text):
        path = YARA_DIR / inc
        if path.exists():
            out.append((inc, path.read_text(encoding="utf-8")))
    return out


def _compile_rules() -> yara.Rules:
    """Compile the container rule set — **only** rules that reason about ZIP structure.

    Previously this compiled index.yar wholesale, so the raw-APK scan ran all
    rules including the `scope = "source"` ones written for decompiled Java.
    That is where the meaningless container matches came from.

    🔴 It then kept every `scope = "both"` rule, which reintroduced the same
    problem for behaviour rules. Measured over 604 benign apps and 640 malware:
    ``Android_BFSI_Accessibility_Driven_Exfil`` matched **82 times at container
    scope on benign apps and 0 on malware**, turning a rule with +0.007
    discrimination into one with −0.090. Benign F-Droid apps have a median of
    3,519 decompiled files against malware's 426, so a large archive simply
    offers more raw bytes for a coincidental hit — and a conjunction like
    "accessibility AND network" means nothing across a compressed archive,
    because co-location inside one class is the entire claim (T20/T21).

    So the container pass is now restricted to rules that explicitly declare
    ``scope = "apk"``. That is T3's actual intent: the container pass exists for
    ZIP-structure rules, and those are the only rules that can say anything
    true about a container.
    """
    cleaned = [_filter_scope(text, target_scope="apk", strict=True)
               for _, text in _rule_sources()]
    return yara.compile(source="\n".join(cleaned))


def _filter_scope(text: str, target_scope: str = "source",
                  strict: bool = False) -> str:
    """Remove rules whose scope meta does not match target_scope.

    Scans for 'scope = "..."' meta lines and removes the entire rule if the
    scope mismatches. Rules with no scope meta, and rules declaring
    scope = "both", are normally kept.

    ``strict`` drops both of those permissive cases: only rules explicitly
    declaring ``target_scope`` survive. Used for the container pass, where a
    "both" behaviour rule produced 82 false positives on benign apps and none
    on malware (see _compile_rules).
    """
    if target_scope not in ("apk", "source"):
        return text

    lines = text.split("\n")
    out: list[str] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        if re.match(r"^\s*rule\s+", line):
            # Find the closing brace of this rule
            brace_depth = 0
            rule_start = i
            rule_lines: list[str] = []
            while i < len(lines):
                rule_lines.append(lines[i])
                brace_depth += lines[i].count("{") - lines[i].count("}")
                if brace_depth == 0 and lines[i].strip() == "}":
                    break
                i += 1
            # Check if rule has scope meta
            scope = None
            for rl in rule_lines:
                m = re.search(r'scope\s*=\s*"(apk|source|both)"', rl)
                if m:
                    scope = m.group(1)
                    break
            if strict:
                keep = scope == target_scope
            else:
                keep = not scope or scope in (target_scope, "both")
            if not keep:
                # Skip this rule
                i += 1
                continue
            out.extend(rule_lines)
        else:
            out.append(line)
        i += 1
    return "\n".join(out)


def _compile_source_rules() -> yara.Rules:
    """Compile rules for source scanning (byte-level checks stripped)."""
    cleaned: list[str] = []
    for _, text in _rule_sources():
        text = _strip_byte_checks(text)
        text = _filter_scope(text, target_scope="source")
        cleaned.append(text)
    return yara.compile(source="\n".join(cleaned))


_RULE_BLOCK = re.compile(r"(?=^rule\s+\w+)", re.M)
# The closing brace may be indented — a rule file that indents its braces must not
# silently lose every content rule from the member ruleset.
_CONDITION_BODY = re.compile(r"condition:(.*?)^\s*\}", re.S | re.M)


def _is_content_rule(rule_block: str) -> bool:
    """Does this rule still assert something about *content* after stripping?

    A rule whose condition was only `uint32be(0) == 0x504B0304 and filesize < 5MB`
    has, once the container gates are removed, no condition left at all — it would
    match every member of every APK. Purely structural rules must therefore stay
    on the container pass, where their gates are meaningful, and be kept out of
    the member ruleset entirely.
    """
    m = _CONDITION_BODY.search(rule_block)
    if not m:
        return False
    cond = m.group(1)
    return "$" in cond or "of them" in cond


def _compile_member_rules() -> yara.Rules:
    """Compile rules for scanning *decompressed members* of an APK.

    This is the ruleset that closed the 92% detection gap. Members were
    previously scanned with the container ruleset, whose rules are gated on
    `uint32be(0) == 0x504B0304`. A `classes.dex` starts with `dex\\n035`, so every
    behaviour rule short-circuited to false against the one place the application's
    strings actually exist in plaintext — the container itself being deflated and
    therefore unreadable. Measured effect of removing the gate here: malware-category
    detection on the dex went from 30% to 60% of samples, and 16 dead rules revived.

    No scope filter is applied. `scope` exists to keep Java-source rules from
    producing noise on the *container*; a dex holds the same API and literal
    strings the source does, so source-scoped rules are legitimate here. Rules that
    match Java syntax rather than strings simply fail to match, which costs nothing.
    """
    kept: list[str] = []
    for _, text in _rule_sources():
        blocks = _RULE_BLOCK.split(_strip_byte_checks(text))
        for block in blocks:
            if not block.strip():
                continue
            if not block.lstrip().startswith("rule "):
                kept.append(block)          # file header: imports, comments
            elif _is_content_rule(block):
                kept.append(block)
    return yara.compile(source="\n".join(kept))


_RULES_CACHE: yara.Rules | None = None
_SOURCE_RULES_CACHE: yara.Rules | None = None
_MEMBER_RULES_CACHE: yara.Rules | None = None


def _get_rules() -> yara.Rules:
    global _RULES_CACHE
    if _RULES_CACHE is None:
        _RULES_CACHE = _compile_rules()
    return _RULES_CACHE


def _get_source_rules() -> yara.Rules:
    global _SOURCE_RULES_CACHE
    if _SOURCE_RULES_CACHE is None:
        _SOURCE_RULES_CACHE = _compile_source_rules()
    return _SOURCE_RULES_CACHE


def _get_member_rules() -> yara.Rules:
    global _MEMBER_RULES_CACHE
    if _MEMBER_RULES_CACHE is None:
        _MEMBER_RULES_CACHE = _compile_member_rules()
    return _MEMBER_RULES_CACHE


def _is_excluded(file: Path, src_dir: Path) -> bool:
    rel = file.relative_to(src_dir).as_posix()
    if rel.startswith("sources/"):
        rel = rel[len("sources/"):]
    return rel.startswith(_EXCLUDE_SOURCE_PREFIXES)


def _scan_one_file(path: Path, rules: yara.Rules, src_dir: Path) -> tuple[str, list]:
    """Scan a single source file. Returns (relative path, matches)."""
    try:
        rel = str(path.relative_to(src_dir))
    except ValueError:
        rel = path.name
    try:
        return rel, rules.match(str(path))
    except Exception:  # noqa: BLE001
        return rel, []


# Members worth scanning inside an APK. The raw container is deflated, so almost
# nothing is visible there; the real content lives in these decompressed members.
_APK_MEMBER_PREFIXES = ("assets/", "res/raw/", "lib/")
_APK_MEMBER_EXACT = ("AndroidManifest.xml",)


def _dex_class_buffers(data: bytes) -> list[tuple[str, bytes]]:
    """Split a `classes.dex` into one buffer per class.

    **A dex is the whole application concatenated**, third-party SDKs included.
    Scanning it as a single buffer reproduces exactly the defect T2 fixed for
    Java sources: a condition like `2 of ($sms*) and 1 of ($exfil*)` is satisfied
    by strings sitting in unrelated library code. Measured directly — whole-dex
    scanning made PennyWise, an expense tracker, match both
    `Android_India_SMS_OTP_Stealer` and `Android_Ransomware_Generic_File_Encryption`.

    A class is the dex-level equivalent of a source file, so per-class buffers
    restore the co-location requirement that makes multi-group conditions mean
    something. Library namespaces are dropped with the same list the source path
    uses, which also removes most of the parsing cost.
    """
    try:
        from androguard.core.dex import DEX
    except ImportError:  # androguard absent: caller falls back to whole-member
        return []

    out: list[tuple[str, bytes]] = []
    try:
        classes = DEX(data).get_classes()
    except Exception:  # noqa: BLE001 — malformed/packed dex; caller degrades
        return []

    for cls in classes:
        try:
            name = cls.get_name()
        except Exception:  # noqa: BLE001
            continue
        # "Lcom/foo/Bar;" -> "com/foo/Bar"
        rel = name[1:-1] if name.startswith("L") and name.endswith(";") else name
        if rel.startswith(_EXCLUDE_SOURCE_PREFIXES):
            continue
        parts = [rel]
        try:
            methods = cls.get_methods()
        except Exception:  # noqa: BLE001
            methods = []
        for method in methods:
            try:
                parts.append(method.get_name())
                code = method.get_code()
                if code is None:
                    continue
                for ins in code.get_bc().get_instructions():
                    name_i = ins.get_name()
                    # `invoke-*` operands are what carry the API surface —
                    # `Landroid/telephony/SmsManager;->sendTextMessage(...)`. They are
                    # references into the dex method pool, not string literals, so a
                    # const-string-only buffer sees none of them. Measured on a
                    # confirmed SMS trojan: const-string only found 0 of
                    # {SmsManager, createFromPdu, getMessageBody, sendTextMessage};
                    # with invoke operands, all four resolve, and createFromPdu and
                    # getMessageBody land in the *same* class — the co-location a
                    # multi-group condition needs.
                    if (name_i.startswith(("const-string", "invoke", "new-instance"))
                            or name_i.startswith(("sget", "iget", "sput", "iput"))):
                        parts.append(ins.get_output())
            except Exception:  # noqa: BLE001
                continue
        out.append((rel, "\n".join(parts).encode("utf-8", errors="replace")))
    return out


def _interesting_members(names: list[str]) -> list[str]:
    out = []
    for n in names:
        if n in _APK_MEMBER_EXACT or n.startswith(_APK_MEMBER_PREFIXES):
            out.append(n)
        elif n.startswith("classes") and n.endswith(".dex"):
            out.append(n)
    return out


def scan_apk(apk_path: str | Path, max_member_bytes: int = 64 << 20) -> list[L1Finding]:
    """Scan an APK with the apk-scoped rule set.

    Two passes, both required and additive:
      1. The raw container, with the **container ruleset** (byte gates intact) —
         the only way ZIP-structure rules (central directory, META-INF layout,
         `$hex_zip at 0`) can ever match.
      2. Decompressed members (dex, manifest, assets, res/raw, native libs), with
         the **member ruleset** (container gates stripped) — the only way content
         rules can match, since everything in the container is deflated and
         therefore invisible to a whole-file scan.

    The two passes must use *different* rulesets. Using the container ruleset on
    members — as this did originally — gates every behaviour rule on ZIP magic
    that a `classes.dex` cannot satisfy, which is what made the scanner blind to
    the application's own string table.
    """
    apk_path = Path(apk_path)
    if not apk_path.exists():
        raise FileNotFoundError(f"APK not found: {apk_path}")
    rules = _get_rules()
    member_rules = _get_member_rules()
    acc: dict[str, _RuleHit] = {}

    try:
        _accumulate(rules.match(str(apk_path)), "container", apk_path.name, acc)
    except Exception:  # noqa: BLE001
        pass

    try:
        with zipfile.ZipFile(apk_path) as zf:
            for name in _interesting_members(zf.namelist()):
                try:
                    info = zf.getinfo(name)
                    if info.file_size > max_member_bytes:
                        continue
                    data = zf.read(name)
                except Exception:  # noqa: BLE001
                    continue
                if name.startswith("classes") and name.endswith(".dex"):
                    # Per class, never the whole dex — see _dex_class_buffers.
                    buffers = _dex_class_buffers(data)
                    if buffers:
                        for cls_name, buf in buffers:
                            try:
                                _accumulate(member_rules.match(data=buf),
                                            "dex_class", f"{name}!{cls_name}", acc)
                            except Exception:  # noqa: BLE001
                                continue
                        continue
                    # Unparseable dex (packed or corrupted): fall through and scan
                    # it whole rather than not at all, and let the breadth fields
                    # record that the location is a whole dex.
                try:
                    _accumulate(member_rules.match(data=data), "apk_member", name, acc)
                except Exception:  # noqa: BLE001
                    continue
    except zipfile.BadZipFile:
        # Deliberately corrupted archives are a documented anti-analysis
        # technique (e.g. the 2026 RTO eChallan dropper). Container-pass
        # results still stand; the caller records the gap.
        pass

    return _acc_to_findings(acc)


def scan_sources(
    src_dir: str | Path,
    max_workers: int = 0,
) -> list[L1Finding]:
    """Scan decompiled Java sources with YARA, one file at a time.

    Files are scanned INDIVIDUALLY, never concatenated. This is a correctness
    requirement, not a performance choice: YARA evaluates a rule's condition
    against whatever buffer it is given, so concatenating N files let conditions
    like `3 of ($wm*) and 2 of ($phish*) and 1 of ($target_pkg*)` be satisfied by
    strings scattered across N unrelated files. Every multi-group rule in the set
    was effectively defeated, which is what made benign apps match
    banking-overlay, ransomware and dropper rules simultaneously.

    Measured cost of per-file scanning on the largest sample in the corpus is
    ~1.2 s — faster than the batched path it replaces, which also paid for a
    buffer copy and an offset binary-search.

    Args:
        src_dir: Directory of decompiled Java sources.
        max_workers: Thread workers (0 = sequential). YARA releases the GIL.
    """
    src_dir = Path(src_dir)
    if not src_dir.exists():
        return []
    rules = _get_source_rules()
    java_files = [f for f in src_dir.rglob("*.java") if not _is_excluded(f, src_dir)]
    if not java_files:
        return []

    acc: dict[str, _RuleHit] = {}
    if max_workers > 0 and len(java_files) > 1:
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = [pool.submit(_scan_one_file, f, rules, src_dir) for f in java_files]
            for future in as_completed(futures):
                try:
                    rel, matches = future.result()
                except Exception:  # noqa: BLE001
                    continue
                if matches:
                    _accumulate(matches, "source", rel, acc)
    else:
        for f in java_files:
            rel, matches = _scan_one_file(f, rules, src_dir)
            if matches:
                _accumulate(matches, "source", rel, acc)

    return _acc_to_findings(acc)


def scan_text(text: str, source_label: str = "text") -> list[L1Finding]:
    """Scan a blob of text (e.g. a Ghidra strings export) with the source rules."""
    if not text.strip():
        return []
    rules = _get_source_rules()
    try:
        matches = rules.match(data=text.encode("utf-8"))
    except Exception:  # noqa: BLE001
        return []
    acc: dict[str, _RuleHit] = {}
    _accumulate(matches, "text", source_label, acc)
    return _acc_to_findings(acc)
