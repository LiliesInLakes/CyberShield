"""L1 YARA scanning engine.

Scans raw APK and decompiled Java sources using the YARA rule set
in L1/yara_templates/. Replaces the naive SUSPICIOUS_SIGS string matching.

Two modes:
  - APK scan: rules as-is, catches format anomalies, embedded payloads, IOCs
  - Source scan: rules with byte-level checks (filesize, uint32) stripped,
    catches behavioral patterns in decompiled Java code
"""

from __future__ import annotations

import bisect
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

import yara

from schema import L1Finding, Severity, Category

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
    combined = f"{name} {meta.get('description', '')}"
    for pattern, cat in _CATALOG:
        if pattern.search(combined):
            return cat
    return Category.OTHER


def _findings_from_matches(matches: list, engine_label: str) -> list[L1Finding]:
    findings: list[L1Finding] = []
    seen: set[tuple[str, str]] = set()
    for result in matches:
        rule_name = result.rule
        meta = result.meta
        sev = _SEV_MAP.get(meta.get("severity", "medium"), Severity.MEDIUM)
        cat = _categorize(rule_name, meta)
        desc = meta.get("description", rule_name)
        string_matches = getattr(result, "strings", None) or []
        for sm in string_matches[:5]:
            for inst in sm.instances[:2]:
                data = inst.matched_data.decode("utf-8", errors="replace")[:200]
            key = (rule_name, data[:80])
            if key in seen:
                continue
            seen.add(key)
            findings.append(L1Finding(
                engine=engine_label,
                category=cat,
                severity=sev,
                evidence=f"[{rule_name}] {desc} -> {data}",
                location=sm.identifier if sm.instances else rule_name,
                detail={"yara_rule": rule_name, "matched_strings": len(string_matches)},
            ))
        if not string_matches:
            key = (rule_name, "")
            if key not in seen:
                seen.add(key)
                findings.append(L1Finding(
                    engine=engine_label,
                    category=cat,
                    severity=sev,
                    evidence=f"[{rule_name}] {desc}",
                    location=rule_name,
                    detail={"yara_rule": rule_name, "matched_strings": 0},
                ))
    return findings


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
        r"^(filesize\s*<\s*\d+\s*MB\s*"           # filesize < N
        r"|uint32\(0\)\s*==\s*0x[0-9A-Fa-f]+\s*"  # uint32(0) == 0x...
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


def _compile_rules() -> yara.Rules:
    return yara.compile(filepath=str(INDEX_FILE))


def _filter_scope(text: str, target_scope: str = "source") -> str:
    """Remove rules whose scope meta does not match target_scope.

    Scans for 'scope = "..."' meta lines and removes entire rule if scope mismatches.
    Rules without scope meta are always kept.
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
                m = re.search(r'scope\s*=\s*"(apk|source)"', rl)
                if m:
                    scope = m.group(1)
                    break
            if scope and scope != target_scope:
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
    index_text = INDEX_FILE.read_text(encoding="utf-8")
    includes = re.findall(r'include\s+"(.+\.yar)"', index_text)
    cleaned: list[str] = []
    for inc in includes:
        path = YARA_DIR / inc
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8")
        text = _strip_byte_checks(text)
        text = _filter_scope(text, target_scope="source")
        cleaned.append(text)
    combined = "\n".join(cleaned)
    return yara.compile(source=combined)


_RULES_CACHE: yara.Rules | None = None
_SOURCE_RULES_CACHE: yara.Rules | None = None


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


def _is_excluded(file: Path, src_dir: Path) -> bool:
    rel = file.relative_to(src_dir).as_posix()
    if rel.startswith("sources/"):
        rel = rel[len("sources/"):]
    return rel.startswith(_EXCLUDE_SOURCE_PREFIXES)


def _find_file_by_offset(
    offset: int,
    file_offsets: list[tuple[int, int, Path]],
) -> Path | None:
    """Binary search: find file containing byte offset in concatenated buffer."""
    if not file_offsets:
        return None
    starts = [fo[0] for fo in file_offsets]
    i = bisect.bisect_right(starts, offset) - 1
    if i >= 0 and offset < file_offsets[i][1]:
        return file_offsets[i][2]
    return None


def _scan_batch(
    batch_files: list[Path],
    rules: yara.Rules,
    src_dir: Path,
) -> list[L1Finding]:
    """Concatenate batch files, YARA scan once, resolve file paths via offset."""
    buf = bytearray()
    file_offsets: list[tuple[int, int, Path]] = []

    for f in batch_files:
        try:
            data = f.read_bytes()
            start = len(buf)
            buf.extend(data)
            file_offsets.append((start, len(buf), f))
        except Exception:
            continue

    if not buf:
        return []

    try:
        matches = rules.match(data=bytes(buf))
    except Exception:
        return []

    findings: list[L1Finding] = []
    seen: set[tuple[str, str]] = set()

    for result in matches:
        rule_name = result.rule
        meta = result.meta
        sev = _SEV_MAP.get(meta.get("severity", "medium"), Severity.MEDIUM)
        cat = _categorize(rule_name, meta)
        desc = meta.get("description", rule_name)
        string_matches = getattr(result, "strings", None) or []

        for sm in string_matches:
            for inst in sm.instances:
                data = inst.matched_data.decode("utf-8", errors="replace")[:200]
                offset = inst.offset
                src_file = _find_file_by_offset(offset, file_offsets)
                rel = str(src_file.relative_to(src_dir)) if src_file else "unknown"

                key = (rule_name, rel)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(L1Finding(
                    engine="yara_source",
                    category=cat,
                    severity=sev,
                    evidence=f"[{rule_name}] {desc} -> {data}",
                    location=f"{rel}:{sm.identifier}",
                    detail={"yara_rule": rule_name, "source_file": rel},
                ))
                break  # one finding per rule per file

        if not string_matches:
            key = (rule_name, "")
            if key not in seen:
                seen.add(key)
                findings.append(L1Finding(
                    engine="yara_source",
                    category=cat,
                    severity=sev,
                    evidence=f"[{rule_name}] {desc}",
                    location=rule_name,
                    detail={"yara_rule": rule_name, "source_file": ""},
                ))

    return findings


def scan_apk(apk_path: str | Path) -> list[L1Finding]:
    """Scan raw APK file with full YARA rule set."""
    apk_path = Path(apk_path)
    if not apk_path.exists():
        raise FileNotFoundError(f"APK not found: {apk_path}")
    rules = _get_rules()
    matches = rules.match(str(apk_path))
    return _findings_from_matches(matches, "yara_apk")


def scan_sources(
    src_dir: str | Path,
    batch_size: int = 500,
    max_workers: int = 0,
) -> list[L1Finding]:
    """Walk decompiled Java sources, scan with YARA (batched + optional parallel).

    Batches files, concatenates each batch into one buffer, does 1 YARA scan per batch.
    Resolves file paths via byte-offset binary search.

    Args:
        src_dir: Directory of decompiled Java sources.
        batch_size: Files per concatenated batch. Lower = more granular file info.
        max_workers: Thread workers (0 = sequential). Default 0 (sequential).
    """
    src_dir = Path(src_dir)
    if not src_dir.exists():
        return []
    rules = _get_source_rules()
    java_files = [f for f in src_dir.rglob("*.java") if not _is_excluded(f, src_dir)]
    if not java_files:
        return []

    batches = [java_files[i:i+batch_size] for i in range(0, len(java_files), batch_size)]
    all_findings: list[L1Finding] = []

    if max_workers > 0 and len(batches) > 1:
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {pool.submit(_scan_batch, b, rules, src_dir): b for b in batches}
            for future in as_completed(futures):
                try:
                    all_findings.extend(future.result())
                except Exception:
                    continue
    else:
        for batch in batches:
            try:
                all_findings.extend(_scan_batch(batch, rules, src_dir))
            except Exception:
                continue

    seen: set[tuple[str, str]] = set()
    deduped: list[L1Finding] = []
    for f in all_findings:
        key = (f.detail.get("yara_rule", ""), (f.evidence or "")[:80])
        if key not in seen:
            seen.add(key)
            deduped.append(f)
    return deduped


def scan_text(text: str, source_label: str = "text") -> list[L1Finding]:
    """Scan a blob of text (e.g. ghidra strings export) with adapted YARA rules."""
    if not text.strip():
        return []
    rules = _get_source_rules()
    findings: list[L1Finding] = []
    seen: set[tuple[str, str]] = set()
    try:
        matches = rules.match(data=text.encode("utf-8"))
    except Exception:
        return []
    for result in matches:
        rule_name = result.rule
        meta = result.meta
        sev = _SEV_MAP.get(meta.get("severity", "medium"), Severity.MEDIUM)
        cat = _categorize(rule_name, meta)
        desc = meta.get("description", rule_name)
        string_matches = getattr(result, "strings", None) or []
        for sm in string_matches:
            for inst in sm.instances:
                data = inst.matched_data.decode("utf-8", errors="replace")[:200]
                key = (rule_name, data[:60])
                if key in seen:
                    continue
                seen.add(key)
                findings.append(L1Finding(
                    engine="yara_text",
                    category=cat,
                    severity=sev,
                    evidence=f"[{rule_name}] {desc} -> {data}",
                    location=f"{source_label}:{sm.identifier}",
                    detail={"yara_rule": rule_name},
                ))
                break
        if not string_matches:
            key = (rule_name, "")
            if key not in seen:
                seen.add(key)
                findings.append(L1Finding(
                    engine="yara_text",
                    category=cat,
                    severity=sev,
                    evidence=f"[{rule_name}] {desc}",
                    location=rule_name,
                    detail={"yara_rule": rule_name},
                ))
    return findings
