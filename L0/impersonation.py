"""Brand-impersonation matching for L0.

Replaces the previous `difflib.SequenceMatcher` similarity gate, which was both
too weak and too strong at once: it scored "SBI Quick Support" against
"YONO SBI" at 0.31 (missing a real State Bank of India clone) while scoring
"duckAssist" against the Income Tax alt-label "iAssist" at 0.706 — enough to
raise a *critical* bank-impersonation finding on a benign note-taking app.

The replacement matches **whole tokens and whole phrases** drawn from curated
per-entity brand vocabularies. Whole-token matching is what fixes both failures:
"SBI Quick Support" tokenises to {sbi, quick, support} and hits the token `sbi`,
while "duckAssist" camel-splits to {duck, assist} and therefore cannot hit
`iassist`.

Two deliberate omissions, both measured over a 110-pair inventory before being
cut:

* **No substring matching.** Compaction manufactures token boundaries that do
  not exist — "BOI Mobile" compacts to "boimobile", which contains "imobile"
  (ICICI's brand token), producing a cross-brand false positive inside the
  reference data itself. Over 110 pairs, substring mode produced 1 false
  positive and 0 unique true positives.
* **No fuzzy/edit-distance matching on labels.** That is what produced the
  duckAssist failure.

Scope boundary, load-bearing — do not "improve" this later: L0 matches only
**manifest-declared identity** (package name, app label). It never inspects dex
or string content. That is the structural reason PennyWise — an expense tracker
that legitimately mentions bank names in its strings — stays clean here.
String-level bank references belong to L1's inject-list analysis.
"""

from __future__ import annotations

import re
import unicodedata
from typing import Any

# Words that are not anybody's brand. A curated `strong` token colliding with
# this set is a load-time error, not a silent false-positive source.
GENERIC_TOKENS = {
    "bank", "banking", "india", "indian", "mobile", "app", "apps", "pay",
    "payment", "payments", "upi", "wallet", "online", "secure", "security",
    "plus", "lite", "official", "new", "the", "of", "and", "ltd", "limited",
    "corporation", "corp", "co", "customer", "care", "support", "service",
    "services", "account", "accounts", "net", "netbanking", "digital", "money",
    "finance", "financial", "card", "cards", "quick", "easy", "smart", "my",
}

# Package prefixes that name no vendor. Never usable as a vendor prefix.
GENERIC_PACKAGE_PREFIXES = {
    "com", "org", "net", "in", "io", "app", "android", "mobile", "co",
    "com.google", "com.android", "com.example", "androidx", "org.apache",
    "in.gov", "in.org", "tax.gov", "com.upi", "gov", "tax",
}

# Latin/Cyrillic homoglyphs and digit substitutions used in label spoofing.
# The corpus contains live examples (e.g. "Сhrоme" with Cyrillic С and о).
_CONFUSABLES = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c",
    "х": "x", "у": "y", "А": "a", "Е": "e", "О": "o",
    "Р": "p", "С": "c", "Х": "x", "Ү": "y", "І": "i",
    "і": "i", "ο": "o", "α": "a", "ρ": "p",
    "0": "o", "1": "i", "3": "e", "5": "s", "$": "s", "@": "a",
})

_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
# Keep Devanagari as word characters so regional alt-labels tokenise sanely.
_SPLIT = re.compile(r"[^0-9a-zऀ-ॿ]+")


def confusable_fold(text: str) -> str:
    """Normalise homoglyphs so `Сhrоme` and `Chrome` compare equal."""
    return unicodedata.normalize("NFKC", text or "").translate(_CONFUSABLES).casefold()


def normalise_label(label: str) -> list[str]:
    """Label -> lowercase token list, splitting camelCase and punctuation.

    `duckAssist` -> ['duck', 'assist']   (this is the duckAssist fix)
    `SBI Quick Support` -> ['sbi', 'quick', 'support']
    """
    if not label:
        return []
    text = unicodedata.normalize("NFKC", label)
    text = _CAMEL.sub(" ", text)
    text = text.translate(_CONFUSABLES).casefold()
    tokens = [t for t in _SPLIT.split(text) if t]
    # Collapse runs of single characters: "S B I Bank" -> "sbi bank"
    out: list[str] = []
    run: list[str] = []
    for t in tokens:
        if len(t) == 1:
            run.append(t)
            continue
        if len(run) >= 2:
            out.append("".join(run))
        run = []
        out.append(t)
    if len(run) >= 2:
        out.append("".join(run))
    return out


def normalise_package(pkg: str) -> str:
    return confusable_fold(pkg or "")


def _entity_tokens(entity: dict[str, Any]) -> tuple[set[str], list[str]]:
    """Return (strong tokens, phrases) for a whitelist entity.

    Reads curated `brand_tokens` when present. Falls back to deriving from
    bank_name/app_label with the generic stoplist applied — derivation alone is
    a false-positive source, so derived tokens are only used when nothing was
    curated, and single-character results are discarded.
    """
    bt = entity.get("brand_tokens") or {}
    strong = {t.casefold() for t in bt.get("strong", []) if t}
    phrases = [p.casefold() for p in bt.get("phrase", []) if p]
    if not strong and not phrases:
        derived: set[str] = set()
        for field in ("bank_name", "app_label"):
            for tok in normalise_label(entity.get(field) or ""):
                if tok not in GENERIC_TOKENS and len(tok) >= 3:
                    derived.add(tok)
        strong = derived
    return strong - GENERIC_TOKENS, phrases


def validate_whitelist(whitelist: dict) -> list[str]:
    """Return a list of load-time problems. Empty means the data is sane."""
    problems: list[str] = []
    for e in whitelist.get("banks", []):
        name = e.get("bank_name", "<unnamed>")
        strong, _ = _entity_tokens(e)
        bad = strong & GENERIC_TOKENS
        if bad:
            problems.append(f"{name}: brand token(s) in generic stoplist: {sorted(bad)}")
        for prefix in e.get("vendor_prefixes", []) or []:
            if prefix.casefold() in GENERIC_PACKAGE_PREFIXES:
                problems.append(f"{name}: generic vendor prefix {prefix!r}")
            elif not e.get("package_verified"):
                problems.append(
                    f"{name}: vendor prefix {prefix!r} on an unverified package name")
    return problems


def match_label_brand(label: str, whitelist: dict) -> list[dict[str, Any]]:
    """Whole-token and whole-phrase brand claims found in an app label."""
    tokens = normalise_label(label)
    if not tokens:
        return []
    token_set = set(tokens)
    joined = " ".join(tokens)
    claims: list[dict[str, Any]] = []
    for e in whitelist.get("banks", []):
        strong, phrases = _entity_tokens(e)
        hit_tokens = sorted(token_set & strong)
        hit_phrases = [p for p in phrases if p and p in joined]
        if not hit_tokens and not hit_phrases:
            continue
        claims.append({
            "type": "label_brand_phrase" if hit_phrases else "label_brand_token",
            "entity": e.get("bank_name"),
            "entity_package": e.get("package_name"),
            "matched_tokens": hit_tokens,
            "matched_phrases": hit_phrases,
        })
    return claims


def match_package(pkg: str, whitelist: dict) -> list[dict[str, Any]]:
    """Vendor-namespace squatting and brand segments in a package name."""
    pkg_norm = normalise_package(pkg)
    if not pkg_norm:
        return []
    segments = set(pkg_norm.split("."))
    claims: list[dict[str, Any]] = []
    for e in whitelist.get("banks", []):
        official = e.get("package_name") or ""
        known = {k.casefold() for k in (e.get("known_packages") or [])} | {official.casefold()}
        if pkg_norm in known:
            continue  # this IS an official package; not a claim
        strong, _ = _entity_tokens(e)

        # Vendor prefixes are curated and only trusted on verified packages.
        if e.get("package_verified"):
            for prefix in e.get("vendor_prefixes", []) or []:
                p = prefix.casefold()
                if p in GENERIC_PACKAGE_PREFIXES:
                    continue
                if pkg_norm == p or pkg_norm.startswith(p + "."):
                    claims.append({
                        "type": "package_namespace_squat",
                        "entity": e.get("bank_name"),
                        "vendor_prefix": prefix,
                        "official_package": official,
                    })
                    break

        # A package segment equal to a distinctive brand token.
        seg_hits = sorted(s for s in segments & strong if len(s) >= 3)
        if seg_hits:
            claims.append({
                "type": "package_brand_segment",
                "entity": e.get("bank_name"),
                "matched_segments": seg_hits,
                "official_package": official,
            })
    return claims
