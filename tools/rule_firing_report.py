"""A4 — per-signal firing rates and the computed weights L5 spends.

    source source_env.sh
    $SENTINEL_PYTHON tools/corpus_labels.py build
    $SENTINEL_PYTHON tools/rule_firing_report.py

Reads the **spines** (not raw layer artifacts) via ``spine.iter_spines()``,
joins them to ``corpus/labels.json``, and prices every signal in the
``signals.py`` namespace.

**The point of this tool is that L5's weights are measured rather than
asserted.** A hand-tuned weight table is a set of opinions with a false air of
precision; this one is a log-odds ratio computed from counts, printed with the
interval around it, and stamped ``unsupported`` when the counts cannot carry it.

    w = ln((m + 0.5)/(M − m + 0.5)) − ln((b + 0.5)/(B − b + 0.5))

Jeffreys smoothing (the +0.5) keeps the weight finite at b = 0, which is the
common case — but finite is not the same as trustworthy, hence the interval.

🔴 **Read the support stamp before believing any number here.** At B = 4 the
Jeffreys 95% upper bound on a benign rate of 0/4 is **0.445**: "zero false
positives" over four apps is statistically consistent with a rule that fires on
44% of benign software. Weights computed against a denominator that small are
emitted so the pipeline can be exercised end to end, and are marked
``unsupported`` so nothing downstream can quietly treat them as evidence.

The weight is a log **odds ratio**, not a log likelihood ratio. Used additively
over *present* signals only, it makes the score a monotone evidence total rather
than a log-posterior — every point traceable to something observed, and nothing
deducted for an absence. That approximation is recorded in ``method.note`` of
the weights file and absorbed by L5's fitted calibration.
"""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

REPO_ROOT = Path(__file__).resolve().parent.parent
for _p in (str(REPO_ROOT), str(REPO_ROOT / "L1")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import signals as sig_mod  # noqa: E402
import spine  # noqa: E402
from tools import corpus_labels  # noqa: E402

WEIGHTS_SCHEMA = "apk-sentinel-weights-1"

YARA_DIR = REPO_ROOT / "L1" / "yara_templates"

# Below this the benign denominator cannot support a weight. 30 is where the
# Jeffreys upper bound on 0 hits falls under 0.08 — still weak, but no longer
# consistent with "fires on half of all benign apps".
DEFAULT_MIN_BENIGN = 30
DEFAULT_MIN_MALWARE = 30
DEFAULT_CLIP = 3.0


def jeffreys_interval(hits: int, total: int) -> tuple[float, float]:
    """Equal-tailed Jeffreys 95% interval for a binomial rate.

    Boundary convention: at 0 hits the lower limit is exactly 0, and at total
    hits the upper limit is exactly 1. Beta.ppf would return a small non-zero
    lower bound at 0 hits, which reads as "we saw a few" and is misleading.
    """
    if total <= 0:
        return (0.0, 1.0)
    from scipy.stats import beta  # local: keeps import cost off the --help path

    lo = 0.0 if hits == 0 else float(beta.ppf(0.025, hits + 0.5, total - hits + 0.5))
    hi = 1.0 if hits == total else float(beta.ppf(0.975, hits + 0.5, total - hits + 0.5))
    return (lo, hi)


def log_odds(m: int, M: int, b: int, B: int) -> float:
    """Jeffreys-smoothed log odds ratio: the A4 weight, verbatim from the plan."""
    if M <= 0 or B <= 0:
        return 0.0
    return (math.log((m + 0.5) / (M - m + 0.5))
            - math.log((b + 0.5) / (B - b + 0.5)))


def benign_needed_for_positive_weight(m: int, M: int) -> int:
    """Smallest B making w > 0 when b = 0.

    Solving ln((m+.5)/(M−m+.5)) > ln(0.5/(B+.5)) gives
    B > 0.5·(M−m+.5)/(m+.5) − 0.5. This is the number that turns "grow the
    benign set" from a preference into a requirement with a size attached.
    """
    if m <= 0 or M <= 0:
        return 0
    return max(0, math.ceil(0.5 * (M - m + 0.5) / (m + 0.5) - 0.5))


# ---------------------------------------------------------------------------
# Ruleset introspection — which rules exist, and can a dead one match anything?
# ---------------------------------------------------------------------------

_RULE_RE = re.compile(r"^\s*rule\s+([A-Za-z0-9_]+)", re.M)
_STRING_RE = re.compile(r'^\s*(\$[A-Za-z0-9_]*)\s*=\s*(.+?)\s*$', re.M)


@dataclass
class RuleMeta:
    name: str
    file: str
    body: str
    category: str = "other"
    severity: str = "low"


def parse_rules(yara_dir: Path = YARA_DIR) -> dict[str, RuleMeta]:
    """Every declared rule, with its source block, keyed by name."""
    out: dict[str, RuleMeta] = {}
    for path in sorted(yara_dir.rglob("*.yar")):
        if path.name == "index.yar":
            continue
        text = path.read_text(errors="replace")
        starts = [(m.group(1), m.start()) for m in _RULE_RE.finditer(text)]
        for i, (name, start) in enumerate(starts):
            end = starts[i + 1][1] if i + 1 < len(starts) else len(text)
            body = text[start:end]
            cat = re.search(r'category\s*=\s*"([^"]+)"', body)
            sev = re.search(r'severity\s*=\s*"([^"]+)"', body)
            out[name] = RuleMeta(
                name=name, file=path.name, body=body,
                category=cat.group(1) if cat else "other",
                severity=(sev.group(1).lower() if sev else "low"),
            )
    return out


def self_match_class(meta: RuleMeta) -> str:
    """Can this rule match a buffer containing every literal string it declares?

    A rule that cannot is structurally broken regardless of the corpus. A rule
    that can is telling you something about the corpus instead — which is a
    different problem with a different fix, and conflating the two sends you
    rewriting rules that were never wrong.

    Only conclusive in the negative when the condition has no negation and no
    regex-only group, hence the two ``inconclusive_*`` outcomes.
    """
    import yara

    literals: list[bytes] = []
    has_regex = False
    for _ident, value in _STRING_RE.findall(meta.body):
        value = value.strip()
        if value.startswith("/"):
            has_regex = True
            continue
        m = re.match(r'^"((?:[^"\\]|\\.)*)"', value)
        if m:
            try:
                literals.append(m.group(1).encode().decode("unicode_escape").encode("latin-1"))
            except (UnicodeDecodeError, UnicodeEncodeError):
                literals.append(m.group(1).encode("utf-8", "ignore"))
        elif value.startswith("{"):
            hexpairs = re.findall(r"\b([0-9A-Fa-f]{2})\b", value)
            if hexpairs:
                literals.append(bytes(int(h, 16) for h in hexpairs))

    has_negation = bool(re.search(r"\bnot\b", meta.body))

    try:
        rules = yara.compile(source=meta.body)
    except yara.Error:
        return "compile_fail"

    buffer = b"\x00".join(literals) if literals else b""
    # Give byte-offset conditions (uint32be(0) == …) a plausible container head.
    buffer = b"PK\x03\x04" + b"\x00" * 26 + buffer + b"AndroidManifest.xmlclasses.dex"

    if rules.match(data=buffer):
        return "self_match"
    if has_regex:
        return "inconclusive_regex"
    if has_negation:
        return "inconclusive_negation"
    return "condition_broken"


# ---------------------------------------------------------------------------
# Corpus view
# ---------------------------------------------------------------------------

@dataclass
class SampleView:
    sha256: str
    cls: str
    subclass: str | None
    keys: set[str]
    l1_status: str
    decompiled_files: int
    categories: dict[str, str] = field(default_factory=dict)
    scopes: dict[str, tuple[str, ...]] = field(default_factory=dict)

    @property
    def l1_ran(self) -> bool:
        return self.l1_status in ("complete", "partial")


def build_views(labels: dict[str, Any], spine_root: Path | None) -> tuple[list[SampleView], int]:
    views: list[SampleView] = []
    unlabelled = 0
    for doc in spine.iter_spines(spine_root):
        sha = doc.get("sha256", "")
        entry = labels.get(sha)
        if not entry:
            unlabelled += 1
            continue
        l1 = (doc.get("layers", {}).get("l1") or {})
        cov = l1.get("coverage") or {}
        sigs = sig_mod.signals(doc)
        views.append(SampleView(
            sha256=sha,
            cls=entry["class"],
            subclass=entry.get("subclass"),
            keys={s.key for s in sigs},
            l1_status=l1.get("status", "not_attempted"),
            decompiled_files=int(cov.get("decompiled_files") or 0),
            categories={s.key: s.category for s in sigs},
            scopes={s.key: s.scopes for s in sigs},
        ))
    return views, unlabelled


# ---------------------------------------------------------------------------
# The statistics
# ---------------------------------------------------------------------------

@dataclass
class SignalStat:
    key: str
    m: int
    M: int
    b: int
    B: int
    w_raw: float
    w: float
    ben_ci: tuple[float, float]
    category: str
    scopes: dict[str, int]
    support: str
    degenerate: bool
    needed_B: int

    @property
    def mal_rate(self) -> float:
        return self.m / self.M if self.M else 0.0

    @property
    def ben_rate(self) -> float:
        return self.b / self.B if self.B else 0.0

    @property
    def discrimination(self) -> float:
        return self.mal_rate - self.ben_rate


def compute(views: list[SampleView], *, clip: float, min_benign: int,
            min_malware: int, source_scope_only: set[str]) -> list[SignalStat]:
    mal = [v for v in views if v.cls == corpus_labels.CLASS_MALWARE]
    ben = [v for v in views if v.cls == corpus_labels.CLASS_BENIGN]

    all_keys = sorted({k for v in views for k in v.keys})
    stats: list[SignalStat] = []

    for key in all_keys:
        # Scope-eligible denominator. A source-scope rule cannot fire on a
        # sample jadx never decompiled, so counting it dilutes the rate and
        # inflates the weight (T18/B26 make this a large population, not an edge).
        if key in source_scope_only:
            elig_m = [v for v in mal if v.decompiled_files > 0]
            elig_b = [v for v in ben if v.decompiled_files > 0]
        else:
            elig_m = [v for v in mal if v.l1_ran or key.startswith(sig_mod.NS_L0)]
            elig_b = [v for v in ben if v.l1_ran or key.startswith(sig_mod.NS_L0)]

        M, B = len(elig_m), len(elig_b)
        m = sum(1 for v in elig_m if key in v.keys)
        b = sum(1 for v in elig_b if key in v.keys)

        w_raw = log_odds(m, M, b, B)
        scopes: Counter[str] = Counter()
        category = "other"
        for v in views:
            if key in v.keys:
                category = v.categories.get(key, category)
                for s in v.scopes.get(key, ()):
                    scopes[s] += 1

        mal_rate = m / M if M else 0.0
        ben_rate = b / B if B else 0.0
        support = ("supported" if B >= min_benign and M >= min_malware
                   else "unsupported")

        stats.append(SignalStat(
            key=key, m=m, M=M, b=b, B=B,
            w_raw=w_raw, w=max(-clip, min(clip, w_raw)),
            ben_ci=jeffreys_interval(b, B),
            category=category, scopes=dict(scopes), support=support,
            degenerate=(mal_rate > 0.9 and ben_rate > 0.9) or abs(w_raw) < 0.2,
            needed_B=benign_needed_for_positive_weight(m, M),
        ))
    return sorted(stats, key=lambda s: -s.w)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--labels", default=str(corpus_labels.LABELS_PATH))
    ap.add_argument("--spine-root", default=None)
    ap.add_argument("--out-report", default=None,
                    help="default docs/reports/rule_firing_<date>.md")
    ap.add_argument("--out-weights", default=None,
                    help="default L5/weights/rule_weights_<date>.json")
    ap.add_argument("--min-benign", type=int, default=DEFAULT_MIN_BENIGN)
    ap.add_argument("--min-malware", type=int, default=DEFAULT_MIN_MALWARE)
    ap.add_argument("--w-clip", type=float, default=DEFAULT_CLIP)
    ap.add_argument("--no-dead-probe", action="store_true",
                    help="skip the per-rule self-match test")
    args = ap.parse_args(argv)

    labels_doc = corpus_labels.load(Path(args.labels))
    labels = corpus_labels.general_population(labels_doc["labels"])
    spine_root = Path(args.spine_root) if args.spine_root else None

    views, unlabelled = build_views(labels, spine_root)

    # A rule seen only at source scope gets the narrower denominator.
    scope_union: dict[str, set[str]] = defaultdict(set)
    for v in views:
        for k, sc in v.scopes.items():
            scope_union[k].update(sc)
    source_scope_only = {k for k, sc in scope_union.items() if sc and sc <= {"source"}}

    stats = compute(views, clip=args.w_clip, min_benign=args.min_benign,
                    min_malware=args.min_malware,
                    source_scope_only=source_scope_only)

    rules = parse_rules()
    fired_rules = {s.key[len(sig_mod.NS_YARA):] for s in stats
                   if s.key.startswith(sig_mod.NS_YARA)}
    dead = sorted(set(rules) - fired_rules)
    dead_class: dict[str, str] = {}
    if not args.no_dead_probe:
        for name in dead:
            dead_class[name] = self_match_class(rules[name])

    date = datetime.now(timezone.utc).strftime("%Y%m%d")
    out_w = Path(args.out_weights or REPO_ROOT / "L5" / "weights" / f"rule_weights_{date}.json")
    out_r = Path(args.out_report or REPO_ROOT / "docs" / "reports" / f"rule_firing_{date}.md")

    n_mal = sum(1 for v in views if v.cls == corpus_labels.CLASS_MALWARE)
    n_ben = sum(1 for v in views if v.cls == corpus_labels.CLASS_BENIGN)
    n_exc = sum(1 for v in views if v.cls == corpus_labels.CLASS_EXCLUDED)
    overall_support = ("supported" if n_ben >= args.min_benign else "unsupported")

    try:
        ruleset_version = __import__(
            "engines.yara_scan", fromlist=["ruleset_version"]).ruleset_version()
    except Exception:
        ruleset_version = "unknown"

    weights_doc = {
        "schema_version": WEIGHTS_SCHEMA,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "generator": "tools/rule_firing_report.py",
        "signal_schema": sig_mod.SIGNAL_SCHEMA,
        "ruleset_version": ruleset_version,
        "corpus": {
            "n_spines": len(views), "n_malware": n_mal, "n_benign": n_ben,
            "n_excluded": n_exc, "n_unlabelled": unlabelled,
            "labels_file": str(Path(args.labels).name),
            "label_counts": labels_doc.get("counts", {}),
        },
        "method": {
            "weight": "jeffreys_log_odds_ratio", "smoothing": 0.5,
            "clip": args.w_clip, "denominator": "scope_eligible",
            "note": ("log ODDS RATIO used as an evidence-only additive term; "
                     "absent signals contribute 0"),
        },
        "support": {
            "min_benign": args.min_benign, "min_malware": args.min_malware,
            "status": overall_support,
            "reason": (f"n_benign={n_ben}" if overall_support == "unsupported" else ""),
        },
        "weights": {
            s.key: {
                "w": round(s.w, 4), "w_raw": round(s.w_raw, 4),
                "m": s.m, "M": s.M, "b": s.b, "B": s.B,
                "mal_rate": round(s.mal_rate, 4), "ben_rate": round(s.ben_rate, 4),
                "ben_rate_ci95": [round(s.ben_ci[0], 4), round(s.ben_ci[1], 4)],
                "discrimination": round(s.discrimination, 4),
                "support": s.support, "degenerate": s.degenerate,
                "benign_needed_for_positive_weight": s.needed_B,
                "scopes": s.scopes, "category": s.category,
            } for s in stats
        },
        "dead_rules": {
            name: {"class": dead_class.get(name, "not_probed"),
                   "file": rules[name].file,
                   "declared_category": rules[name].category,
                   "declared_severity": rules[name].severity}
            for name in dead
        },
    }
    out_w.parent.mkdir(parents=True, exist_ok=True)
    out_w.write_text(json.dumps(weights_doc, indent=2, sort_keys=True))

    out_r.parent.mkdir(parents=True, exist_ok=True)
    out_r.write_text(render_report(weights_doc, stats, rules, dead_class, labels_doc))

    # ---- console summary -------------------------------------------------
    print(f"spines {len(views)}  malware {n_mal}  benign {n_ben}  excluded {n_exc}"
          f"  unlabelled {unlabelled}")
    print(f"support: {overall_support.upper()}"
          + (f"  ({weights_doc['support']['reason']})" if overall_support == "unsupported" else ""))
    print(f"signals priced: {len(stats)}   dead rules: {len(dead)}")
    if dead_class:
        print(f"dead-rule classes: {dict(Counter(dead_class.values()))}")
    neg = [s for s in stats if s.w < 0]
    print(f"signals with a NEGATIVE weight: {len(neg)} of {len(stats)}")
    print(f"\nwrote {out_w.relative_to(REPO_ROOT)}")
    print(f"wrote {out_r.relative_to(REPO_ROOT)}")
    return 0


def render_report(doc: dict[str, Any], stats: list[SignalStat],
                  rules: dict[str, RuleMeta], dead_class: dict[str, str],
                  labels_doc: dict[str, Any]) -> str:
    c = doc["corpus"]
    sup = doc["support"]
    L: list[str] = []
    a = L.append

    a(f"# A4 — rule firing report ({doc['generated_at'][:10]})\n")
    a(f"- corpus: **{c['n_malware']} malware**, **{c['n_benign']} benign**, "
      f"{c['n_excluded']} excluded, {c['n_unlabelled']} unlabelled")
    a(f"- ruleset `{doc['ruleset_version']}` · signals `{doc['signal_schema']}` "
      f"· labels `{c['labels_file']}`")
    a(f"- weight: Jeffreys-smoothed log odds ratio, clip ±{doc['method']['clip']}, "
      f"denominator `{doc['method']['denominator']}`")
    a(f"- **support: {sup['status'].upper()}**"
      + (f" — {sup['reason']}" if sup["reason"] else ""))

    if sup["status"] == "unsupported":
        a("")
        a("> 🔴 **Every weight below is unsupported and must not be used as evidence.**")
        a("> With this few benign apps the Jeffreys 95% upper bound on a benign rate")
        a("> of 0 is wide enough to be consistent with a rule that fires on a large")
        a("> fraction of benign software. These numbers exist to exercise the")
        a("> pipeline and to quantify how much benign data is actually needed.")

    a("\n## Corpus caveats\n")
    for s in labels_doc.get("sources", []):
        for cav in s.get("caveats", []):
            a(f"- `{s['id']}`: {cav}")
        if s.get("reason"):
            a(f"- `{s['id']}`: {s['reason']}")

    a("\n## Signal weights\n")
    a("| weight | m/M | b/B | mal rate | ben rate | ben 95% CI | discrim | support | signal |")
    a("|---:|---:|---:|---:|---:|:---:|---:|:---:|---|")
    for s in stats:
        flag = " ⚠️deg" if s.degenerate else ""
        a(f"| {s.w:+.2f} | {s.m}/{s.M} | {s.b}/{s.B} | {s.mal_rate:.3f} | "
          f"{s.ben_rate:.3f} | [{s.ben_ci[0]:.3f}, {s.ben_ci[1]:.3f}] | "
          f"{s.discrimination:+.3f} | {s.support[:5]} | `{s.key}`{flag} |")

    neg = [s for s in stats if s.w < 0]
    if neg:
        a(f"\n## 🔴 Sign sanity — {len(neg)} of {len(stats)} signals priced negative\n")
        a("A negative weight means *this signal is evidence of being benign*. Where")
        a("that contradicts the signal's own declared severity, the denominator is")
        a("the suspect, not the rule. `benign needed` is the smallest benign corpus")
        a("that would make the weight positive at the observed malware rate.\n")
        a("| weight | signal | category | benign needed |")
        a("|---:|---|---|---:|")
        for s in sorted(neg, key=lambda s: s.w):
            a(f"| {s.w:+.2f} | `{s.key}` | {s.category} | {s.needed_B} |")
        worst = max(s.needed_B for s in neg)
        a(f"\n**A benign corpus of ≥ {worst} apps makes every currently-negative "
          f"signal sign-correct.**")

    deg = [s for s in stats if s.degenerate]
    if deg:
        a(f"\n## Degenerate signals ({len(deg)})\n")
        a("Fires on nearly everything in both classes, or carries a weight too")
        a("small to matter. L5 prices these at zero **by measurement**, not by a")
        a("hand-maintained blocklist.\n")
        for s in deg:
            a(f"- `{s.key}` — mal {s.mal_rate:.3f}, ben {s.ben_rate:.3f}, w {s.w:+.2f}")

    if dead_class:
        a(f"\n## Dead rules ({len(dead_class)})\n")
        a("Declared but never fired on this corpus. The self-match test compiles")
        a("each rule alone against a buffer built from its own declared strings:")
        a("a rule that cannot match that **is broken**; one that can is telling you")
        a("something about the corpus instead. Conflating the two sends you")
        a("rewriting rules that were never wrong.\n")
        a("| rule | file | class | declared category |")
        a("|---|---|---|---|")
        for name, klass in sorted(dead_class.items(), key=lambda kv: (kv[1], kv[0])):
            a(f"| `{name}` | {rules[name].file} | **{klass}** | {rules[name].category} |")
        a("")
        for klass, n in sorted(Counter(dead_class.values()).items()):
            a(f"- `{klass}`: {n}")

    a("\n## Method\n")
    a("```")
    a("w = ln((m + 0.5)/(M - m + 0.5)) - ln((b + 0.5)/(B - b + 0.5))")
    a("```")
    a(f"\n{doc['method']['note']}.\n")
    a("Malware vintage is 2020–2022; any weight partly measures era rather than")
    a("malice, and that cannot be separated on this corpus.")
    return "\n".join(L) + "\n"


if __name__ == "__main__":
    raise SystemExit(main())
