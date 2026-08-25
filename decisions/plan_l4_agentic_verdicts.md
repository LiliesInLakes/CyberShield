# Plan: L4 Agentic Verdicts — 3-Agent Pipeline, Scored 0–10

**Date:** 2026-08-16
**Status:** Draft
**Supersedes:** `plan_l4_rag_verdicts.md` (Phase 1–3 scope kept; verdict shape changes
from 3-way categorical to a 0–10 score; adds a network-correlation step and
splits "explain" from "check" into three agents instead of two LLM calls)
**Depends on:** none (independent of the L2 network-isolation work just landed)

---

## What changes from the previous plan, and why

The prior plan (analyst call → mechanical verify → adversarial verifier call)
is kept as the backbone. Four things change:

1. **Three agents, not two.** The single analyst call is split into an
   **Analyst** (extracts claims — purpose, strings, APIs, a first-pass
   verdict) and a **Reasoning-trail** agent (builds the cited evidence chain
   from those claims against retrieved KB entries). A **Verifier** agent then
   adversarially checks the trail. Splitting narrows each call's job — the
   analyst is not asked to also write a defensible narrative in the same
   breath it's extracting strings, and the verifier checks a trail that
   already cites its sources rather than free-form prose.
2. **Score 0–10 per class, not a 3-way label.** `GROUNDED`/`UNVERIFIED`/
   `REFUTED` collapses real differences (a KB match at cosine 0.95 with every
   claim verified is not the same confidence as one at 0.31). The score
   replaces the label as the thing L6 sorts and displays by; the 3-way
   *reasoning* remains internally as the score's derivation, not the output.
3. **Network correlation, with a documented limitation.** Checked the actual
   instrumentation before proposing this: `mitm_addon.py` records `host`/`url`
   only, and `dynamic_hooks.js` sends findings with no call-stack capture —
   **there is currently no mechanism that attributes a network call to a
   specific class or method.** True code-to-network attribution would need a
   new Frida hook (capture `Java.use("java.lang.Exception").$new().getStackTrace()`
   at the socket/URL-open call site) — that's out of scope here, flagged as
   future work (§7). What *is* shippable now: string/host correlation — if a
   class's decoded strings or literal hosts match an entry in
   `network_evidence.json`'s `c2_endpoints` or the isolation layer's
   blocked-host list, that's surfaced as context to the Analyst. It's
   correlation by content, not proof of causation, and the prompt must say so.
4. **Score stays out of L5**, exactly as before — this plan only feeds L6
   (report-level ranking). The `GROUNDED → L5 ±5 pts` edge from the prior plan
   remains Phase 4, still deferred behind `n_benign ≥ 213` (T24). A 0–10
   report score is useful for triage regardless of when L5 unblocks.

---

## Architecture

```
L0 (bank-impersonation, cert)  ─┐
L1 (finding + source + IOCs)   ─┼─► feature bundle for one class
L2 (sms/overlay/c2 summary,    ─┘        │
    package-level, not class-level)      ▼
                                  ┌───────────────┐
KB (kb.json: MITRE Mobile,       │   RAG          │
 YARA meta, India patterns)  ───►│   retrieval    │──► top-3 KB matches (sim≥0.3)
                                  └───────┬───────┘         or "novel"
                                          ▼
                                  ┌───────────────┐
                          ┌──────►│    Analyst     │  claims: purpose, renamed,
    network_evidence.json │       │    agent       │  decoded_strings, api_calls,
    (string/host match,   │       └───────┬───────┘  iocs, first_verdict, suspicion
    flagged if any) ──────┘               ▼
                                  ┌───────────────┐
                                  │  Mechanical    │  verify.py (unchanged) +
                                  │  verify        │  mitre/pattern existence checks
                                  └───────┬───────┘
                                          ▼ kept claims + KB matches
                                  ┌───────────────┐
                                  │ Reasoning-trail│  RAG-grounded: cites which
                                  │ agent          │  KB entry backs which step
                                  └───────┬───────┘
                                          ▼ evidence_chain (cited)
                                  ┌───────────────┐
                                  │  Verifier      │  adversarial, RAG-grounded:
                                  │  agent         │  "find a flaw", checks each
                                  └───────┬───────┘  citation is real, not invented
                                          ▼
                                  ┌───────────────┐
                                  │  Scorer        │  → 0–10, deterministic function
                                  │  (no LLM)      │    of the above (see §3)
                                  └───────┬───────┘
                                          ▼
                              L6 report: score, verdict, cited trail
                    (L5 edge: same as before, deferred behind T24)
```

---

## 1. Data sourcing per agent — "find the data appropriate for the task"

| Agent | Reads | Does NOT read |
|---|---|---|
| **Analyst** | This class's source (L1 `location`); L0 summary (`brand_claim`, cert anomaly — one line, for context, e.g. "app claims to be SBI"); L2 **package-level** summary (`sms_intercepted`, `overlay_displayed`, `c2_endpoints` — booleans/lists, not per-class); string/host correlation flag from `network_evidence.json`; top-3 KB matches | Other classes' source; raw PCAP; L5 (doesn't exist yet at this point in the pipeline) |
| **Reasoning-trail** | The Analyst's *kept* claims only (post mechanical-verify — never sees a claim `verify.py` already dropped); the KB matches used for retrieval, with full text so it can cite specifics | Raw source code (it explains claims, not re-reads the class — keeps it a distinct, cheaper call) |
| **Verifier** | Source code (to check the trail isn't inventing something absent); the full evidence_chain with citations; the KB entries cited, so it can check a citation is a real match and not a plausible-sounding fabrication | Nothing beyond what it's checking — an adversarial reviewer that gets extra unrelated context is an adversarial reviewer being coached |

This mirrors the existing discipline in `L4/verify.py`'s docstring: every
claim class that a decoder/parser/substring-search can settle is settled that
way, never by asking a model to grade its own work.

---

## 2. `L4/SKILL.md` — the analyst agent spec

**Where:** New file `L4/SKILL.md` (repo convention, not a `.claude/skills/`
entry — this is documentation the analyst *prompt* is built from, read by
`deobfuscate.py` at import time, not a Claude Code skill).

Contents: role, the exact input bundle shape (source, L0/L2 context lines,
KB matches, network-correlation flag), the output JSON schema (extends the
current one — see below), and **explicit negative instructions** carried over
from the measured failure in `provider.py`'s docstring (T26 — the `gate.php`
mis-decode): *"Every string you claim to decode will be re-decoded
mechanically. Every renamed identifier must occur verbatim. Do not decode
your way to a plausible URL — say what the bytes say."*

Extended analyst schema (additions over today's, **bold**):
```json
{
  "purpose": "...",
  "renamed": {...},
  "decoded_strings": {...},
  "api_calls": [...],
  "iocs": [...],
  "behaviours": [...],
  "first_verdict": "malicious|suspicious|benign|unclear",
  **"suspicion": {"flag": true|false, "reason": "free text, carried unverified"},**
  **"matched_pattern": "<kb id or null>",**
  "confidence": "high|medium|low"
}
```

`suspicion` is exactly the "something feels fishy to the LLM" case — a
free-text hunch that never becomes a mechanical fact. It is always carried in
`unverified`, and it is one of the inputs the *scorer* (§3) can use to lift a
claim out of the 0–4 floor when the reasoning is judged sound by the verifier
— see the sub-5 rule below.

---

## 3. Scoring — 0–10, deterministic, not another LLM call

**Where:** New file `L4/scorer.py`. Pure function, no network call — the
score is computed from artifacts the pipeline already produced, so it's
reproducible and auditable (`l5.py --explain`-style transparency).

```python
def score_class(
    kept_claims: dict,           # from verify.py — decoded_strings/renamed/api_calls/iocs that passed
    dropped_claims: list,        # from verify.py
    kb_matches: list[KBMatch],   # from retriever, with similarity scores
    verifier_result: VerifierVerdict,  # confirmed | weakened | refuted, + counter_argument
    suspicion: dict,             # analyst's unverified hunch, if any
) -> ClassScore: ...
```

**Bands** (matches the instruction: sub-5 for unverified-but-reasonable,
0 for refuted, mechanical+RAG grounding required to clear 5):

| Condition | Score |
|---|---|
| `verifier_result == "refuted"` | **0** — dropped from the report's ranked list entirely, kept only in `dropped_claims` for audit |
| No KB match (`matched_pattern is null`) AND no kept mechanical claims AND `suspicion.flag` with a reason the verifier does not refute | **1–4**, scaled by verifier confidence in the counter-check (not the analyst's confidence — the analyst grading itself is not evidence) |
| No KB match, but ≥1 mechanically kept claim (e.g. a verified `api_call` with no KB pattern behind it) | **3–5** — a real, checkable fact with no threat-intel grounding is worth more than a hunch, still short of "matches known malware" |
| KB match (sim ≥ 0.3) AND `verifier_result == "confirmed"` | **5–10**, scaled by `0.3 → 5`, `1.0 → 10` linear on similarity, then −1 per dropped claim (floor 5) |
| KB match AND `verifier_result == "weakened"` | same band as "no KB match, confirmed" (**one band down** — a weakened grounded claim is not better than an ungrounded solid one) |

This directly implements *"unverified claims can be given a sub 5 score in
case llm provides a reasonable reason"* — the reasonableness test is not the
analyst's own confidence field (self-grading), it's whether the **verifier**,
looking for a flaw, failed to find one. That keeps the same anti-self-report
discipline as the rest of L4.

`ClassScore` also carries `band: Literal["grounded","plausible","hunch","refuted"]`
so the report can group by band as well as sort by number — a reader
scanning 8 classes wants "what's the top 3" as much as "what's the exact
score".

---

## 4. Network correlation — the shippable version

**Where:** `L4/network_correlation.py` (new, small — one function).

```python
def correlate(class_literals: Iterable[str], network_evidence: dict) -> list[str]:
    """Literal strings/hosts in this class that also appear in L2's
    c2_endpoints or exfiltration targets. Content match, not causation —
    the docstring and every caller must say so."""
```

Feeds a boolean-ish flag + matched values into the Analyst's context bundle
(§1). Does not claim "this class made this call" — claims "this class
contains a string that also shows up in this sample's captured network
traffic," which is what the data actually supports today.

---

## 5. Files to create / modify

| File | Action |
|---|---|
| `L4/SKILL.md` | **Create** — analyst agent spec (§2) |
| `L4/knowledge/__init__.py`, `build_kb.py`, `kb.json`, `retriever.py` | **Create** — unchanged from the prior plan's Phase 1 |
| `L4/network_correlation.py` | **Create** — §4 |
| `L4/scorer.py` | **Create** — §3 |
| `L4/reasoning_trail.py` | **Create** — second agent call, RAG-grounded, consumes only kept claims + KB matches |
| `L4/verify_verdict.py` | **Create** — third agent call (verifier), adversarial, per prior plan's Phase 3 design |
| `L4/deobfuscate.py` | **Modify** — `explain_class` orchestrates analyst → verify → reasoning-trail → verifier → scorer; `interesting_locations` unchanged; add L0/L2 package-context bundle builder |
| `L4/verify.py` | **Modify** — add `matched_pattern` existence check against `kb.json` (mechanical, not LLM) |
| `L6/report.py` | **Modify** — render score + band + cited trail; **no L5 change** (still deferred) |
| `tests/test_l4_scorer.py`, `test_l4_retriever.py`, `test_l4_network_correlation.py` | **Create** |

**Do NOT modify:** `L5/score.py`, `L5/gates.py`, `L5/policy.yaml`, spine/L0/L1/L2
(this plan's L2 read is the *existing* `network_evidence.json` — no L2 change).

---

## 6. Interface contracts (so parallel implementation doesn't collide)

```python
# L4/knowledge/retriever.py
@dataclass
class KBMatch:
    kb_id: str
    title: str
    similarity: float
    mitre_techniques: list[str]

def retrieve(query_text: str, top_k: int = 3, min_sim: float = 0.3) -> list[KBMatch]: ...

# L4/network_correlation.py
def correlate(class_literals: Iterable[str], network_evidence: dict) -> list[str]: ...

# L4/reasoning_trail.py
@dataclass
class ReasoningTrail:
    steps: list[str]          # each cites a kb_id or "no KB citation"
    kb_ids_cited: list[str]

def build_trail(kept_claims: dict, kb_matches: list[KBMatch], provider: Provider) -> ReasoningTrail: ...

# L4/verify_verdict.py
@dataclass
class VerifierVerdict:
    status: Literal["confirmed", "weakened", "refuted"]
    counter_argument: str
    fabricated_citations: list[str]   # kb_ids the trail cited that don't actually exist/match

def verify_trail(trail: ReasoningTrail, source: str, kb_index, provider: Provider) -> VerifierVerdict: ...

# L4/scorer.py
@dataclass
class ClassScore:
    score: int                # 0-10
    band: Literal["grounded", "plausible", "hunch", "refuted"]
    rationale: str             # one line, derived, not another LLM call

def score_class(kept_claims, dropped_claims, kb_matches, verifier_result, suspicion) -> ClassScore: ...
```

Any implementer can build against these signatures without waiting on
another file to exist.

---

## 7. Explicitly out of scope

- **Call-stack code-to-network attribution.** Would need a new Frida hook
  capturing `getStackTrace()` at the network call site plus a jadx-location
  resolver for the resulting frames — real work, not a research question, and
  it changes L2 not L4. File as a separate plan if wanted.
- **L5 scoring integration.** Same deferral as the prior plan — held on
  `n_benign ≥ 213` (T24).
- **Retraining or re-curating the KB** beyond the ~500-doc seed from Phase 1
  of the prior plan.

---

## Verification

1. `pytest tests/test_l4_scorer.py tests/test_l4_retriever.py tests/test_l4_network_correlation.py -q`
2. `pytest tests/ -q` — no regressions
3. `$SENTINEL_PYTHON L4/deobfuscate.py <sha256> --src <jadx_src> --explain` on the SBI sample —
   the SMS-interception class should score in the 7–10 band (T1636.004 is a
   real, high-similarity KB entry for exactly this behaviour) and cite it.
4. A synthetic benign class with a superficially suspicious string but no KB
   match and a verifier that finds a benign explanation should land in the
   1–4 band, not 0 and not 7+.
