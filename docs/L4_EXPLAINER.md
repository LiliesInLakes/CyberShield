# L4 Explainer — GenAI Reasoning, Verified

L4 (`L4/deobfuscate.py`) is the layer that reads decompiled Java for the classes L1 already
flagged and explains them. It is also the layer with the most machinery per unit of score
contributed — by design, it contributes **zero** points to the score (`L4/deobfuscate.py`'s
`promote()`: `"contributes_points": None`). This doc covers three things: why it's built the
way it is, how the two verification passes actually differ, and an honest read on the TF-IDF
retrieval choice.

---

## 1. The architecture, and why it's shaped this way

### The pipeline

Per class, `explain_class()` (`L4/deobfuscate.py:436`) runs up to three sequential LLM calls
plus one deterministic scoring step:

```
Analyst (LLM #1)  →  verify()  →  build_trail() (LLM #2)  →  verify_trail() (LLM #3)  →  score_class()
   extracts claims    mechanical    cited reasoning chain      adversarial re-check       pure function
   from source         checks       from KEPT claims only      of trail + source          of everything
```

1. **Analyst** — one LLM call, given the class source plus L0/L2/manifest/resource-string
   context and top-3 retrieved KB matches, returns a JSON claim set: `purpose`, `renamed`,
   `decoded_strings`, `api_calls`, `iocs`, `behaviours`, `suspicion`, `matched_pattern`,
   `confidence`.
2. **`verify()`** (`L4/verify.py`) — no LLM call. Every checkable claim kind is re-derived from
   the artifact and either kept or dropped.
3. **`build_trail()`** (`L4/reasoning_trail.py`) — second LLM call. Reads *only* the claims
   `verify()` kept, plus the KB matches — never raw source, never a dropped claim — and produces
   a step-by-step chain where each step either cites a `kb_id` or is marked "no KB citation".
4. **`verify_trail()`** (`L4/verify_verdict.py`) — third LLM call. Reads the actual source code
   plus the trail (not the raw claims) and is told to find a flaw. Independently, mechanically
   cross-checks every `kb_id` the trail cited against the KB index actually shown to it.
5. **`score_class()`** (`L4/scorer.py`) — pure function, no LLM, no network call. Turns the kept
   claims, dropped-claim count, KB similarity, and verifier status/confidence into a 0–10 score
   and a rationale string.

### Why three calls and not one

`decisions/plan_l4_agentic_verdicts.md` §1 states it directly: splitting narrows each call's
job. A single call asked to both extract facts from code *and* argue a defensible verdict in
the same breath tends to do both worse — the extraction gets contaminated by the desire to
sound persuasive, and the verdict gets contaminated by not having been checked against
anything yet. Separating "what does this code contain" (Analyst) from "does the surviving
evidence support a claim" (reasoning trail) from "can I break that claim" (verifier) means each
model call has one job, and the second and third calls only ever see what has already survived
scrutiny — the reasoning-trail agent literally cannot invent a new claim from source because it
is never shown the source (`L4/reasoning_trail.py:1-14`).

### Why "verify, don't trust" is the organizing principle

Every one of these modules' docstrings repeats a version of the same sentence: the LLM's job
is to produce explanation and candidate evidence, never a number, and nothing checkable is
accepted on the model's word. This isn't boilerplate caution — it's a direct response to a
measured failure, recorded as **T26** in `CLAUDE.md` and reproduced in `L4/verify.py`'s
docstring and `L4/provider.py`'s model-selection notes:

> Given the base64 literal `aHR0cDovLzE5Mi4xNjguMS4xMDAvZ2F0ZS5waHA=`, the candidate model
> `north-mini-code` (via OpenRouter) confidently asserted it decoded to
> `http://192.168.1.100/get.php`. The correct decoding is `gate.php`.

That's a single wrong character in a plausible-shaped URL, produced with full fluency and no
hedge. The reason this specific failure mode is dangerous — and the reason the fix isn't "add
more retrieval" — is in `L4/verify.py`'s docstring: **RAG grounds claims about the general
threat landscape, not the specific bytes of this sample.** A retrieval system stocked with
MITRE ATT&CK Mobile entries and YARA rule descriptions has no way to know what
`aHR0cDovLzE5Mi4xNjguMS4xMDAvZ2F0ZS5waHA=` actually decodes to — that's not a fact about threat
intelligence, it's a fact about *this one literal in this one class*, and the only way to check
it is to run `base64.b64decode` and compare. So the fix is orthogonal to RAG entirely: a
mechanical, code-level verifier (`L4/verify.py`) that re-derives every checkable claim from the
artifact itself. If the model's claimed decoding isn't in the set of things the literal
actually decodes to, the claim is dropped — not down-weighted, not flagged low-confidence,
dropped, with the reason recorded (`verify_decoded_strings`, `L4/verify.py:181`).

The same discipline extends past decoding: `renamed` claims require the original obfuscated
identifier to actually occur in the code (word-boundary, not substring — see §2); `api_calls`
require the API name to actually appear; `iocs` may never introduce an indicator the
deterministic layers (L1) didn't already extract — because an IOC export from this pipeline
feeds a blocklist, and an LLM-invented IOC in a blocklist is a false-positive machine. Even the
*second* LLM call in the chain gets this treatment: `verify_trail()` doesn't trust the trail's
self-reported citations, it looks them up (§2). The philosophy compounds — the trail-builder
LLM is told a citation to a KB entry it wasn't shown is "exactly the T26 failure shape one
layer up" (`L4/verify.py:307`), and the code enforces that by never letting a model's report of
its own citation correctness be the final word.

The one place the model's word is kept unmechanized is free-text narrative — `purpose`,
`behaviours`, `suspicion` — and those are carried explicitly labeled `unverified` in the output
(`ClassExplanation.unverified`), never folded into `kept`. A reader of the report can see
exactly which sentences rest on the model's word alone versus which were independently
re-derived.

### Why L4 doesn't score anything itself

`promote()`'s docstring is explicit about this being a deliberate boundary, not an omission:
whether the 0–10 class scores feed L5 at all is **L5's** decision (`L5/score.py::apply_l4`),
gated on the L5 side, currently held behind T24 (benign-corpus size for supported weights).
Duplicating that threshold check inside L4 would let the two drift — the same T15 trap
("a metric defined in prose and re-implemented in code will drift") that already bit this
project once on `MALWARE_CATEGORIES`. So L4 reports `"contributes_points": None` and points a
reader at `layers.l5.summary.ai_delta` for what actually happened.

### Two-tier model routing

`explain_class()` accepts a separate `verifier_provider`, and `L4/deobfuscate.py::main()`
wires the adversarial verifier (step 4) to a stronger model
(`AICREDITS_REASONING_MODEL = "anthropic/claude-haiku-4.5"`, `L4/provider.py:108`) while the
Analyst and trail-builder run on the default (cheaper) model. The rationale in the docstring:
generation-only steps (extracting claims from source, structuring an already-verified trail)
don't need the strongest model available; the one step that has to catch a subtle logical gap
under adversarial pressure, and runs exactly once per class rather than once per retry, is
worth spending more on.

---

## 2. Two different verifiers — mechanical vs adversarial

These are easy to conflate because both are called "verify" and both exist to stop the model
lying to the report. They check different things, at different points in the pipeline, and one
of them makes no LLM call at all.

### `L4/verify.py::verify()` — mechanical, zero LLM calls, checks claims about *this sample*

Runs immediately after the Analyst call, before anything else happens. Pure code — no network,
no model. For each claim kind:

- **`decoded_strings`** — `_try_decode()` (`L4/verify.py:113`) independently re-decodes every
  literal the model claimed to decode, and the claim is kept only if the model's answer is in
  the set of things the literal *actually* decodes to. The decoder tiers matter here: base64
  (standard and URL-safe, including double-encoded), base32, and hex are **sound** — a
  structural decode either succeeds validly or fails outright, so keeping its result is safe.
  Single-byte XOR and ROT13 are **speculative** — brute-forcing 255 XOR keys against arbitrary
  bytes will eventually produce *something* printable by chance, so those two are additionally
  gated on the output being indicator-shaped (`_INDICATOR_RE` — a URL, a domain-like token, or
  a bare IPv4) before they're even offered as a candidate match. Plain ASCII text run through
  ROT13 never produces a false "decoding" because the check requires the result to look like an
  IOC, not just look like text.
- **`renamed`** — `_occurs_as_identifier()` (`L4/verify.py:208`) requires the claimed-obfuscated
  original identifier to occur in the code *at a word boundary*. This can't be substring
  matching, because obfuscators emit exactly the single/double-letter names (`a`, `b`, `zz`)
  that would match as a substring of `class`, `java`, or nearly every token in the file. Nor
  can it use a length floor, for the same reason. Word boundaries are the only check that
  actually answers "is this identifier really here."
- **`api_calls`** — `_api_forms()` (`L4/verify.py:239`) does 3-tier matching: the full dotted
  name as reported, the last-two-components form (`Log.i`, `SmsManager.sendTextMessage`), and
  the bare trailing token if it's long enough to be unambiguous. This exists because the naive
  version — matching only the trailing component of `android.util.Log.i` — measurably dropped
  four true claims (`Log.i`, `Log.e`, `Log.d`, `Date.<init>`) on a class that plainly contained
  all four; a constructor claimed as `java.util.Date.<init>` never appears as `<init>` in
  decompiled source, it appears as `new Date(`.
- **`iocs`** — a hard allowlist: an IOC claim is kept only if it's already in L1's
  deterministically-extracted indicator list. The model may never *introduce* a new indicator,
  because an IOC export from this pipeline is loaded into a blocklist downstream.
- **`matched_pattern`** — the claimed KB id must be one of the ids actually retrieved and shown
  to the Analyst for this class; inventing a plausible-sounding pattern id is "exactly the T26
  failure shape one layer up."

Everything else (`purpose`, `behaviours`, `suspicion`) has no mechanical check and is carried
as `unverified`, never as fact.

Output is a `Verdict` with `kept`/`dropped`/`unverified` buckets. **No model is called during
this step.** `explain_class()` calls it as a plain function between the Analyst call and the
trail-builder call (`L4/deobfuscate.py:495`).

### `L4/verify_verdict.py::verify_trail()` — adversarial, one LLM call, checks the *argument*

This runs later, after `build_trail()` has already turned the mechanically-kept claims into a
cited reasoning chain. It is a genuinely different question from `verify()`'s: `verify()` asks
"did the model correctly read the bytes in front of it"; `verify_trail()` asks "even granting
every kept claim is true, does the argument built from them actually hold up, or is there a
benign explanation that fits at least as well?" The system prompt is explicit about not
defaulting to agreement: *"a trail that holds up under genuine scrutiny is rare, not the
default outcome."*

The verifier LLM call is given the source code (to check the trail isn't inventing something
absent), the trail's steps, and the KB entries the trail cited — and returns
`status: confirmed|weakened|refuted` plus a `counter_argument` and its own `confidence`.

But the citation check inside this step is **not** delegated to that LLM call.
`_mechanically_check_citations()` (`L4/verify_verdict.py:81`) independently looks up every
`kb_id` in `trail.kb_ids_cited` against `kb_index` — the same index the trail-builder was
actually shown — and anything that fails to resolve is recorded as a `fabricated_citations`
entry, full stop, regardless of what the LLM's adversarial pass concluded about `status`. The
override logic (`verify_trail()`, lines 158–176) then does something specific: it computes a
rank order `confirmed < weakened < refuted` and forces `status` to at least `weakened` (if some
citations are fabricated) or `refuted` (if *all* cited citations are fabricated) — but it can
only push the status **down** the rank, never up. If the LLM already said `refuted`, a clean
citation check doesn't rescue it to `confirmed`; if the LLM said `confirmed` but the citations
turn out fake, the mechanical check forces at least `weakened`. It also caps `confidence` at
`medium` if it was `high` and any fabrication was found, on the reasoning that "a trail that
cites sources that don't exist is not evidence of a careful reviewer's high confidence in
whatever remains."

This mirrors `verify.py`'s discipline exactly — one layer up, on a different kind of claim. The
LLM's self-report about whether its own citations are real is not trusted; the citations are
looked up.

### Summary of the difference

| | `L4/verify.py::verify()` | `L4/verify_verdict.py::verify_trail()` |
|---|---|---|
| LLM call? | None | One (adversarial), plus a mechanical override |
| Runs after | The Analyst call | `build_trail()` |
| Checks | Individual claims about *this sample's bytes* (decoded strings, renamed identifiers, API calls, IOCs, KB pattern id) | Whether the *argument* built from already-kept claims survives an adversarial re-read of the source, and whether every citation in that argument actually resolves |
| Failure mode it targets | T26 — a fluent, wrong decode/claim about a specific artifact | A trail that overstates certainty, cites a KB entry it wasn't shown, or has a benign alternative explanation |
| Output | kept / dropped / unverified buckets | `confirmed` / `weakened` / `refuted` + counter-argument + `fabricated_citations` |

### `score_class()` — deterministic, no LLM, no network

`L4/scorer.py::score_class()` is a pure function over: kept-claim count, dropped-claim count,
best KB similarity, verifier status, verifier confidence, and the Analyst's carried
`suspicion` hunch. The bands:

- **`status == "refuted"` → 0**, unconditionally, regardless of anything else. Dropped from the
  ranked list, kept only in `dropped_claims` for audit.
- **No KB match, no kept claims, but an unrefuted `suspicion.flag`** → 1–4, scaled by the
  *verifier's* confidence in its own counter-check (`_HUNCH_CONFIDENCE_SCORE`), never the
  Analyst's self-reported confidence — same anti-self-grading discipline as everywhere else in
  this pipeline.
- **No KB match, ≥1 mechanically-kept claim** → 3–5 (`min(5, 3 + kept_count - 1)`). A real,
  checkable fact with no threat-intel grounding behind it is worth more than a bare hunch, but
  still capped below "matches known malware."
- **KB match (similarity ≥ 0.3) and `status == "confirmed"`** → 5–10, linear on similarity
  (`_similarity_to_score`: 0.3 → 5.0, 1.0 → 10.0), minus 1 per dropped claim, floored at 5.
- **KB match but `status == "weakened"`** → capped at exactly the top of the ungrounded band:
  `min(5, 3 + kept_count)`. The comment in the code states the reasoning directly: *"a weakened
  grounded claim is not better than an ungrounded solid one."*

**The ceiling is deliberate, and it is not a bug.** Nothing not grounded in the retrieved
knowledge base can exceed 5/10, no matter how confident the adversarial verifier's `confirmed`
status was, because "confirmed" without a KB match means the *argument* holds together
internally — it doesn't mean an external threat-intelligence source corroborates it. This is
visible in the project's own artifacts. Running L4 against the XBot banking trojan sample
(`org.merry.core`, `L4/artifacts/1264c25d.../deobfuscation.json`) produced:

```
com/xbot/core/SMSHandler.java            -> 5/10  plausible   verifier: confirmed   kb_matches: []
com/xbot/core/locker/Lock.java           -> 5/10  plausible   verifier: none        kb_matches: []
com/xbot/core/activities/BrowserActivity.java -> 4/10 hunch   verifier: confirmed   kb_matches: []
```

`SMSHandler.java` is a real class in a real, confirmed-malicious banking trojan, with an
adversarial verifier that found no flaw — and it scores 5/10, capped, because retrieval found
no similar entry in `kb.json` at ≥0.3 cosine similarity. That's the system working as designed:
"confirmed, ungrounded" is deliberately priced as "plausible," not "known-bad." Two other
samples in the corpus (`L4/artifacts/b16176038152.../deobfuscation.json`,
`L4/artifacts/b4df57d563d3.../deobfuscation.json`) show the mirror case — a real KB match
(similarity 0.30–0.39) whose verifier came back `weakened` rather than `confirmed`, and those
also land at exactly 5/10, per the "same band as ungrounded-confirmed, one band down" rule.
Four different real classes converging on 5/10 through two different code paths (ungrounded-
confirmed and grounded-weakened) is exactly what a deliberately conservative ceiling looks
like from the outside — a coincidence of design, not of chance.

---

## 3. Is TF-IDF + cosine similarity the right retrieval choice?

`L4/knowledge/retriever.py` is the whole RAG layer: a `sklearn.FeatureUnion` of word-level
TF-IDF (`stop_words="english"`, `sublinear_tf=True`) and character 3–5-gram TF-IDF, cosine
similarity against a matrix built once from `L4/knowledge/kb.json`, cached process-wide in a
module-level `_KBIndex`. `kb.json` currently holds **216 entries** (122 MITRE ATT&CK Mobile
techniques, 59 YARA-rule-derived entries, 27 hand-curated India-banking patterns, 8 "emerging
2026" entries). No vector database, no embeddings API, no hosted model in the retrieval path
at all.

Direct answer: **at 216 entries, this is close to a genuine architectural fit, not just a
cost-saving shortcut — but it is a fit that expires, and the expiry point is identifiable, not
vague.**

**Where it's a real, durable advantage, not just cheap:**

- *Auditability.* TF-IDF is a fully inspectable bag-of-words statistic. Given a query and a KB
  entry, you can hand-compute why they matched — which tokens overlapped, what their document
  frequencies were — down to the exact float. An embedding-based match is a cosine similarity
  between two opaque vectors from a model whose internal representation nobody on this project
  can inspect. For a system whose entire ethos — stated four times over in this doc alone — is
  "verify mechanically, don't trust an opaque process," reaching for a black-box embedding
  model in the one component whose entire job is *deciding what counts as grounding* would be
  in tension with everything else L4 does. This part of the argument isn't about cost; it's
  that an ungrounded match from an opaque encoder would be exactly as unauditable as the T26
  failure the rest of the pipeline exists to prevent, just moved one step earlier.
- *No moving target.* A hosted embeddings API can silently change its underlying model version;
  a locally-pinned `sklearn` TF-IDF vectorizer, rebuilt deterministically from `kb.json` by
  `reload_index()`, cannot drift under you between two runs unless the KB file itself changes.
  Given `score_class()`'s explicit design goal — "a score is reproducible from its inputs...
  re-run `score_class` on the same four inputs and get the same number back" — an
  embedding provider that can silently re-version itself would quietly break that guarantee at
  the retrieval step, upstream of the part that actually claims reproducibility.
- *No network dependency, no per-call cost, no latency.* `retrieve()` is a synchronous, local,
  in-memory cosine similarity over an already-fitted matrix. It never fails for API-outage
  reasons, never adds a network round-trip to a call chain that already makes up to three LLM
  calls per class, and costs nothing beyond the one-time `fit_transform()` at process start.

**Where TF-IDF's known weakness actually bites, concretely:**

TF-IDF (even unioned with character n-grams) has no notion of meaning — it matches lexical
overlap, not synonymy. If a class's extracted query text (built from the location string plus
the first 40 string literals, `L4/deobfuscate.py:463`) says something like `"intercepts
incoming text messages and forwards them"` and the matching KB entry's description was written
using the phrase `"SMS interception"` with zero shared word stems, TF-IDF's cosine similarity
between them could sit near zero even though a real embedding model would place "text message"
and "SMS" close together in vector space and surface the match easily. This is a real gap, and
it's not hypothetical for this KB specifically: `_expand_identifiers()`
(`L4/knowledge/retriever.py:43`) exists precisely because API identifiers like
`sendTextMessage` survive obfuscation while renamed variable names don't (per the module
docstring, referencing T22), so the retriever splits camelCase/dotted tokens to expose their
word components — a hand-engineered patch for exactly one instance of the paraphrase problem
(code-identifier vocabulary vs. prose-description vocabulary), not a general solution to it.
Anywhere the query text and the KB entry's prose use genuinely different words for the same
concept and neither happens to contain the shared identifier tokens the expansion step
surfaces, TF-IDF will not find the match, and a class's `matched_pattern` will legitimately
come back null when a semantic retriever would have found grounding.

**Why the current scale mitigates this more than it would at 10x or 100x:** `kb.json`'s 216
entries were either scraped from a fixed schema (MITRE's own `name`/`description` fields, which
use fairly standard security-vocabulary phrasing) or hand-curated by this project's own team
(the India-banking and "emerging 2026" entries). That means the vocabulary on the KB side is
comparatively predictable and largely under this project's control — closer to "we wrote both
sides of the comparison" than "we're matching against an open-ended corpus of independently-
authored text." A hand-curated KB at this size can be, and plausibly was, written with an eye
toward the vocabulary the retrieval queries would actually contain (API names, MITRE technique
names, common malware-behaviour terms), which is exactly the condition under which lexical
matching quietly does most of the work semantic matching would otherwise be needed for. That
condition degrades as the KB grows past what one team can curate coherently and starts
absorbing text from more heterogeneous sources (community-submitted rules, scraped vendor
write-ups, translated regional threat reports) written in less predictable, more varied
phrasing — at which point paraphrase gaps like the SMS example above stop being an edge case
and start being routine.

**The honest verdict:** this is not a "pragmatic hack we'll obviously outgrow" and it's not a
"free lunch that scales forever" either — it's a choice whose two justifications (audit
discipline, and a hand-curated 216-entry KB with predictable vocabulary) both hold today and
both weaken as the KB grows, but at different rates. The audit/determinism argument doesn't go
away with scale — it would still be true to prefer an inspectable statistic over a black box at
50,000 entries. What does go away with scale is the lexical-predictability argument: once the
KB starts absorbing entries this team didn't author in a consistent voice, paraphrase misses
become routine rather than occasional, and no amount of `_expand_identifiers()`-style patching
scales to cover an open vocabulary. A reasonable order-of-magnitude estimate for where that
flips: this KB is fine well into the low thousands of entries (roughly 1,000–5,000) as long as
curation discipline holds and most entries are still written or reviewed by people who know
what the retrieval queries look like; past that — and certainly once entries start coming from
multiple uncoordinated sources, community contribution, or automated ingestion of raw vendor
reports — the paraphrase-miss rate would climb enough that migrating to (or at minimum
layering in) embeddings becomes the right call, most plausibly as a hybrid: keep TF-IDF's
audit trail for the "why did this match" explanation surfaced to a reader, and add embedding
similarity as a second signal specifically to catch the synonym misses TF-IDF structurally
cannot. At 216 entries today, that migration would be solving a problem this KB doesn't
actually have yet.

---

## Files referenced

- `L4/deobfuscate.py` — orchestration (`explain_class`, `deobfuscate`, `promote`)
- `L4/verify.py` — mechanical claim verification
- `L4/reasoning_trail.py` — cited-trail construction from kept claims
- `L4/verify_verdict.py` — adversarial trail verification + mechanical citation check
- `L4/scorer.py` — deterministic 0–10 scoring
- `L4/knowledge/retriever.py` — TF-IDF + cosine similarity retrieval
- `L4/knowledge/kb.json` — 216-entry knowledge base
- `L4/provider.py` — model selection notes, including the T26 measurement
- `decisions/plan_l4_agentic_verdicts.md` — the plan this pipeline implements
- `decisions/plan_l4_rag_verdicts.md` — the earlier plan it supersedes
- `CLAUDE.md` §6 (T26) — the trap this whole design responds to
