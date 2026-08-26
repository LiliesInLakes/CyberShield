# APK Sentinel — Complete Methodology Guide

*Everything the project does, why it does it, and how to explain it — written so a
CS freshman can follow it, and structured so a judge scoring **Novelty /
Technical Feasibility / Model Explainability / Scalability / UI Design** can
find exactly what they're looking for.*

**One-line pitch:** APK Sentinel is an automated pipeline that takes a
suspicious Android app (APK file) and produces a **trustworthy, evidence-backed
verdict** — "this app is 92% likely to be a banking trojan impersonating SBI,
and here is the exact code and network traffic that proves it" — instead of a
black-box "malicious: yes/no."

---

## Part 0 — Foundations (skip if you know this already)

| Term | Meaning |
|---|---|
| **APK** | Android Package — the `.zip`-like file that contains an Android app: compiled code (`classes.dex`), the manifest (permissions, components), resources (images, strings), and a certificate. |
| **Malware** | Software built to cause harm — steal data, spy, defraud. **Banking malware** specifically targets financial credentials, OTPs, and UPI PINs. |
| **SHA-256** | A cryptographic *hash* — a fixed-length fingerprint of a file. Two different files (almost) never produce the same hash, so it's used as a unique ID for every sample. |
| **Static analysis** | Examining a file **without running it** — reading its code, strings, and structure. Safe, fast, but can be fooled by obfuscation. |
| **Dynamic analysis** | **Actually running** the app (in a safe, isolated sandbox) and watching what it does — what network requests it makes, what permissions it uses, what it reads/writes. Catches things static analysis can't see, but slower and riskier. |
| **Decompilation** | Turning compiled bytecode (`.dex`) back into readable Java-like source code. We use a tool called **jadx** for this. |
| **YARA rule** | A pattern-matching rule (like a very powerful regex) written to detect malicious code signatures — e.g. "if a class both reads SMS messages *and* sends them off-device, flag it." |
| **Sandbox / Emulator** | A fake, isolated Android phone (software-only, no real hardware) used to run malware safely. We use the **Android Emulator** (`sentinel30` AVD) with network access locked down. |
| **C2 (Command & Control)** | The remote server a piece of malware talks to for instructions or to send stolen data. Finding a C2 address is one of the most valuable things a scan can produce. |
| **IOC (Indicator of Compromise)** | A concrete, actionable artifact — a URL, IP, domain, phone number — that a bank's security team can block. |
| **LLM / GenAI** | A large language model (like GPT or Nemotron) — used here to *read and explain* obfuscated code, not to make the final verdict. |
| **Hallucination** | When an LLM confidently states something false. The single biggest risk of using AI in a security tool — **this project is built around solving it** (see Part 3, L4). |

---

## Part 1 — The Big Idea: the Evidence Spine

Every layer of the pipeline writes into **one shared record per sample**,
keyed by its **SHA-256 hash**. This record is called the **evidence spine**
(`artifacts/<sha256>/evidence.json`). Every later layer reads what came
before it and adds to the same file — nothing is recomputed, nothing is lost,
and every number in the final report can be traced back to the exact finding
that produced it.

**Why this matters (this is the core design philosophy of the whole
project):** a security verdict that a bank has to act on **must be
auditable**. "Our model says 87% malicious" is not good enough — an analyst
needs to know *which* signal fired, on *which* line of code, verified *how*.
The evidence spine is what makes that possible end-to-end.

### The seven layers at a glance

| Layer | Name | Does what | One-line status |
|---|---|---|---|
| **L0** | Triage | Hash, parse manifest, compare icon/name against a curated bank list | ✅ the project's core differentiator |
| **L1** | Static analysis | Decompile + YARA-scan the code | ✅ 37% malware-category detection (up from a measured 8% baseline) |
| **L2** | Dynamic analysis | Detonate the app live in an isolated emulator | ✅ demonstrated live — captures real C2 traffic |
| **L3** | ML classifier | A trained model gives a generic "how malware-like is this" probability | ✅ bounded ±10 points, never decides alone |
| **L4** | GenAI reasoning | An LLM explains obfuscated code — **every claim is mechanically re-checked** | ✅ the project's technical novelty centerpiece |
| **L5** | Hybrid scoring | Combines every signal above into one auditable 0–100 score | ✅ every point traces to evidence |
| **L6** | Output / UX | Web dashboard, HTML report (PDF via optional weasyprint), STIX/CSV/YARA/Sigma export | ✅ live control panel with real-time detonation feed |

---

## Part 2 — Layer-by-Layer Deep Dive

### L0 — Triage & Bank-Impersonation Detection *(the differentiator)*

**What it answers:** *"Is this app pretending to be a real Indian bank, UPI
app, or government service?"*

This is the single thing that separates this project from a generic
antivirus scanner (like VirusTotal or MobSF): those tools answer **"is this
app insecure?"**; L0 answers **"is this app impersonating your bank, and how
do we know?"** — which is the actual fraud vector that hurts users.

**How it works:**
1. Compute the **SHA-256** hash, parse the **AndroidManifest** (package name,
   permissions, app label).
2. Extract the app **icon** and compare it (via **perceptual hashing**,
   `pHash` — a technique for detecting visually similar images even if the
   file bytes differ) against a **curated whitelist of 40 real Indian banks
   and payment apps**.
3. Compare the app's claimed name/package against known legitimate identifiers
   — **whole-token matching only** (never fuzzy string matching — an earlier
   version used fuzzy matching and flagged a benign note-taking app as
   impersonating the Income Tax Department; exact/whole-word matching fixed
   that).
4. Parse the app's **signing certificate** and flag anomalies (self-signed is
   normal for Android and carries no weight alone; a mismatched signer
   identity does).

**Real example from this project:** the SBI ("State Bank of India") sample
`com.sbi.complaintregister` was correctly flagged as impersonating SBI —
0/8 India-targeted samples were caught before this layer existed; **8/8** are
caught now.

**Under the hood:**
- **Icon comparison uses perceptual hashing (`pHash`/`dHash`), not exact
  matching.** An exact-bytes comparison is trivially defeated by re-saving
  the icon at a different quality. Perceptual hashing instead computes a
  compact fingerprint of an image's *visual structure* (via the `imagehash`
  library), so two icons that *look* the same to a human still hash close
  together even if their file bytes differ completely — compared with a
  **Hamming distance** threshold (counting differing bits between two
  fingerprints). Icons are extracted across a **DPI ladder** (multiple
  resolution buckets), because Android's `get_app_icon()` defaults to
  `max_dpi=65536`, which frequently returns an **adaptive-icon binary XML**
  that a normal image library can't decode at all — silently failing icon
  extraction on roughly half of all APKs until this was fixed.
- **Certificates are parsed with `androguard` 4.x**, which returns
  `asn1crypto` certificate objects, not `cryptography` ones — so fields must
  be read as `cert.sha256` / `cert.issuer.native`, never
  `cert.public_bytes()` (the latter silently produces a different, wrong
  result under a bare `except` if you're not careful). Signer *anomalies*
  are what carry weight, not `self_signed` alone — every Android app,
  benign or not, is self-signed by construction, so that flag alone carries
  **zero discriminating weight** downstream.
- **Whole-token matching, never fuzzy string matching.** An earlier
  prototype used a fuzzy-match library and scored `"duckAssist"` (a benign
  note-taking app) at 0.706 similarity against `"iAssist"` (an Income Tax
  Department alias) — a false "critical impersonation" flag on a harmless
  app. Brand tokens are matched as whole words/phrases only.
- **The output structure matters for the rest of the pipeline:** L0 writes a
  `smoking_gun_inputs` dict (which specific hard evidence fired — brand
  claim, SMS-permission trifecta, cert anomaly) directly into the spine.
  **L5's scoring gates read this exact same dict, not a re-derived copy** —
  a deliberate single-source-of-truth choice so the "why did this gate fire"
  answer can never drift from what L0 actually found.

---

### L1 — Static Analysis

**What it answers:** *"What does the code itself say this app does, without
running it?"*

**Pipeline:** `.dex` (compiled bytecode) → **jadx** decompiles it into
readable Java source → both the raw `.dex` **and** the decompiled source are
scanned with **YARA rules**.

**Two scan scopes, and why both matter:**
- **Container scope** — scans the raw ZIP structure (catches file-format
  tricks).
- **Member scope** — scans decompiled class-by-class (catches behavioural
  patterns like "this exact class reads SMS *and* sends it off-device").

A rule needs *both* representations because a raw APK is compressed
(everything looks like noise), and a class-by-class scan is required so that
"SMS-read + SMS-send in the same class" actually means something — scanning
the whole app as one blob lets *unrelated* strings in *different* files
falsely satisfy a rule.

**15 YARA rule files**, covering banking-trojan primitives (SMS interception,
accessibility abuse, overlay/phishing screens, droppers, screen-lockers,
ransomware). Measured **37% malware-category detection** across a 649-sample
corpus (up from a measured **8%** baseline before the rule rewrite —
detection had been *believed* to be 50%, which is why everything in this
project is **measured, never assumed**).

**Also extracts indicators (IOCs):** URLs, IPs, phone numbers, UPI IDs,
emails — scanned from both the compiled code *and* the app's resource files
(a fix made this session: a malware sample's C2 address was hiding in a
compiled Android string resource, not the code, and was invisible until the
scanner was extended to look there too).

**Under the hood:**
- **A dex file is split into one byte-buffer per class** (`_dex_class_buffers`)
  before any rule runs. Scanning a whole dex as one blob was measured to
  make an unrelated expense-tracker app match *both* an OTP-stealer rule
  *and* a ransomware rule, purely because their strings happened to sit in
  the same multi-megabyte buffer — conjunction (`A and B`) only means
  something when it's scoped to one class.
- **Each class buffer is built from `invoke`/`const-string`/`new-instance`
  operand bytes, not just visible string literals.** A dex records an API
  call as an *operand reference* (e.g.
  `Landroid/telephony/SmsManager;->sendTextMessage`), while jadx's
  decompiled source renders the same call as
  `SmsManager.getDefault().sendTextMessage(...)`. Every YARA string in this
  project's rule set is written as a bare method/constant name specifically
  so it's a substring of **both** representations — a rule that only matched
  literal source text missed real API usage that a const-string-only scan
  can't see.
- **Two scan passes use two *different* rule sets, not the same rules
  twice**: the **container pass** keeps byte-level gates (e.g. "this buffer
  must start with the ZIP magic number") to catch archive-structure tricks;
  the **member pass** strips those same gates, because a `classes.dex` or a
  compressed resource member can never satisfy a "starts with ZIP magic"
  check — using the container rule set on decompressed members would make
  every content-based rule permanently unreachable.
- **IOC extraction is a denylist-vs-allowlist problem, not a plain regex.**
  A naive URL regex over a decompiled app returns hundreds of hits, nearly
  all framework/SDK boilerplate (`schemas.android.com`, Firebase, Gradle
  metadata). Every candidate host is checked against an **infrastructure
  denylist** (62 known SDK/framework domains) and a **plausible-TLD
  allowlist** before being kept; bare (schemeless) hostnames use an even
  *stricter* TLD list than URLs with an explicit `http://`, because a bare
  host is only proven to be a real endpoint by context — `.click` and `.id`
  had to be excluded from the bare-host list after they matched UI
  identifiers like `btn.click` and Firebase field names like
  `measurement.id`. Digit-only patterns (phone numbers) are **only**
  extracted from code buffers, never resource buffers — an early version
  extracted three "SMS-exfil phone numbers" from a banking trojan that
  turned out to be byte runs inside a stock Android Material-Design
  checkbox drawable, present in *every* app built against AndroidX.

---

### L2 — Dynamic Analysis (Live Detonation)

**What it answers:** *"What does this app actually do when it runs?"*

This is where the app is **actually executed** — inside a fully isolated
Android emulator (`sentinel30`, running on **KVM** hardware virtualization),
never on a real device.

**The safety model (this is worth understanding for the technical-feasibility
score):**
1. **Network isolation** — `iptables` rules inside the emulator drop *all*
   outbound traffic except to the host machine's proxy. Verified **fail-closed**:
   after applying the rules, the system pings a real external host and
   confirms it *fails* before proceeding — if isolation didn't actually take
   effect, the run aborts rather than silently detonating malware with real
   internet access.
2. **Traffic containment** — an intercepting proxy (**mitmproxy**) sits
   between the app and the network. Known bank/C2 endpoints get **fake, safe
   responses** to keep the malware "engaged" (so it keeps behaving instead of
   erroring out); everything else is **blocked by default**, not merely
   logged.
3. **Instrumentation** — **Frida** (a dynamic instrumentation toolkit) hooks
   into the running app's process to observe SMS interception, overlay
   screens, and clipboard access as they happen.

**The hard problem this layer solves:** most malware doesn't do anything
interesting until a human taps through its UI (enters a fake OTP, hits
submit). A blind, random UI-clicking bot (**DroidBot**) often gets stuck.
This project adds a second option: a **GenAI navigator** — an LLM that reads
the screen (via Android's UI-automation tree), decides the next tap/type
action, and fills in realistic **synthetic Indian test data** (fake names,
phone numbers, OTPs) to actually progress through login/registration flows.

**Real example:** detonating the **XBot** banking trojan live captured its
**C2 beacon** — an HTTP POST to `192.227.137.154/request.php` requesting a
second-stage payload — and the containment layer correctly **blocked** it
(logged as `blocked: true`) rather than letting it reach a live malicious
server.

**Under the hood:**
- **The exact isolation ruleset**: inside the emulator, a custom `iptables`
  chain (`st_OUTPUT`) is inserted at the top of `OUTPUT` — traffic to
  loopback and the emulator's own subnet (`10.0.2.0/24`) is allowed
  (`RETURN`), everything else is `DROP`ped. A separate NAT rule transparently
  redirects any port-80/443 traffic to the host proxy at `10.0.2.2:8080` (the
  emulator's fixed gateway address) — so the malware *thinks* it has normal
  internet, but every HTTP(S) request actually lands on our proxy.
- **Isolation is verified, not assumed, with a two-sided check**: (1) a
  **negative** check — `ping 8.8.8.8` from inside the guest **must fail**;
  if it succeeds, isolation silently didn't take effect and the run aborts
  before installing anything; (2) a **positive** check — a `nc` (netcat)
  connection to the proxy gateway **must succeed**; without this, a
  misconfigured "block everything" rule would look identical to correct
  isolation from the outside, while actually being useless (the sample can't
  reach the proxy either, so nothing gets captured).
- **Stopping mid-detonation is signal-driven, not a force-kill.** The
  sandbox spawns `mitmproxy` and the UI-driving process as their **own
  process groups**. A plain kill of the top-level orchestrator would leave
  those orphaned and the isolation rules permanently applied inside the
  guest. Instead, a stop request sends `SIGTERM`, which a handler converts
  into a Python exception (`DetonationStopped`) — caught by the *same*
  `try/except/finally` block that handles every other failure mode, so a
  manual stop gets the identical clean teardown (isolation restored, proxy
  and UI-driver processes killed) as a normal completion.
- **The GenAI navigator perceives the screen the same way a human would.**
  It reads Android's `uiautomator` XML dump (the accessibility tree every
  screen exposes), filters it down to only clickable/editable nodes (a raw
  dump can have hundreds of layout containers no action would ever target),
  and asks an LLM to pick exactly one next action from
  `{tap, type, swipe, back, wait, done}` given that list plus its last few
  actions. A **screen-hash** (a fingerprint of the visible nodes, ignoring
  parse-order and pixel-jitter) detects when the same screen keeps
  reappearing and switches strategy (e.g. prefers a scroll) to break the
  loop. All synthetic form data (names, phone numbers, OTPs) is generated
  locally by a seeded random generator — the model only ever names *which
  kind* of field it is (`"mobile_number"`, `"otp"`), never the literal value,
  so it can't leak or hallucinate real-looking PII into a form.

---

### L3 — Machine-Learned Classifier

**What it answers:** *"Based on thousands of measured samples, how
malware-like does this app's feature profile look, in general?"*

A **LightGBM** (gradient-boosted decision tree) model trained on a **corpus-derived
vocabulary** — every feature column is a token our *own* extraction pipeline
produces (permissions, API calls, intents), not borrowed from an external
dataset with different extraction assumptions (an earlier version trained on
a public dataset's precomputed columns and suffered from **train/serve
skew** — the columns our extractor produced at inference time didn't match
what the model was trained on).

**Deliberately bounded:** contributes **at most ±10 points** to the final
score and **can never alone push a verdict to "Critical."** This is a
philosophical choice, not a technical limitation — a generic ML prior is a
*hint*, not a verdict, because it can't explain *why* it thinks something is
malicious the way rule-based evidence can (see **Model Explainability**
below).

**Under the hood:**
- **Model:** `LGBMClassifier` (LightGBM — a gradient-boosted decision-tree
  library, chosen for training speed and native handling of sparse,
  high-dimensional binary feature vectors, which is exactly what a
  permission/API-token vocabulary looks like), with an **isotonic
  regression** calibrator layered on top. Raw classifier scores from tree
  ensembles are usually *not* well-calibrated probabilities (a raw 0.9
  doesn't reliably mean "90% likely"); isotonic regression is a
  non-parametric technique that learns a monotonic correction curve so the
  output can be read as an actual probability.
- **Train/test split is group-disjoint, not random**, grouped by malware
  family where known (else by source dataset). A random row-level split lets
  near-duplicate samples from the same family leak between train and test,
  producing a held-out AUROC that looks great but is measuring
  memorization, not generalization — this project's own metrics code flags
  any held-out AUROC **≥ 0.99** as a leakage warning rather than a win.
- **The feature vocabulary is corpus-derived**, not borrowed: columns are
  built by running this project's *own* extractor across the training
  corpus and keeping tokens within a **document-frequency band**
  (`min_df`–`max_df`) — dropping both singleton tokens (which just
  memorize one sample) and near-universal tokens (which carry no signal,
  the same T6/T23 base-rate lesson from L1's rule design).
- **The bounding formula** is a straight linear map clipped to a cap:
  `delta = clip(round(2 · cap · (prob − 0.5)), −cap, +cap)` with
  `cap = 10` — so `prob = 1.0` contributes exactly `+10`, `prob = 0.5`
  contributes `0`, and nothing this layer computes can, by construction,
  exceed that cap regardless of how extreme the raw probability is.

---

### L4 — GenAI Reasoning *(the technical novelty centerpiece)*

**What it answers:** *"What does this obfuscated class actually do, in plain
English — and can we trust that explanation?"*

Malware authors deliberately obfuscate code (renamed variables, encoded
strings) specifically to defeat static analysis. An LLM is very good at
reading through that — but LLMs also **hallucinate**: they state things
confidently that are false.

**The core innovation of this layer is a three-stage anti-hallucination
pipeline**, not just "ask an LLM to summarize the code":

1. **Analyst pass** — the LLM reads the decompiled class and proposes
   claims: decoded strings, renamed identifiers, API calls used, suspected
   indicators.
2. **Mechanical verification** — every checkable claim is independently
   re-derived by code, not trusted:
   - A claimed "decoded string" is re-decoded with `base64`/`hex`/etc. by
     Python and compared byte-for-byte against the model's claim. **(Measured
     example that justified this entire design:** one candidate model
     confidently decoded `aHR0cDovLzE5Mi4xNjguMS4xMDAvZ2F0ZS5waHA=` as
     `.../get.php`; the real answer is `gate.php`. One line of
     `base64.b64decode` catches this in a microsecond — no amount of
     "smarter prompting" would.)
   - A claimed "renamed identifier" must actually be **present in the code**
     as a real token.
   - A claimed **API call** must literally occur in the source.
   - A claimed **IOC** (URL/IP) is accepted **only if a deterministic layer
     (L0/L1) already extracted it independently** — the model is never
     allowed to introduce a brand-new indicator on its own authority.
   - A claim that fails its check is **dropped, not down-weighted** — and the
     drop is recorded, so a reader can see exactly what didn't survive.
3. **Adversarial verifier pass** — a *second*, independent LLM call actively
   tries to find a benign explanation for the surviving claims, and
   cross-checks every cited knowledge-base reference against the *actual*
   retrieved matches (a fabricated citation is caught mechanically, the same
   discipline as step 2).

**Result:** every sentence in an L4 explanation is labeled **verified** or
**unverified**, and a reader can see exactly which parts rest on the model's
word alone.

**Dual LLM provider setup** (a real engineering decision, not incidental):
a free-tier provider (**OpenRouter**, `nemotron`) is the default, with a
paid fallback provider (**aicredits.in**, OpenAI-compatible, offering
`gpt-4o-mini`) available when free-tier daily quotas are exhausted — both
share one retry/cost-tracking abstraction.

**By design, L4's narrative (the LLM's prose) contributes zero points to the
score directly.** What *does* contribute is gated and bounded: a class
reading only affects the final score if it is either **grounded** in a
retrieved knowledge-base match or scores at/above a measured confidence
threshold — and even then, capped, positive-only, and incapable of reaching
"Critical" by itself. This is the same anti-black-box discipline as L3,
applied to AI reasoning specifically.

**Under the hood:**
- **Three separate LLM calls per class, not one**: (1) the **analyst call**
  (`explain_class`) proposes claims from the raw source; (2) a
  **reasoning-trail builder** (`build_trail`) is shown *only* the claims
  that survived mechanical verification — never the raw source — and writes
  a short step-by-step trail; (3) an **adversarial verifier**
  (`verify_trail`) is shown the source, the trail, and the cited
  knowledge-base entries, and is explicitly instructed to look for a benign
  explanation. If step 2 or 3 fails for any reason, the pipeline degrades to
  "no score signal" rather than crashing — the mechanically-verified claims
  from step 1 still stand on their own.
- **The decode-verification cascade has two honesty tiers, and only one is
  promotable as ground truth.** `_try_decode` tries, in order: **structural
  decoders** — base64 (standard and URL-safe), base32, hex — each of which
  either succeeds or fails deterministically, so a match is *proof*; then
  **speculative decoders** — single-byte XOR brute-forced across all 255
  keys, and ROT13 — gated only on the output *looking* indicator-shaped
  (matching a URL/IP/suspicious-TLD regex). With 255 XOR keys tried against
  a short string, a coincidental indicator-shaped match is a real risk, so
  speculative-tier decodes are **never treated as strong enough to promote
  into a spine finding**, only structural ones are.
- **`verify_renamed` uses word-boundary regex matching, not substring
  matching, deliberately.** Obfuscators emit exactly the short names
  (`a`, `b`, `zz`) that a length filter would reject, but a plain substring
  search for `a` matches inside `class`, `java`, and nearly every other
  word in the file — so identifiers are checked with an actual regex word
  boundary (`(?<![A-Za-z0-9_$])a(?![A-Za-z0-9_$])`) instead.
- **`verify_api_calls` matches three progressively looser forms of the same
  API** — the full dotted name, the last-two-components form (e.g.
  `Log.i`, `SmsManager.sendTextMessage`), and the bare trailing name if it's
  3+ characters (to avoid single-letter false matches) — plus a special
  `new ClassName(` form for constructors (`<init>` never appears literally
  in decompiled source). This was tuned against a measured failure: the
  first version of this check dropped four *true* claims (`Log.i`, `Log.e`,
  `Log.d`, `Date.<init>`) on a class that plainly called all four, because
  it only checked the fully-qualified form.
- **`verify_iocs` is a hard allowlist gate, not a plausibility check** — a
  claimed IOC is kept **only if it string-matches something a deterministic
  layer (L0/L1) already extracted independently**; there is no code path
  where an LLM-only claim becomes an exported indicator, by design.
- **The final per-class 0–10 score is a deterministic function of four
  inputs** — kept claims, dropped claims, retrieved knowledge-base matches,
  and the adversarial verifier's `confirmed`/`weakened`/`refuted` status —
  with **no further LLM call**, so re-running `score_class` on the same four
  inputs always reproduces the same number. `refuted` forces score `0`
  regardless of anything else; a KB match with `confirmed` status maps
  linearly from similarity 0.3→score 5 up to 1.0→score 10, minus 1 point per
  dropped claim.
- **Cost is hard-capped by a `CostLedger`** that raises rather than merely
  logs once a run's dollar cap is reached — an infinite-loop bug becomes a
  refused call, not an unbounded bill. Two interchangeable LLM providers
  (a free-tier OpenRouter default, a paid `aicredits.in` fallback) share one
  retry/cost/JSON-parsing implementation via a generalized `base_url`
  parameter, so switching providers changes zero calling code.

---

### L5 — Hybrid Scoring *(the auditability engine)*

**What it answers:** *"Given everything above, what is the final score
0–100 — and can I see exactly why?"*

This is **not a machine-learned classifier making a black-box decision.**
It is an **auditable additive formula**:

1. **Accumulate** — every fired signal (a YARA rule, an L0 impersonation
   flag, a qualifying L4 finding) contributes a **weight**. Weights are not
   guessed — they are **measured**: computed from how often each signal
   fires on real malware vs. real benign apps (a **Jeffreys-smoothed log-odds
   ratio**, a statistically sound way to price a signal even with limited
   data), over a corpus of **3,090 malware and 604 benign** samples.
   Correlated signals from the same "family" (e.g. three SMS-related rules
   firing together) are **discounted geometrically** — three related facts
   should not count as three times the evidence.
2. **Map to 0–100** through a fitted sigmoid curve.
3. **Apply the L3 ML prior** (±10, capped).
4. **Apply the gated L4 AI contribution** (±10 max, positive-only, capped).
5. **Apply "smoking-gun" gates** — a small number of *specific, high-confidence
   evidence combinations* (e.g. bank impersonation **and** a credential-entry
   UI *together*) that act as a **floor**, not an override: they can only
   *raise* the score to at least a threshold, never lower it, and the
   additive score can still legitimately exceed the floor.

**Every single point in the final score names the exact signal and evidence
ID that produced it.** This is the direct answer to "how do you explain your
model's decision" — see the **Model Explainability** section below.

**Under the hood — the four stages, with real numbers from this project:**
1. **Accumulate.** Every fired signal's weight is looked up, then signals
   are grouped into named **families** (e.g. `sms`, `overlay`,
   `accessibility`, `dropper`, `cert`, `brand`, `hygiene`), ranked by
   `|weight|` descending within each family, and **geometrically discounted**
   by rank: the *n*-th-ranked signal in a family counts at `decay^n` of its
   raw weight. Measured family parameters actually in use:
   `sms: decay 0.5, cap ±4.0`; `cert: decay 0.7, cap ±3.0`;
   `brand: decay 1.0 (no discount), cap ±4.0`;
   `hygiene: decay 0.25, cap ±1.0` (weak/noisy signals like "uses a
   deprecated crypto algorithm" are discounted hard and capped low, so they
   can nudge but never dominate a score). Each family total is then clamped
   to its cap — three correlated SMS rules firing together is priced as
   *close to* one strong fact, not three independent ones.
2. **Map to 0–100** through a **sigmoid** with two fitted constants,
   currently `s0 = 0.1145` and `temperature = 2.2696`:
   `score = 100 / (1 + e^(-(S − s0) / T))`. A bare linear map has arbitrary
   endpoints; a *plain* sigmoid saturates so hard that nearly every real
   malware sample lands at 99 and the Low/Medium bands go unused — so both
   constants are **fit**, not guessed, against measured score distributions.
3. **Apply L3, then the gated L4 contribution** — each independently
   bounded (±10, capped, can't reach Critical alone), applied in sequence.
4. **Apply gates as a floor, never an override**: `final = max(score,
   floor)` only for gates that actually **fired** — a gate can raise a
   score to at least its floor, but the additive score can still legitimately
   sit *above* that floor, in which case the full underlying reason chain
   is preserved rather than being replaced by the gate's own summary.
- **Weights themselves are computed, not hand-tuned**: a **Jeffreys-smoothed
  log-odds ratio** over measured firing counts on malware vs. benign
  samples — Jeffreys smoothing is a standard statistical technique for
  safely computing odds ratios even when a count is small or zero (a naive
  log-odds computation blows up or is undefined at zero), which matters
  here because some signal categories still have limited benign coverage.
- **The L4 (AI) gate, precisely**: a class contributes only if it is
  **RAG-grounded** (its explanation cited a real, retrieved knowledge-base
  match) **or** its own 0–10 score is **≥ 5** (the configured floor); the
  contributed delta is `round((max_score / 10) · cap)` with `cap = 10`,
  always **non-negative** (AI reasoning can only raise suspicion, never
  lower it), and if adding it would push the score from below 85 to 85+
  without an explicit `may_reach_critical` override, it's clamped down to
  **84** instead — Critical requires deterministic evidence, never AI alone.

---

### L6 — Output & the Web Control Panel

**What it answers:** *"How does an analyst actually use this?"*

- A **live web dashboard** (FastAPI backend, no external JS framework — a
  single self-contained HTML file, so it works fully **air-gapped**, no
  internet dependency).
- Pick a target app, choose **which layers to run** (skip the emulator or the
  LLM freely for a faster static-only pass), watch a **live, real-time feed**
  of every pipeline stage as it happens (not a summary after the fact), and
  **stop a run mid-detonation** safely — the stop signal is caught and
  triggers the same clean network-isolation teardown a normal completion
  would, so nothing is left in a broken state.
- A **live phone-screen view** streams actual emulator screenshots while L2
  runs, alongside the GenAI navigator's action-by-action reasoning.
- **Exports**: a full HTML forensic report, plus **STIX 2.1**, **CSV**,
  **YARA**, and **Sigma** — the standard formats a real SOC (Security
  Operations Center) can immediately load into a blocklist or SIEM.

**Under the hood:**
- **The backend is FastAPI**, and a run's state is a small in-memory **job
  dict** keyed by job ID (`{stage, steps[], sha256, log[], stop_requested,
  done}`), polled by the frontend roughly once a second. There is
  deliberately no database or message queue — a single-analyst desktop tool
  doesn't need that complexity, and the job dict's simplicity is exactly
  what makes the live feed and stop control easy to reason about.
- **The live feed streams real subprocess output line-by-line**, not a
  captured blob shown after the process exits. A generic runner
  (`_stream_subprocess`) launches the L2 detonation or L4 reasoning process
  with its stdout piped, reads it one line at a time as it's produced, and
  appends each line to that job's log list immediately — which is also how
  L4's per-class progress (`"[2/8] analyzing X.java"`, `"[2/8] done → 5/10
  plausible"`) becomes visible live instead of only as a final summary.
- **Stopping a run reuses L2's own signal-handling mechanism**: the stop
  endpoint sends `SIGTERM` to the tracked subprocess, which (for a live
  detonation) is caught by the `DetonationStopped` handler described in the
  L2 section — so a UI-triggered stop and a normal completion both run
  through the *exact same* cleanup path.
- **19 API routes** cover the full lifecycle: catalogue (`/api/apks`),
  launching a run against a picked sample or an uploaded file
  (`/api/run`, `/api/analyze`), live polling (`/api/job/{id}`,
  `/api/job/{id}/log`, `/api/job/{id}/nav`), a live emulator frame
  (`/api/emulator/screenshot`), a stop control (`/api/job/{id}/stop`), a
  score-recompute endpoint for the AI-inclusion toggle (`/api/score/{sha}`),
  and the report/export/browse endpoints.
- **The dashboard is one self-contained HTML file with zero external
  requests** — no CDN, no external font, no build step — so it renders
  identically on a fully air-gapped analyst machine, matching the same
  operational assumption the rest of the pipeline is built around (a
  malware-analysis tool that phones home for its own UI is a bad look on
  its own threat model).

---

## Part 3 — Evaluation Criteria

### Novelty — 30

1. **Bank-impersonation-first, not insecurity-first.** Every mainstream
   scanner (MobSF, VirusTotal) answers "is this app risky." This project's
   L0 answers "is this app pretending to be *your* bank" — the actual fraud
   mechanism, verified against a curated Indian bank/UPI whitelist with
   whole-token matching (deliberately *not* fuzzy matching, after a measured
   false-positive incident).
2. **Mechanically-verified GenAI reasoning**, not "ask an LLM to summarize
   code and trust it." The three-stage verify → adversarial-check → gate
   pipeline in L4 is a direct, working answer to the industry-wide "LLMs
   hallucinate in security contexts" problem, justified by a real measured
   failure case (`gate.php` vs `get.php`).
3. **Auditable additive scoring instead of a black-box classifier.** Every
   point traces to a named signal and an evidence ID — a fundamentally
   different design from "the model says 87%."
4. **A live GenAI UI-navigator** that fills in synthetic Indian test data to
   actually trigger a banking trojan's payload past its login/OTP screen —
   most sandboxes give up where a human interaction is required.
5. **India-specific threat modeling** end-to-end: UPI virtual-payment-address
   extraction, Indian mobile number patterns, SBI/HDFC/ICICI-shaped fake OTP
   injection during detonation.

### Technical Feasibility — 30

- **It runs, today, not a mockup.** 412 automated tests passing. Live
  detonations captured real malicious network traffic (XBot's C2 beacon,
  blocked by the containment layer).
- **Real engineering safety discipline**, not just a demo script:
  fail-closed network isolation (verified by an actual failed ping, not
  assumed), a documented, safety-audited protocol for handling **live
  malware samples on disk** (password-protected archives, never bulk-extracted,
  detected by file magic bytes rather than file extension — measured on this
  project's own malware corpus, where 45% of archive members are
  extensionless).
- **Measured, not claimed, numbers throughout**: 37% detection rate (up from
  an honestly-reported 8% baseline), a 3,664-sample scored corpus, weights
  computed (not asserted) from 3,090 malware vs. 604 benign samples.
- **Graceful degradation everywhere**: if Ghidra (native-code analysis) is
  absent, or an LLM provider's free quota is exhausted, or the emulator isn't
  available, the pipeline reports an honest **"skipped: reason"** rather than
  crashing or silently reporting a clean result.

### Model Explainability — 20

This is the throughline of the *entire* architecture, not one feature:

- **L5's score is a sum of named, evidence-linked contributions** — every
  point printed with the signal name, its evidence ID, and its measured
  weight. Nothing is a black-box number.
- **L4's claims are labeled verified/unverified**, and every dropped claim is
  recorded *with its reason* (`literal_is_not_decodable`,
  `api_not_present_in_code`, `not_extracted_by_a_deterministic_layer`) — a
  reader sees exactly what didn't survive scrutiny, not just the polished
  final answer.
- **Confidence is reported separately from the score itself** — a low-coverage
  analysis (e.g. the emulator didn't run) is flagged as lower-confidence
  rather than silently blended into one number.
- **Gates show their legs**: a "smoking gun" gate lists which specific
  conditions fired and which didn't, with evidence IDs for each.
- **The final report literally states, in plain language, why AI did or
  did not contribute to this specific sample's score.**

### Scalability — 10

- **A resumable corpus runner** already processes hundreds of samples per
  run (705 samples in ~57 minutes, measured), safe to resume after
  interruption without reprocessing.
- **Disk-safety and cost-safety built in**: decompiled output is disposed of
  per-sample to prevent disk exhaustion; every LLM call runs under a hard
  **cost ledger** that refuses to exceed a budget rather than overspending
  silently.
- **Every layer is independently skippable** per sample (a static-only pass
  needs no emulator and completes in seconds), so throughput scales down
  gracefully for lightweight triage and up for full forensic depth.
- **Honest current limits** (worth stating plainly in a demo, not hiding):
  one emulator instance today, LLM calls are the throughput bottleneck at
  scale, and a small benign-sample denominator for some rule categories
  means some weights are provisional until the corpus grows further —
  the system *knows and reports* this rather than overclaiming confidence.

### UI Design — 10

- **A single-file, air-gapped, no-build-step web dashboard** — no external
  dependency, works with zero internet access, matching a security tool's
  own threat model (you don't want your malware-analysis console phoning
  home).
- **Live, real-time visibility**: a streaming log feed of every pipeline
  stage as it executes (not a spinner with no information), live emulator
  screenshots, and a live action-by-action feed of the GenAI navigator's
  reasoning.
- **A safe stop control** — mid-run cancellation that still performs full
  cleanup, not a force-kill that could leave the sandbox half-isolated.
- **Deliberate visual language**: severity communicated through color with
  actual urgency (Critical reads as alarming, not decorative), a clear
  layer-selection rail, an auditable per-signal score breakdown surfaced
  directly in the verdict view, and an exportable one-click report/IOC flow.

---

## Part 4 — Presentation Keyword Cheat-Sheet

Use these terms — they signal you understand the system, not just its output:

**Architecture:** evidence spine · seven-layer pipeline · SHA-256-keyed
record · auditable additive scoring · bounded contribution

**L0/L1:** bank-impersonation detection · perceptual hashing (pHash) ·
whole-token matching · YARA rule · container vs. member scope · static
analysis

**L2:** dynamic analysis / detonation · fail-closed network isolation ·
traffic containment · Frida instrumentation · GenAI UI-navigator · C2 beacon

**L3:** bounded ML prior · train/serve skew · corpus-derived vocabulary

**L4:** mechanically-verified reasoning · anti-hallucination pipeline ·
adversarial verifier · dropped vs. kept claims · zero-points-by-default AI

**L5:** Jeffreys-smoothed weights · smoking-gun gate · evidence-linked
contribution · confidence banding

**L6:** live streaming feed · air-gapped dashboard · STIX/CSV/YARA/Sigma
export

**Big picture, one sentence each, for the pitch:**
- *"Every score traces to named evidence — nothing is a black box."*
- *"We don't trust the AI's word — we mechanically re-derive every checkable
  claim it makes."*
- *"We measure everything — our detection rate, our weights, our
  confidence — we never assert a number we haven't verified."*
- *"This is the fraud a bank actually cares about: is this app pretending to
  be them."*
