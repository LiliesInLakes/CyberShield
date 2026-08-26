# Plan — L4 verified-decode promotion (the mechanical-verification → L5 path)

**Status:** proposed, awaiting review (2026-08-26)
**Author:** implementation session
**Scope:** option B from the L4→L5 diagnosis. Evidence path only. **No score change** is
promised by this plan — see §"What this does *not* do."

## Context

L4 emits two distinct kinds of output, and today **neither** reaches L5:

1. The LLM's *narrative* (`purpose`, `behaviours`, the 0–10 class score). This is opinion
   and **must** continue to contribute zero points — the §7 decided direction, and the
   reason `L5/score.py` states "there is no code path by which L4 output reaches this
   module."
2. Facts L4 **mechanically re-derived** in `L4/verify.py` — above all `decoded_strings`,
   where an obfuscated literal is re-decoded and kept *only* if the model's claim matches
   the machine's decode (the `gate.php` check, T26).

   🔴 **Accuracy correction (review 2026-08-26): "mechanical" is not one tier.** `verify.py`
   has two, and only one is ground-truth-grade:
   - **Sound (structural):** base64 (`validate=True`), base32, hex (`verify.py:128–157`). A
     match *is* proof the literal decodes to the claim.
   - **Heuristic (speculative):** single-byte XOR brute-force (255 keys) + ROT13, gated only
     on the result being indicator-shaped (`verify.py:158–176`). With 255 keys and a loose
     regex a short literal can be *made* to yield an indicator-shaped match — that confirms
     *a* mapping, not that the obfuscator meant it. Coincidence-prone.

     (`verify_api_calls` is similarly loose — trailing-component **substring** match,
     `verify.py:262` — which is why this plan promotes only `decoded_strings`, not
     `api_calls`.)

The "LLM contributes zero points" rule was aimed at (1). It has been applied to (2) as
well by omission: `deobfuscate.write_layer()` passes `findings=[]` ("L4 never mints
evidence", `deobfuscate.py:475`), and `signals.signals()` reads only `l0_signals +
yara_signals` (`signals.py:161`). So a mechanically-recovered, indicator-shaped decode —
exactly the class of fact `L0/promote.py` turns into a citable finding — is visible to no
one. L6 cannot cite it; A4 cannot price it.

This plan gives L4 the same promotion path L0 already has, for **only** its
mechanically-verified, indicator-shaped decodes.

## Why this does not violate "the LLM contributes zero points"

The promoted fact is one `verify.py` re-derived from the APK's own bytes. The LLM only
*surfaced the candidate literal*; the literal is in the code whether or not a model
mentioned it. Two ways to make that airtight, presented as a fork for review:

- **B1 (LLM-surfaced, verified):** promote what `verify.py` kept from the analyst's
  `decoded_strings` claims. Cheapest; already computed each L4 run. The model is a
  candidate-selector, the machine is the oracle.
- **B2 (deterministic sweep, no model):** promote from a deterministic pass over *all*
  string literals + dex strings (`_try_decode` already exists and is model-free), so the
  promoted evidence has **no LLM dependency at all**. Strictly more defensible against the
  zero-points principle, and it also catches decodes the LLM never surfaced; more work and
  a wider false-positive surface to measure.

**Recommendation: B1 now**, because `_try_decode` is already the oracle and the output set
is small and already audited per run; keep B2 as a tracked follow-up if benign measurement
shows the LLM is missing material decodes. Either way the *decision* to promote is the
machine's, never the model's.

## Design (B1)

### 1. `L4/promote.py` (new, mirrors `L0/promote.py` — stdlib-only, takes plain dicts)

`verified_indicator_findings(result: DeobfuscationResult) -> list[dict]`:

- Iterate `explanation.kept["decoded_strings"]` (already machine-verified `{literal:
  plaintext}` pairs).
- 🔴 **Promote only structurally-decoded pairs** (base64 / base32 / hex). A pair whose only
  decoder was the speculative XOR/ROT13 branch is **not** promoted — it is coincidence-prone
  (see §Context correction) and has no place minting a citable finding. This requires the
  `detail.encoder` tagging below (so promotion can filter on decoder class); until
  `_try_decode` reports which decoder fired, treat *all* speculative decodes as
  non-promotable by construction.
- Keep a pair **only if the plaintext is indicator-shaped** — reuse `verify._INDICATOR_RE`
  (URL / bare IPv4 / suspicious TLD). A decode that yields ordinary text is not evidence
  of anything and is dropped here, not promoted.
- **De-dup across classes** by `(literal, plaintext)` so the same recovered C2 in three
  classes is one finding, not three (mirrors L0's `_spine_key`).
- Emit spine finding dicts:
  - `engine`: `"l4_verified_decode"`
  - `category`: `"packing_obfuscation"` — the discriminating fact is **concealment**, not
    the destination. A plain URL in code is not suspicious; a URL a dropper hid behind
    base64 is. We do *not* claim `c2_communication` — L4 cannot know the endpoint is C2.
    (Open question O1 below.)
  - `severity`: `"medium"` (an obfuscated network indicator; not self-evidently critical)
  - `evidence`: `f"obfuscated indicator recovered: {literal!r} -> {plaintext}"`
  - `location`: the class location the decode came from
  - `mitre_techniques`: `["T1027"]` (Obfuscated Files or Information) — deferred to review
  - `observation`: **`"inferred"`**. Schema reserves `observed` for L2 runtime and
    `confirmed` for L6 analyst (`L1/schema.py:76`). A static re-decode proves *what the
    string is*, not that it *executed*, so `inferred` is schema-correct. The strength lives
    in `detail.verification` (O2 below).
  - `detail`: `{"l4_finding_type": "decoded_indicator", "encoder": <which decoder hit>,
    "literal": <literal>, "plaintext": <plaintext>, "verification": "mechanical_redecode",
    "spine_key": f"decoded_indicator:{plaintext}"}`

`_try_decode` currently returns the decoded *set* without saying which decoder fired; add a
thin variant (or return `{plaintext: encoder}`) so `detail.encoder` is populated. Small,
local to `verify.py`.

### 2. `L4/deobfuscate.py::write_layer` — stop passing `findings=[]`

Change the one call site to `findings=promote.verified_indicator_findings(result)`. Update
the `promote()` summary note: it is no longer true that "L4 never mints evidence" for
decoded indicators; keep the note that **class scores and narrative still contribute zero**.
`contributes_points` in the summary stays `0` (the number is A4's job, and T24 keeps it 0
regardless — see below).

### 3. `signals.py` — a new `l4_signals(doc)` branch

- One signal per distinct promoted decoded indicator on the sample, keyed
  `l4:decoded_indicator` (single stable key; A4 measures its base rate, exactly like
  `l0:brand_claim`). Carry the finding `id`s as `evidence_ids` so a contribution can cite
  them. `category="packing_obfuscation"`.
- Add `NS_L4 = "l4:"`; extend `signals()` to `[*l0_signals, *l4_signals, *yara_signals]`.
- Update `SIGNAL_SCHEMA` bump + the vocabulary test that pins the namespace (`tests/`), per
  the T15 discipline this module exists to enforce.

## What this does *not* do (read before quoting any number)

- **It does not change any score today.** `l4:decoded_indicator` is absent from the current
  weights file, so `L5/score.accumulate()` stamps it `unpriced` → weight **0**. And T24
  holds the whole policy `unsupported` until the benign corpus reaches B≥213. The
  deliverable of B is that the *evidence reaches the spine* (L6 can cite it, A4 can measure
  it) — not points.
- **It does not let L4 introduce a new IOC.** `verify_iocs` still forbids that. A promoted
  decode is a *finding about concealment*, not an entry in the IOC export blocklist. (If we
  later want recovered C2 in the IOC export, that is a separate, deliberately-gated change.)
- **It does not touch the class-score / narrative path.** Those stay zero-point, forever,
  by design.

## Verification (measure before claiming — §8)

1. **Freeze a baseline first.** Snapshot current L4 artifacts + a handful of spines under
   `tests/baseline/pre_l4promote/` so the change is a diff.
2. **Unit tests** for `L4/promote.py`: an indicator-shaped verified decode promotes; a
   plain-text verified decode does **not**; cross-class de-dup collapses to one finding;
   empty/absent `decoded_strings` promotes nothing.
3. 🔴 **Benign false-positive check (the T7/T28 gate).** Arming a new promotion path →
   assume a false positive → test the benign set immediately. F-Droid apps base64 config
   and analytics URLs routinely, so `l4:decoded_indicator` **will** fire on benign apps.
   Run L4 over a benign sample slice; record the firing rate. This is not a bug — it is the
   base rate A4 needs, and it is *why the weight will be near zero* if benign apps conceal
   URLs as often as malware. Report the rate; do not suppress it.
4. **Signal wiring test:** a spine carrying a promoted finding yields exactly one
   `l4:decoded_indicator` signal with the right `evidence_ids`; `signals.vocabulary()`
   counts it.
5. **Full pytest green**, including the bumped `SIGNAL_SCHEMA` vocabulary pin.
6. **A4 dry-run:** confirm `tools/rule_firing_report.py` picks up the new key and prices it
   (expected: near-zero / negative until B grows — record it, don't act on it).

## Companion (raised in review): manifest + resources.arsc grounding

This is a *reasoning-quality* enhancement, related but separable — it improves what the L4
analyst sees, and it feeds better candidate decodes into the promotion path above. Can ship
as a follow-up or fold in; recommend the **manifest half now**, arsc as a tracked follow-up.

**AndroidManifest (high value, low cost).** L0 already parses the full permission list
(`ingest.py:108`), but `deobfuscate.package_l0_context` forwards only brand/cert, so L4
never sees it. And **nothing extracts components** — exported `SMS_RECEIVED` receivers,
`AccessibilityService` / `NotificationListenerService`, device-admin and boot receivers, the
`Application` class. Those name a class's *role*, which obfuscated decompiled code hides,
and directly ground `behaviours` claims (sms_interception, accessibility_abuse). Add a
distilled manifest block to the L4 bundle: high-risk permissions + a component table
(type, exported, intent-filter actions, matched class). androguard already has all of it
(`apk.get_receivers/_services/_activities/_intent_filters`).

**resources.arsc (moderate value, needs care).** Nobody reads it today. Its *app-scoped*
string resources carry phishing lures ("Enter your OTP"), hardcoded URLs / phone numbers /
SMS templates — intent signal, and an extra indicator source (a C2 URL in `strings.xml`
becomes a deterministic, no-LLM promotion input — the B2 direction). Constraints, all real:
filter to the app package (skip framework strings), size-cap, and tolerate a **malformed
table** (`ResParserError` / B26 is a documented anti-analysis technique — fail soft to
"resources unavailable", never crash L4).

🔴 **Both are attacker-controlled text → prompt-injection surface.** Feed them as
*distilled, structured, explicitly-labelled-untrusted data*, never raw XML/arsc, and — the
key discipline — anything the model derives from them must stay mechanically checkable
against the parsed structures: a claimed permission verifies against the manifest, a URL
"in a string resource" is re-read from that resource. This is two new **checkable claim
classes** in `verify.py` (`declared_permissions`, `resource_strings`), the same shape as
`verify_api_calls`/`verify_iocs`, so a manifest/resource-grounded claim is held to the same
bar as everything else L4 keeps.

## Open questions for review

- **O1 — category.** `packing_obfuscation` (chosen: the concealment is the signal) vs a
  network-indicator category vs `other` letting the signal key carry all meaning. Category
  affects family-grouping/discount in `accumulate()` and L6 display, not the A4 weight
  (keyed on the signal string). Recommend `packing_obfuscation`.
- **O2 — observation value.** `inferred` (chosen, schema-correct) with
  `detail.verification="mechanical_redecode"`, vs proposing a new `mechanically_verified`
  observation tier. A new tier is a schema change with wider blast radius; recommend the
  detail flag now.
- **O3 — B1 vs B2** (LLM-surfaced-verified vs deterministic full sweep). Recommend B1 now,
  B2 as a tracked follow-up gated on the §Verification-3 benign rate.
- **O4 — manifest/resources scope** (the companion above): manifest-grounding now +
  arsc-strings as a follow-up (recommended) vs both now vs neither (keep this plan to the
  promotion path only). The manifest half is cheap and independently useful even if the
  promotion path waits.

## Out of scope (tracked separately)

- The two L2 code bugs (option A) — `honeypot.seed_contacts` binds no name/number;
  `l2_engine.process` globs all sandbox artifacts. Separate, safe fixes.
- Firing the SBI payload (option C) — needs live detonation approval + SUBMIT-handler RE.
- Any `ml.enabled` / gate-arming flip — blocked on T24 regardless, and out of this plan.
