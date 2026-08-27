# L6 Recommendation Explainer — "What Should the Analyst Do Next?"

`L6/recommend.py` is the layer that reads a *finished* score (L0-L5 already
ran) and answers the question none of them do: concretely, what should a
human analyst do about this app? This doc covers four things: why it isn't
a trained ML model, exactly where every piece of guidance it cites actually
came from, how the mechanical verification works, and the decisions behind
the module boundaries.

---

## 1. Why not a trained ML model

The user's original question was direct: *"a reasoning ML model (or smth
else if you suggest)"*. A supervised classifier for this problem needs
labelled `(report → correct action)` pairs — thousands of real incidents
where a human analyst's actual decision is recorded as ground truth. That
dataset doesn't exist anywhere accessible, and manufacturing it credibly
would mean either fabricating labels (defeats the purpose) or running a real
incident-response program for months (out of scope for anything short of a
production deployment). Building a second, parallel ML pipeline to solve a
problem this project already solved once — reasoning over evidence,
grounded, verified before anything reaches an output — would also just
duplicate `L4`'s machinery for no real gain.

So this reuses **L4's exact shape**: an LLM proposes, in prose, grounded in
retrieved reference material; mechanical code disposes, dropping anything
not backed by something real. The one part that genuinely *is* deterministic
— not LLM judgment — is the **priority tier**, and it's built that way
deliberately:

```python
def priority_tier(score: ScoreResult) -> str:
    if score.unsupported:
        return "MONITOR"
    if score.band == "Critical":
        return "IMMEDIATE"
    if score.band == "High":
        return "URGENT_24H"
    if score.band == "Medium":
        return "STANDARD"
    return "MONITOR"
```

No network call, no model, a pure function over a number the pipeline
already computed. This mirrors `L4/scorer.py::score_class`'s own
determinism — the one place in that layer where an LLM's confidence is
never allowed to be the final word. Here it's the same principle applied to
urgency: a model can under-react to a Critical-band report (it happened in
testing — see §3), but the *tier* it gets sorted into can't be talked down.

## 2. Where every piece of grounding actually came from

`L6/knowledge/sop_kb.json` has 21 entries. Every one of them is real,
citable, and — this matters — **none of them were assumed correct without
checking a primary source first.**

### The bulk-fetch that didn't work, and what I did instead

The natural first move was to mirror `L4/knowledge/build_kb.py` exactly: it
pulls MITRE ATT&CK Mobile *Techniques* from a live fetch of the public
`mitre/cti` GitHub repo's `mobile-attack.json` STIX bundle. That same bundle
also contains MITRE's *Mitigation* objects (the "what to do about it" half
of ATT&CK) and the `relationship` objects linking them to techniques — so
pulling both in one pass looked straightforward.

It wasn't reachable. `raw.githubusercontent.com` accepted the TLS handshake
and then hung until timeout, empty-handed, on repeated attempts — the same
network-reliability pattern independently hit this session downloading the
AndroZoo index (a `ConnectionResetError` partway through a multi-GB transfer,
requiring a resume-capable retry loop to be added to that fetcher too).

The tempting shortcut at that point is: I already know roughly what MITRE's
mobile mitigations look like from training data, so just write them down.
**That was explicitly rejected.** This project's central design principle —
stated in `L4/verify.py`'s own docstring, illustrated by the real incident
where a candidate model confidently decoded a base64 string as `.../get.php`
when the true value was `gate.php` — is that a fluent, plausible-sounding
claim is exactly the failure mode that needs mechanical checking, not more
confidence. Hand-writing a plausible-but-unverified `M1234` ID into a
knowledge base whose entire purpose is to be a citable ground truth would be
precisely that failure, just moved one layer up.

So instead: **11 MITRE Mitigation entries were fetched individually**, one
HTTP request per technique page, from `attack.mitre.org` (which — unlike the
bulk GitHub raw-content host — was reachable). The technique IDs chosen were
the ones this project's own `L1/schema.py::CATEGORY_MITRE_MAP` already maps
its detection categories to (`T1636.004` SMS interception, `T1417.002`
overlay attacks, `T1453` accessibility abuse, `T1437` C2, `T1646`
exfiltration, `T1471` ransomware, `T1655`/`T1660` masquerading/phishing,
`T1626` privilege escalation, `T1414` clipboard hijack) — not an arbitrary
sample, the exact vocabulary a real finding from this pipeline would use.

Three of those ten fetches came back with an important negative result:
MITRE's own page for T1437 (Application Layer Protocol / C2), T1646
(Exfiltration Over C2 Channel), and T1471 (Data Encrypted for Impact) state
explicitly — verbatim, quoted in `build_sop_kb.py` — *"This type of attack
technique cannot be easily mitigated with preventive controls since it is
based on the abuse of system features."* No M-ID exists to cite for any of
them. That's not a gap in the fetch; it's real information, and it's kept in
the KB as its own entry rather than silently dropped, because it's exactly
the reason this KB needed non-MITRE sources at all: MITRE's mitigations are
prevention-oriented ("stop this from happening"), but a finding that already
shows live C2 traffic or ransomware behaviour needs a *response* action, not
a prevention one — which is what the CERT-In and NIST entries are for.

### CERT-In and RBI — re-derived, not re-researched

The 3 CERT-In entries (mandatory 6-hour incident reporting, 180-day log
retention, 6-hour response to CERT-In's own information requests) and 3 RBI
entries (the 2025 dynamic-authentication direction, mobile-app security /
fraud-detection duty, the SMS-OTP phase-out rationale) were **not**
re-fetched from scratch. `docs/PIPELINE_STUDY.md` §3.1-3.2 had already
independently researched and cited these facts with real source URLs before
this feature existed. Building `sop_kb.json`'s entries from that existing,
already-verified research — rather than re-doing the same web research a
second time — is reuse, not a shortcut; the citation URLs in each KB entry
trace back to the same sources that document already cites.

### NIST SP 800-61 — caught a wrong assumption by checking the primary source

The original plan for this feature (written before any KB content existed)
assumed NIST's incident-response lifecycle has **six** phases. It doesn't —
`nvlpubs.nist.gov`'s actual PDF was fetched directly, and it defines **four**:
Preparation; Detection and Analysis; Containment, Eradication, and Recovery
(one combined phase, not three separate ones); and Post-Incident Activity.
The plan's phase count was wrong, caught only because the primary source was
checked instead of trusted from memory — which is the entire discipline this
project asks of its own LLM layer, applied here to a human-written plan
before any of it, too.

### What's honestly not in there yet

SANS Institute's Incident Handler's Handbook was named as a fifth candidate
source in the original plan and was **never fetched or ingested**. Its
redistribution terms need checking before any of its text lands in this
repo — SANS reading-room material is typically free to read and cite but
not necessarily free to bulk-copy, and that distinction wasn't verified.
`sop_kb.json`'s `source_counts` has `"sans_handbook": 0` — an explicit zero,
not a missing key, specifically so a reader sees this was considered and
deferred, not simply forgotten.

## 3. How the mechanical verification actually works

`L6/recommend_verify.py` is `L4/verify.py`'s discipline applied to a new
domain: a proposed action survives only if code — not another model call —
confirms it against facts already on record.

| Check | What fails it |
|---|---|
| Action taxonomy | The action string isn't one of the seven fixed `Action` enum members (`L6/recommend_actions.py`) — the model can select, never invent |
| Finding citation | A cited finding `id` doesn't exist in this sample's own `findings[]` |
| KB citation | A cited SOP-KB entry `id` doesn't exist in the retrieved matches |
| IOC grounding | `block_ioc` names a value not present in this sample's own extracted IOC list |

An action with **zero** surviving citations after checking is dropped
entirely — not kept with an empty citation list. An unsupported
recommendation isn't a weaker recommendation; it isn't a recommendation.

On top of the per-action checks, two things are decided by code alone, never
put to the model as a question it could get wrong:

1. **A Critical-band (`IMMEDIATE` tier) report force-adds `escalate_cert_in`**
   if the model didn't already propose it. This was validated as a real,
   necessary guard, not a theoretical one — an earlier smoke test in this
   same session (on a different feature, the L2 navigator) showed a model
   correctly identifying an escalation-worthy situation and then talking
   itself out of the correct action under a specific framing. The same
   failure shape is plausible here: a model under-reacting to a report the
   *score itself* already says is severe. The override makes that
   structurally impossible regardless of the model's own read.
2. **An `unsupported` score collapses every recommendation to
   `insufficient_evidence`**, regardless of what the model proposed. This
   mirrors L5's own T24 discipline exactly: a score computed from too little
   benign data doesn't get to drive urgent action just because a number came
   out the other end. `L5/score.py`'s `unsupported` stamp already refuses to
   arm a scoring gate on this basis; this extends the same refusal to
   whatever happens *after* the score.

### The real end-to-end measurement

Rather than trust the design on paper, it was run for real against XBot's
already-scored sample (`1264c25d67d41f52102573d3c528bcddda42129df5052881f7e98b4a90f61f23`,
band Critical):

```
priority_tier=IMMEDIATE actions=2 dropped=0 cost=$0.037256 model=openai/gpt-4o-mini
summary: The analysis of the Android APK indicates it is a critical threat,
capable of intercepting SMS messages and potentially locking the victim's
device. It has been confirmed to have malicious capabilities, including a
connection to a command and control server for further malicious activities.
  [escalate_cert_in] The app has been confirmed as malicious and requires
    reporting to India's CERT-In within the mandated timeframe.
    citations: finding:F011
  [block_ioc] ioc=192.227.137.154 Blocking the command and control server
    will help prevent further malicious activity from this app.
    citations: finding:F009
```

The model proposed `escalate_cert_in` on its own — the deterministic
force-add wasn't even needed for this run, which is itself a useful data
point (the model got the urgent case right without the safety net; the net
exists for when it doesn't). It correctly named the real captured C2 IP
address for `block_ioc`, and that value was mechanically confirmed against
this sample's own extracted-IOC list before being kept, not trusted because
it looked plausible.

## 4. Module boundaries and the decisions behind them

- **`L6/recommend_actions.py` is its own file**, imported by both
  `recommend.py` (to prompt the model with the menu) and
  `recommend_verify.py` (to check the model's picks against it) — kept
  separate specifically so neither of those two modules has to import the
  other, avoiding a circular dependency for what is conceptually one small
  piece of shared vocabulary.
- **The SOP index is *not* retrieved through `L4/knowledge/retriever.py`'s
  `retrieve()`/`reload_index()` functions**, even though those functions
  exist and would appear to do exactly this. Those two share one
  process-wide global (`_INDEX`); calling `reload_index()` with the SOP
  KB's path would silently repoint L4's own malware-detection retrieval at
  this SOP KB for the rest of a long-lived process — a real hazard once this
  runs inside the same FastAPI server process as L4. `L6/recommend.py`
  instead instantiates `_KBIndex` directly (a class with no shared global
  state), reusing the same TF-IDF/cosine-similarity code with zero
  modifications, safely.
- **The output lives in its own artifact (`L6/artifacts/<sha>/
  recommendation.json`), not spine findings.** This mirrors L4's own
  precedent exactly: it contributes zero points, mints no evidence, and runs
  strictly after L5, so it structurally cannot feed back into the score even
  by accident. `spine.py`'s `"l6"` layer slot was already reserved in the
  `LAYERS` tuple and simply never used until this — `report.py`/`export.py`
  only ever *read* the spine, so this is the first thing to actually write
  into it, purely for `ran`/`skipped`/`failed` status tracking.
- **Never enters `L6/export.py`'s STIX/CSV/YARA/Sigma feeds.** That module's
  docstring states as a standing rule that nothing an LLM produced may enter
  a machine-consumed export. This module's output is LLM-proposed prose
  (even though every action is mechanically checked) and belongs only on
  human-read surfaces — the HTML report and the live web UI — where "AI-
  generated advisory, verify before acting" can be labelled inline. Verified
  live, not just documented: all four export formats were checked against a
  real recommended sample after the fact, zero references to recommendation
  content found in any of them.
- **The `--budget` default is `$0.25`, not a round number picked in
  advance.** L4's web-app default of `$0.50` was discovered mid-session to
  be too low for a stronger reasoning-tier model, silently failing to
  analyse a sample's most severe class. To not repeat that mistake here, the
  default was set *after* the real end-to-end measurement above ($0.037/run
  on the cheap tier) — about 7x headroom over an actual number, not a guess.

---

*Full technical plan (module list, file-by-file responsibilities, test
plan) lives in the session's plan file at the time this was built; the
architecture summary above is the durable reference. See also
`L6/recommend.py`, `L6/recommend_verify.py`, and
`L6/knowledge/build_sop_kb.py`'s own docstrings — each carries the same
level of detail as this document for the piece it covers.*
