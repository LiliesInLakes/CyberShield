# APK Sentinel / CyberShield — Pipeline Explainer

Built for the **PSB Cybersecurity, Fraud & AI Hackathon 2026** (Bank of India ·
IIT Hyderabad · DFS, Ministry of Finance · IBA). Target threat: fraudulent
Android APKs impersonating Indian banks, UPI apps and government services.

This document explains what each of the seven layers actually does, why it is
built the way it is, and where it currently falls short. It is grounded in the
code and decision records as of **2026-08-16**. Every number quoted below was
either read directly from a file or produced by a command run during the
writing of this document — sources are named inline, and anything that could
not be verified is flagged as such rather than guessed.

> **How to read this document if you have five minutes:** every section has a
> quick technical paragraph, then a blockquote starting **"ELI5"** that
> explains the same thing in plain language. Skim the blockquotes first.

**Verified while writing this document:** `source_env.sh && $SENTINEL_PYTHON
-m pytest tests/ -q` → **285 passed** (2026-08-16, this session). `todo.md`
records 285/285 as of the same date, so this is corroborated, not just a
single run.

---

## The shape of the system

Seven layers, glued by one evidence record per sample:

```
L0 Ingest/Triage → L1 Static (YARA) → [Evidence Spine] → L2 Dynamic (sandbox)
                                              │
                          L3 ML prior ────────┼──── L4 GenAI reasoning
                                              ▼
                                        L5 Hybrid Scoring
                                              ▼
                                     L6 Output & Export
```

L0 and L1 write directly into the spine. L2 is wired to write into it but has
no live spine-producing run behind today's committed artifacts. L3 and L4 read
the spine and (for L3) write a bounded delta or (for L4) write explanation
only — never a score. L5 reads the whole spine and computes the number. L6
reads L5's output and everything upstream of it to produce a report or export.

The differentiator claimed for this project, and the one actually backed by
measurement, is **L0 bank-impersonation detection** — not "is this app
insecure" (that's MobSF's question) but "is this app pretending to be your
bank, and how do we know."

---

## L0 — Ingestion & Triage

**File:** `L0/ingest.py` (706 lines), `L0/impersonation.py` (210 lines),
`L0/certinfo.py` (244 lines).

L0 is the first and only layer that touches raw APK bytes without a
decompiler. It computes MD5/SHA-256 (`compute_hashes`), parses the manifest
via androguard (`harvest_manifest` — package name, app label, SDK bounds, and
a curated `HIGH_RISK_PERMISSIONS` set that flags things like `SEND_SMS`,
`BIND_ACCESSIBILITY_SERVICE`, `SYSTEM_ALERT_WINDOW`), extracts the launcher
icon and computes a perceptual hash (`extract_icon_phash`), parses the signing
certificate (`certinfo.extract_cert_info`), and runs the bank-impersonation
check (`impersonation.py`) against a hand-curated whitelist of 39+ Indian
banking/UPI/government entities (`bank_whitelist.json`). It also makes the
routing decision (jadx-only vs. jadx+Ghidra) that L1 obeys without
re-deriving.

The impersonation check (`match_label_brand`, `match_package`) works by
**whole-token and whole-phrase matching only** — never substring, never
fuzzy/edit-distance. Labels are camelCase-split and homoglyph-normalized
(`confusable_fold` maps Cyrillic lookalikes and digit substitutions like `0→o`,
`1→i`, `@→a` back to Latin) before matching against curated `brand_tokens`
per entity. Package names are checked for vendor-namespace squatting
(`package_namespace_squat`) and brand segments (`package_brand_segment`), but
only against **verified** package names (`package_verified: true`) — an
unverified vendor prefix cannot raise a finding.

Certificate analysis (`L0/certinfo.py`) classifies signer anomalies rather
than flagging self-signing itself (see T6 below), using androguard 4.x's
`asn1crypto`-backed cert objects correctly (T4).

### Why it's built this way

The whole-token design directly replaces `difflib.SequenceMatcher`
fuzzy-matching, which is documented as both too weak and too strong at once
(`L0/impersonation.py` docstring, and trap **T7** in `CLAUDE.md`): it scored
"SBI Quick Support" vs. "YONO SBI" at only 0.31 (missing a real clone) while
scoring "duckAssist" vs. the Income Tax alt-label "iAssist" at 0.706 — enough
to raise a **critical bank-impersonation finding on a benign note-taking
app**. Whole-token matching fixes both: SBI Quick Support tokenizes to
`{sbi, quick, support}` and hits `sbi`; duckAssist camel-splits to
`{duck, assist}` and cannot hit `iassist`.

Substring matching was tested and explicitly rejected too — over a 110-pair
inventory, "BOI Mobile" compacts to "boimobile", which contains "imobile"
(ICICI's brand token), a cross-brand false positive baked into the reference
data itself.

Vendor prefixes require `package_verified: true` because trap **T9**: 22 of
the original 39 whitelist package names returned HTTP 404 when checked — they
were fabricated identifiers, and trusting an unverified name would seed a
fake namespace into the detector.

The icon-hash dpi ladder exists because trap **T5**: androguard's
`get_app_icon()` defaults to `max_dpi=65536`, which picks the adaptive-icon
binary XML that PIL cannot decode — icon extraction silently failed on
roughly half of all modern APKs, including every India-targeted sample, until
the ladder was added.

Scope is a deliberate, load-bearing boundary: L0 matches **only
manifest-declared identity** (package name, app label) — it never inspects
dex or string content, which is why an app like PennyWise (an expense
tracker that legitimately mentions bank names inside its code) stays clean at
this layer. String-level bank references are L1's job.

> **ELI5:** L0 is the bouncer checking ID at the door. It reads the app's
> name tag, its "license plate" (package name), its photo (icon, hashed so
> near-duplicates match too), and who signed off on it — and asks one
> question: "are you claiming to be a bank you're not?" It only checks the
> label on the box, never opens it and reads the contents — that's the next
> layer's job.

### Current limitations

- Whitelist covers 39 curated entities; anything outside it is invisible to
  impersonation detection at this layer.
- `self_signed` carries zero weight alone (T6: it's a ~100% base rate — every
  Android APK observed locally, benign and malicious, is self-signed); only
  signer *anomalies* discriminate.
- `_label_similarity`/`_best_label_sim` in `L0/ingest.py` still use `difflib`
  and are flagged in `todo.md` as an open audit item (T7-adjacent) even
  though the primary impersonation path (`impersonation.py`) does not use
  fuzzy matching.
- Pre-A6 malware `L0/artifacts/` (stale, dated before the impersonation
  logic was fixed — trap T16) still exist on disk and read `verdict: unknown`
  on all 8 original India samples; anything derived from those specific
  on-disk files, rather than the spine, is stale.
- 3.8% of samples die at L0 on `ResParserError` per `CLAUDE.md` — androguard
  vs. malformed UTF-16 in resource tables, a documented anti-analysis
  technique (B26).

---

## L1 — Static Analysis

**Files:** `L1/l1.py` (167 lines, dispatcher), `L1/engines/yara_scan.py`
(757 lines), `L1/yara_templates/*.yar` (59 rules across multiple files as of
this session).

L1 dispatches to jadx decompilation (or Ghidra for native code, or a combo
track) based on L0's routing decision, then runs YARA across **three
distinct scopes**, each a different textual transformation of the same
sample:

1. **Container pass** (`scope = "apk"`) — the raw ZIP/APK bytes, for
   ZIP-structure rules only.
2. **Source pass** (`scope = "source"`) — jadx-decompiled `.java` files,
   scanned **per file**, never batched.
3. **Member pass** (`scope = "both"`) — decompressed dex members, scanned
   **per decompiled class buffer** (dex invoke/field operands plus
   `const-string` operands, not just string literals).

`merge_findings()` collapses a rule that fired in multiple scopes into one
finding with breadth recorded as `detail` fields, so the source and APK
passes cannot silently double-count.

### The dead-rule and over-conjunctive-rule history

This is one of the most measured parts of the project. As of the start of
this session's YARA work, A4 (`tools/rule_firing_report.py`) confirmed
**16 of the ruleset's rules had never fired** on 640 malware + 604 benign
spines. All 16 passed a self-match test (compile the rule alone against a
buffer of its own declared strings — trap **T25**): the conditions were
syntactically fine, so the fault was structural, not typo-level. The pattern,
per `decisions/decision_yara_improvement.md` and
`decisions/l1_l4_yara_improvements_2026.md`:

- **Over-conjunctive per-class requirements** (9 rules): conditions like `3
  of ($enc*) and 2 of ($file*) and 1 of ($note*) and 2 of ($ext*)` require
  tokens from encryption, file-walking, ransom-note UI text and file
  extensions all inside **one dex class** — real malware spreads those
  concerns across separate classes.
- **Family-specific IOC rules mixed with behaviour conditions** (3 rules,
  e.g. TaxiSpy, Zanubis): tied to one malware family's C2 IP or package name,
  and the family is absent from this corpus. These are legitimately expected
  to sit at 0 hits — that's what an IOC rule looks like when the family isn't
  present, not a defect.
- **Strings that live in `resources.arsc`, not dex** (3 rules, e.g.
  `Android_India_FakeBank_App`): bank names and KYC lure text are UI strings
  compiled into the Android resource table, invisible to a scanner that only
  reads dex/decompiled Java.
- **Native C APIs referenced from a dex-scope rule** (1 rule): `dlopen`,
  `dlsym`, and ELF magic numbers exist in `.so` files, never in dex
  bytecode.

This session's repair pass (`decisions/l1_l4_yara_improvements_2026.md`)
**relaxed the 16 rules in place** rather than splitting them into new
primitives, specifically so A4's signal-pricing history (keyed by rule name)
stays on the same row rather than becoming an unmeasured new signal. Every
repaired condition is now **at most two top-level token groups**, enforced by
a structural test
(`test_repaired_rules_use_at_most_two_token_groups`). Some literal tokens
were also removed for being unconditionally true inside an `N of` clause —
e.g. `/[0-9]{4,6}/` (matches any four digits, including a version code) and
`"DECRYPT"` (a substring of `Cipher.DECRYPT_MODE`, present in any class that
decrypts anything for a legitimate reason).

Measured on an 89-malware/99-benign probe (not the full corpus — see
Limitations): **3 of the 16 dead rules came back to life on malware**
(`Android_Suspicious_Command_Execution` 0→2/89,
`Android_Spyware_Generic_GPS_Surveillance` 0→1/89,
`Android_Spyware_SMS_Call_Log_Harvester` 0→1/89). Both ransomware rules are
**still dead** — their condition is no longer the blocker, but their target
strings (ransom-note text) genuinely live in `resources.arsc`, which the
scanner does not parse yet.

### The 2026 emerging-techniques rules

`L1/yara_templates/apk_emerging_techniques_2026.yar` adds 8 rules, one per
gap identified against the 2024–2026 threat landscape
(`docs/research/yara_new_techniques_2024_2026.md`): Automated Transfer
System / on-device fraud, VNC remote screen control, MQTT C2, session-cookie
theft, non-SMS OTP theft, USSD shortcode abuse, delayed/staged droppers, and
DNS-over-HTTPS C2. Each follows the same "exactly two token groups, one
capability + one context" idiom that made the BFSI primitives work, and each
is tested for T22 (bare method/class names matching both dex and jadx
representations), T23/T6 (no rule fires on a single high-base-rate primitive
alone), and T28 (never reaching the container pass). Five of the eight
(ATS, VNC, MQTT, USSD, DoH) fired on **zero** samples in the 188-sample probe
— expected, since the local corpus is 2020–2022 vintage and these are
2024–2026 techniques; a zero here is not evidence the rules are broken.

### Why it's built this way

Per-file/per-class scanning exists because of **T2**: batching 500 `.java`
files into one buffer for YARA let a conjunctive condition like `3 of
($wm*) and 2 of ($phish*)` be satisfied by strings scattered across
*unrelated* files, which caused a 100% false-positive rate on benign apps in
an earlier version. **T21** is the dex-scope version of the same lesson: a
dex is the whole app concatenated, so scanning it as one blob let an expense
tracker match an OTP-stealer rule and a ransomware rule simultaneously;
per-class buffers fix it. **T20**: rules gated on `uint32be(0) ==
0x504B0304` (ZIP magic) can never match a `classes.dex` — the container pass
and member pass need separate rulesets with container gates stripped.
**T28**: a behaviour rule that reaches the container (deflated ZIP) pass
proves nothing structurally, and one such rule was measured firing 82 times
on benign apps at container scope vs. 0 on malware — the container pass now
only takes `scope = "apk"` rules.

> **ELI5:** L1 decompiles the app back into readable source and pattern-matches
> it against a library of "known bad recipe" rules — but a real malware
> "recipe" is usually split across several files (read the SMS in one place,
> send it out in another), so a rule that demands every ingredient be in the
> *same* file almost never fires. This session's fix loosened those overly
> picky rules from requiring 4 ingredients in one bowl down to 2, without
> throwing out the recipe entirely — so the signal's track record carries
> forward instead of resetting to zero.

### Current limitations / MVP-only

- **18 of 51 rules were dead as of the last full-corpus A4 run**
  (`CLAUDE.md`); this session's repair reduces that on a 188-sample probe
  but **no fresh full-corpus A4 run has been executed against the repaired
  ruleset** — `decisions/l1_l4_yara_improvements_2026.md` §3.5 states this
  explicitly. The 37% (238/649) malware-category detection figure in
  `CLAUDE.md` predates this session's repairs and is not re-measured under
  them.
- Both ransomware rules remain dead pending `resources.arsc` string
  extraction — a scanner change, not a rule change, deliberately left undone
  this session.
- 40% of the corpus does not fully decompile within jadx's 180s timeout
  (`decompilation_partial`), which confounds "rule missed it" with "jadx
  never produced the source" — a distinction A4 has to separate before any
  weight computed from it means anything.
- No benign false-positive rate is claimed for the new/repaired rules at
  corpus scale — the 89/99 probe's 0-hit rows have a Jeffreys 95% upper
  bound near 3.7%, which is "no evidence of a high FP rate," not "evidence
  of a low one."

---

## The Evidence Spine

**File:** `spine.py` (407 lines), `decisions/decision-0001-evidence-spine.md`.

Every layer writes its own raw artifact (`L0/artifacts/<sha>/evidence.json`,
`L1/artifacts/<sha>/analysis.json`, …) *and* additionally folds a distilled
view of itself into one merged record at `artifacts/<sha256>/evidence.json`
— note this is a **new top-level `artifacts/`**, not under any layer's own
directory. `spine.update_layer()` is the single writer: it reads the current
spine, merges **only the calling layer's block and findings**, and replaces
the file atomically (`tempfile.mkstemp` + `os.replace`, plus an `fsync` of
the containing directory so the rename itself survives a crash). A
cooperative per-sample file lock (`_SpineLock`) covers the remaining race —
two processes reading the same spine and each writing back a version missing
the other's layer.

Findings carry two separate identities. `id` (`F001`, `F002`, …) is assigned
by a deterministic sort (`assign_ids`) over layer order, severity, category,
engine — it's what a report or L5 cites, but it **shifts** whenever a new
rule inserts a finding earlier in the sort order. `fingerprint` is a SHA-1
of a stable `finding_key` (detector identity: `layer|engine|category|
yara_rule-or-spine_key`, not the matched text) — it survives ruleset edits
and insertion, so two runs can be diffed on it. Layer status is a
`LayerStatus` enum (`NOT_ATTEMPTED`, `RUNNING`, `COMPLETE`, `PARTIAL`,
`FAILED`, `SKIPPED`) — the string `"pending"` was deliberately removed; it
used to carry no distinction between "never ran" and "in progress."
`analysis_gaps` is derived automatically: any of the three *evidence-gathering*
layers (L0, L1, L2 — L3-L6 consume rather than gather, so their absence isn't
a coverage gap) that is `NOT_ATTEMPTED`, `SKIPPED`, or `FAILED` contributes a
named gap string.

`MALWARE_CATEGORIES` is a frozen set of exactly the nine categories the
original benign-pass criterion was measured against — explicitly *not*
including `packing_obfuscation`/`evasion` (legitimately common in benign
apps) or `certificate_anomaly` (counted separately; a debug-signed training
app is anomalous without being malicious). Widening this set is documented as
silently redefining every recorded before/after number (this is trap **T15**
in spirit, applied concretely here).

### Why it's built this way

`decision-0001-evidence-spine.md` states the reason directly: L0's own
`run_l0` **destructively overwrites** `L0/artifacts/<sha>/evidence.json`,
resetting `l1`…`l6` to a placeholder on every run (**T10**) — so a shared
evidence record cannot live inside a layer's own artifact directory, because
the next L0 run would wipe it. A single spine at a new top-level path with
one atomic writer solves this. It also decouples downstream consumers from
any one layer's artifact path — confirmed in practice when L1's artifact
root moved to a different filesystem (`SENTINEL_L1_ARTIFACTS`, see T18/T31)
and nothing downstream needed to change, because L4/L5/L6 only ever read the
spine.

> **ELI5:** Imagine five different inspectors each writing their own report
> in their own notebook, but also copying a short summary onto one shared
> whiteboard. The whiteboard only ever gets erased and rewritten in the one
> section belonging to the inspector currently updating it — nobody else's
> notes vanish. Every finding gets a running number (which can shift if a
> new finding gets inserted earlier in the list) and a fingerprint (which
> never changes) so you can always tell "is this the same finding as last
> time" even after the running numbers move around.

### Current limitations

- 28 dedicated tests in `tests/test_spine.py` (per `CLAUDE.md`); the spine
  mechanics themselves are described as solid ("✅ works") but this document
  did not independently re-derive that figure beyond the aggregate 285-test
  pass count.
- The spine is only as fresh as the layers that wrote to it — a spine whose
  `l1` block is stamped with an old `ruleset_version` is not automatically
  known-stale to a casual reader; `CLAUDE.md` trap **T29** exists precisely
  because a scanner behaviour change that doesn't touch a `.yar` file can
  leave `ruleset_version` unchanged, letting a resumable corpus run silently
  skip samples that need re-scanning.

---

## L2 — Dynamic Analysis

**Files:** `L2/l2_engine.py` (480 lines), `L2/sandbox/orchestrator.py`
(1,072 lines), plus `honeypot.py`, `mitm_addon.py`, `safety.py`,
`proxy_setup.py`, `pcap_capture.py`, `install_ca.py`, and the Frida script
pack (`stealth_init.js`, `ssl_unpin.js`, `dynamic_hooks.js`, `auth_fill.js`,
`auth_bypass.js`, `accessibility_hooks.js`).

L2 boots an Android emulator (`sentinel30` AVD, API 30), installs a sample,
drives it with **DroidBot** (installed from GitHub since the PyPI release is
broken — unqualified imports, shadows the stdlib `types` module), attaches
**Frida** for runtime hooking, and routes network traffic through
**mitmproxy** with a fake-response "honeypot" layer (`mitm_addon.py`) that
serves plausible Indian banking/UPI API responses (login, OTP verify, MPIN,
balance, beneficiaries, mini-statement) so a trojan's exfiltration/C2 logic
has something realistic to talk to. `tcpdump` captures a parallel PCAP.

Runtime SMS OTP injection (`honeypot.py`'s `OTP_TEMPLATES`, SBI/HDFC/ICICI
formats) fires at T+10/20/30s via `threading.Timer` during detonation, to
give SMS-interception logic something to intercept. Permission auto-grant
(`grant_permissions()`) pre-grants the dangerous runtime permissions
(`READ_SMS`, `RECEIVE_SMS`, `SEND_SMS`, `READ_PHONE_STATE`,
`READ_CONTACTS`, `ACCESS_FINE_LOCATION`) and enables any accessibility
service the manifest declares, so the sandbox doesn't stall on a permission
dialog DroidBot can't reliably dismiss.

### Safety and isolation

`L2/sandbox/safety.py`'s `DetonationSafety.enforce_isolation()` is meant to
set up a fail-closed iptables chain (`st_OUTPUT`) that drops everything
except loopback and the emulator subnet, forcing traffic through mitmproxy.
As of `decisions/plan_l2_network_isolation.md` (2026-08-16, drafted this
session), **this method exists but is never called anywhere in the
codebase**, and even if called, has a wiring bug — it flushes a chain
(`-F st_OUTPUT`) that was never created (`-N`) and never hooked into the
built-in `OUTPUT` chain, so the DROP-all rule would sit inert. The plan to
fix and wire this is drafted but **not yet implemented as of this document**.
Practically: mitmproxy and PCAP capture run, but nothing today prevents a
detonated sample from reaching the real internet if it doesn't go through
the configured proxy. `CLAUDE.md`'s own status table still marks "network
isolation not enforced yet."

> **🔄 Correction (2026-08-24 / 2026-08-26):** the above is stale. Isolation
> **is** now wired and fail-closed-verified — `orchestrator.run()` calls
> `enforce_isolation()` (line 873) then `verify_isolation()` (line 877, which
> requires `ping 8.8.8.8` to FAIL and the proxy to be reachable before it
> proceeds). And as of 2026-08-26 `mitm_addon.py` no longer merely observes:
> every non-honeypot host is **blocked** (answered locally `200 {}`, tagged
> `blocked: true`, never forwarded), so the proxy-bypass gap this paragraph
> worried about is closed at the HTTP layer too (override
> `SENTINEL_MITM_BLOCK_UNKNOWN=0`). See `CLAUDE.md` §10.

HTTPS interception works despite `/system` being read-only on the current
AVD build (which blocks installing mitmproxy's CA into the system trust
store) via Frida's `ssl_unpin.js`, which bypasses certificate pinning at the
TrustManager/OkHttp3/Conscrypt/WebViewClient level instead.

### The real bug history from this session

This is a legitimate part of "how L2 currently works," documented in
`docs/l2_droidbot_reliability_log.md`, because the project is actively
mid-debugging it:

1. **`send()` payloads were silently discarded even on a fully successful
   Frida attach.** `_generate_dynamic_json` called `json.loads()` on every
   line of the `frida` CLI's stdout and swallowed the `JSONDecodeError` —
   but the CLI's non-interactive output for `send()` is a Python-repr-style
   line (`message: {'type': 'send', ...} data: None`), not JSON. Every hook
   that fired was thrown away. Fixed with a bracket/string-aware parser
   (`_parse_frida_cli_line`, using `ast.literal_eval`, deliberately never
   `eval` — parsing adversarial malware output).
2. **`frida-server` was not running on the device at all.** Process
   enumeration (`frida-ps`) goes over plain `adb` and doesn't need
   `frida-server`, so every prior "process liveness" check reported success
   while every real attach silently had nothing to attach to. `-wipe-data`
   (used for clean boots) wipes `/data/local/tmp`, and nothing redeployed
   `frida-server` after a fresh boot. Fixed with
   `L2Orchestrator._ensure_frida_server()`.
3. **`Java.perform` doesn't work through the raw Python `frida` bindings.**
   The `frida` CLI's REPL lazily resolves `Java`/`ObjC`/`Swift` via its own
   internal bridge-loading protocol, wired into the CLI's own agent wrapper
   script — not exposed by a plain `session.create_script()` call.
   Reimplementing that machinery (or installing a Node toolchain for
   `frida-compile`) was out of scope; the fix reverted to shelling out to
   the `frida` CLI itself, keeping only two independently-fixable defects:
   attach by **PID** (not package identifier — `frida -U <pkg>` fails on
   this frida-tools/Android 11 combination even when `frida-ps` lists the
   identifier), and the CLI-output parser from item 1.
4. **No hook sends an unconditional attach-confirmation signal.** Every
   `send()` in the hook scripts fires only when the target calls a hooked
   API — so a benign app, or a sample that never progresses past its splash
   screen, legitimately produces zero hook traffic even with a *perfect*
   attach, making it impossible to distinguish "attached fine, app did
   nothing suspicious" from "never attached at all." Fixed by appending one
   inert diagnostic ping to the combined runner script.
5. **A "confirmed" DroidBot splash-screen restart-loop on the SBI Quick
   Support sample turned out to no longer be reproducible** once the above
   Frida-capture fixes landed — most plausibly because the *old* retry-attach
   logic (a fresh `frida -U <pkg> -l script` subprocess per retry, up to 3×,
   each preceded by install/attach churn) was itself destabilizing the
   target process, producing exactly the "app keeps restarting" symptom that
   looked like a DroidBot navigation bug. Re-verified live: DroidBot
   genuinely reaches and operates the app's real `MainActivity` (a complaint
   form with an `EditText` and a `SUBMIT` button), not stuck on the splash
   screen. Zero DroidBot code changed to fix this.

**What is still open, live and unresolved as of this document:** on the SBI
Quick Support sample, DroidBot reaches and genuinely operates the app's one
real screen — but **the sample's actual malicious payload (SMS interception,
exfiltration) has never been observed triggering in a live L2 run.** Two live
runs on 2026-08-16 (documented in the reliability log) show `frida_hooks.jsonl`
containing only the diagnostic attach-confirmation pings, zero
`finding`-category hooks, and `network.total_requests` varying between 0 and
18 across otherwise-similar runs depending on exact tap/text-fill ordering.
This is a distinct, narrower problem than "can the sandbox reach the app" —
it needs sample-specific reverse engineering of what the SUBMIT handler
actually expects, not a general automation fix.

> **🔄 Update (2026-08-26):** the SBI-specific gap above still stands, but the
> broader claim "no malicious behaviour has ever been observed in a live L2
> run" no longer holds. Detonating the **XBot** trojan (`org.merry.core`) —
> which beacons from a `BOOT_COMPLETED` receiver, so no UI interaction is
> needed — produced the first non-zero behavioural capture: a C2 POST to
> `http://192.227.137.154/request.php` whose `data=<base64>` body decodes to
> `{"name":"bootScriptNet","action":"get_script"}`, recorded in
> `L2/sandbox/artifacts/org.merry.core/network_evidence.json`. Remaining L2
> gaps (incoming-SMS hook, containment-vs-observation, the two code bugs) are
> listed in `CLAUDE.md` §10 and the 2026-08-26 reliability-log entry.

### Why it's built this way

DroidBot was chosen over alternatives after dedicated research
(`decisions/decision_dynamic_analysis_automation.md`); a GenAI-vision-driven
navigator was considered and explicitly rejected as unnecessary
(`decision_dynamic_analysis_automation.md`: "decision: skip, DroidBot +
rule-based scripts sufficient"). The stealth extensions (sensor jitter,
battery spoof, package hiding from Magisk/Xposed detection, WiFi spoof)
exist because banking trojans routinely detect emulators and behave
differently under analysis — a plain stock AVD would simply not show its
real behaviour. Attach-by-PID over attach-by-identifier and the CLI-shellout
architecture are not the originally intended design; they are what survived
contact with a real Android 11 emulator and this frida-tools version, kept
because they are the version that demonstrably works, verified live.

> **ELI5:** L2 is a locked padded room where you actually run the app and
> watch what it does, instead of just reading its ingredients list. A robot
> (DroidBot) taps around the screen for it, a wiretap (Frida) listens to
> what functions get called inside the app, and a fake phone company
> (mitmproxy) answers any network requests with realistic-looking fake bank
> data to see if the app tries to steal it. This session found and fixed
> three separate reasons the wiretap wasn't actually recording anything even
> though every earlier status light said it was working — turns out the
> wiretap device itself wasn't plugged in. The room's "no calling outside
> the building" lock (network isolation) is designed but not actually
> engaged yet, so nothing dangerous should be run through it unsupervised.

### Current limitations / MVP-only

> **🔄 The first two bullets are superseded (2026-08-24 / 2026-08-26):**
> isolation is now enforced+verified and mitm blocks unknown egress; and a
> live XBot detonation has produced a real C2-beacon finding. See the two
> correction blocks above and `CLAUDE.md` §10.

- ~~**Network isolation is designed but not enforced**~~ — now wired
  (`enforce_isolation()` at `orchestrator.py:873`, `verify_isolation()` fail-closed
  at 877) and `mitm_addon.py` blocks non-honeypot egress by default (2026-08-26).
- ~~**No live detonation … has produced a confirmed malicious-behaviour
  finding**~~ — XBot's C2 beacon was captured on 2026-08-26 (first non-zero
  behavioural capture). Note the residual: *India-targeted* SBI-style samples
  still gate their payload behind a form submit that automation hasn't driven.
- Detonation of any sample is user-approved per `CLAUDE.md`; the go/no-go
  checkpoint for the India-12 demo set has not been given.
- `dynamic.json` generation, PCAP pull integration, and the L2 spine
  producer were planned in `decisions/plan_l2_phase4.md` and are marked done
  in `todo.md`, but the spine entries observed for at least one sample in
  this repository's `artifacts/` directory point to a `/tmp/...` synthetic
  integration-test artifact path (from the Phase 4f synthetic-artifact test)
  rather than a genuine live-detonation run — see the worked example at the
  end of this document for the specific case checked.
- `/system` is read-only on the current AVD build, blocking system CA
  install and `/etc/hosts` DNS redirection; both are worked around rather
  than fixed (Frida SSL unpinning covers HTTPS; DNS redirection is deferred).

---

## L3 — ML Classifier

**Files:** `L3/train.py` (273 lines), `L3/fetch_lamda.py` (52 lines).

L3 trains a classifier on **LAMDA** (HuggingFace `IQSeC-Lab/LAMDA`, MIT
license, ungated — chosen because AndroZoo/Drebin/MalRadar are unobtainable
on this project's timeline, per `CLAUDE.md` §7). LAMDA is roughly 1,008,381 ×
4,561 in its dense form — too large to hold densely alongside a corpus run on
a 14 GB machine, so `train.py` converts each year's slice to a sparse matrix
and drops the dense frame immediately.

The split is **temporal, not random**: the docstring is explicit that a
random split over a 2013–2025 corpus leaks the future into the past, so
training stops at `--train-until` and every later year is scored as a
held-out future, producing a year-by-year AUROC table that is the intended
"drift exhibit" rather than a bug to hide. The classifier is wrapped in
isotonic regression fitted on a held-out slice of the training years, never
on future years, because L5 maps the predicted probability to a bounded
point delta, so a miscalibrated 0.9 costs real score points, not just a
wrong label.

### Why it's built this way

LAMDA is measured at roughly 99.6% non-banking, so a confident L3 output
means only "this resembles Android malware in general" — never "this is a
banking trojan." The output is therefore capped to **±10 points** on the
0–100 L5 score (`L5/score.py::apply_ml`, `cap = int(cfg.get("max_delta",
10))`), and structurally **cannot push the score into the Critical band by
itself**: if applying the delta would cross the 85-point boundary without an
explicit `may_reach_critical` policy flag, the score is clamped to 84
(`ml_clamp` binding reason). This encodes the project's stated claim
discipline (`CLAUDE.md` §7): "we encode India-specific detection logic ...
not 'we detect Indian banking trojans in the wild'" — a generic prior is not
allowed to make a banking-specific claim.

> **ELI5:** L3 is a machine-learning "does this generally smell like Android
> malware" check, trained on roughly a million samples of mostly
> non-banking-specific malware. Because it was never taught banking fraud
> specifically, it's only allowed to nudge the final score up or down by a
> small amount (±10 out of 100) and is physically prevented from being the
> sole reason a sample gets flagged as the worst category — it can suggest,
> never convict.

### Current limitations / MVP-only

- **No model is trained yet.** `L3/model/` is empty and `l3` is
  `not_attempted` on every spine, per `CLAUDE.md` §7 item 7. The pipeline is
  verified end to end via a 2020-only proof run: **AUROC 0.9965 in-year,
  0.8978 on 2024** (the drift exhibit) — but that proof run is not the same
  thing as a production-trained model.
- The full training run needs ~6 GB and has not been executed in this
  repository as of this document.

---

## L4 — GenAI Reasoning

**Files:** `L4/deobfuscate.py` (454 lines), `L4/scorer.py` (195 lines),
`L4/verify.py` (266 lines), `L4/verify_verdict.py` (182 lines),
`L4/reasoning_trail.py` (157 lines), `L4/knowledge/` (retriever + `kb.json`,
216 entries as of this session: 122 MITRE, 59 YARA-derived, 27 curated, 8
new "emerging_2026").

L4 runs a **3-agent pipeline** over the small number of classes L1 already
flagged as interesting (its `location` fields) — 6 to 8 classes per APK, not
a hierarchical summary of the whole decompiled app, because summarizing
everything costs 30–40 minutes of model time and mostly narrates framework
code no analyst would read:

1. **Analyst** extracts claims from one class's source: purpose, renamed
   identifiers, decoded strings, API calls, IOCs, a first-pass verdict, and
   a free-text `suspicion` hunch that is explicitly never promoted to a
   mechanical fact.
2. **Mechanical verify** (`L4/verify.py`) — every checkable claim is
   re-checked deterministically: decoded strings are re-decoded, renamed
   identifiers must occur verbatim in the source, claimed API calls must
   actually appear, and `matched_pattern` must resolve to a real KB id.
   Nothing here is graded by asking the model whether it thinks it's right.
3. **Reasoning-trail agent** builds a cited evidence chain from only the
   *kept* (post-verification) claims against the retrieved KB matches
   (TF-IDF/cosine similarity, `min_sim=0.15–0.3` depending on caller).
4. **Verifier agent** adversarially checks the trail against the actual
   source code, explicitly instructed not to be agreeable ("a trail that
   holds up under genuine scrutiny is rare, not the default outcome"). Every
   `kb_id` the trail cites is cross-referenced mechanically against the KB
   index in `L4/verify_verdict.py`, not by asking the model to self-grade —
   **any citation that fails to resolve is a fabricated citation, full stop,
   and mechanically overrides the model's own `status` verdict** toward
   `weakened`/`refuted` regardless of what the adversarial pass itself
   concluded.
5. **Scorer** (`L4/scorer.py`) is a pure deterministic function — no network
   call — that turns kept claims + KB matches + verifier status + the
   analyst's suspicion hunch into a 0–10 class score and a
   `grounded/plausible/hunch/refuted` band. A `refuted` verdict scores 0 and
   is dropped from the ranked report list.

### Why it's built this way

**T26** is the load-bearing trap here: in model selection testing, an LLM
confidently mis-decoded a base64 string (`aHR0cDovLzE5Mi4xNjguMS4xMDAvZ2F0ZS5waHA=`)
as `.../get.php` when it is actually `gate.php` — a one-character error a
human reviewer would not catch by reading the LLM's prose. Retrieval grounds
claims about the *threat landscape* (what does T1636.004 generally look
like), never claims about *this specific sample's bytes* — anything a
decoder, parser, or hash can settle mechanically is settled that way before
it reaches a report.

**L4 contributes zero points to the score, by design, not by omission** —
`L5/score.py`'s module docstring states there is no code path by which L4
output reaches L5. This was a decided architectural choice
(`CLAUDE.md` §7): the original proposal's `0.45·rules + 0.30·ml + 0.25·llm`
blend was replaced with an auditable additive scheme where smoking-gun gates
are the primary mechanism. A planned `GROUNDED → L5 ±5 pts` edge exists in
`decisions/plan_l4_agentic_verdicts.md` but is explicitly **not wired**,
deferred behind the same `n_benign ≥ 213` support requirement that blocks L5
gate-arming (T24).

> **ELI5:** L4 is three AI reviewers checking each other's work instead of
> one AI grading its own homework. Reviewer 1 reads the suspicious code and
> makes claims about what it does. A dumb, fast fact-checker (not an AI —
> just code) throws out any claim that isn't literally true when checked
> against the actual bytes. Reviewer 2 builds an argument citing real threat
> intelligence for the claims that survived. Reviewer 3's whole job is to
> try to find a hole in Reviewer 2's argument — and if Reviewer 2 cited a
> source that doesn't actually exist, that's caught mechanically, not by
> asking Reviewer 3 nicely. None of this changes the final risk score by
> itself — it produces the human-readable explanation, but the number comes
> from elsewhere.

### Current limitations / MVP-only

- **L4 score never reaches L5** — by design, and the ±5 point edge from the
  agentic-verdicts plan is explicitly deferred, not merely unbuilt.
- The full 3-agent pipeline is validated on synthetic/fake-provider tests;
  `todo.md` still lists "Live-sample smoke test against the SBI Quick
  Support sample" as an open item as of the last update, separate from the
  standalone verified real-sample run described in the worked example below
  (that run used the earlier, simpler analyst+verify pipeline, not
  necessarily every component of the newer 3-agent plan).
- Network correlation (`L4/network_correlation.py`) is **string/host content
  matching only** — "this class contains a string that also appears in this
  sample's captured network traffic" — not proof of causation, and the
  module's own docstring says every caller must state that explicitly.
  True call-stack-level code-to-network attribution is out of scope,
  flagged as a separate future plan.
- Model cost is $0.00/call on the OpenRouter free tier per `CLAUDE.md`,
  which is an availability/rate constraint as much as a cost one.

---

## L5 — Hybrid Scoring

**Files:** `L5/l5.py` (164 lines), `L5/score.py` (348 lines), `L5/gates.py`
(214 lines).

L5 is four stages, in this fixed order, over `signals.py`'s extraction of
named `Signal`s from the spine:

1. **Accumulate** — sum per-signal log-odds weights, with a **per-family
   redundancy discount**: three SMS-related rules firing on one class is
   treated as close to one fact, not three, via a geometric decay
   (`disc = decay ** rank`) within each configured signal family, clamped to
   a per-family cap. Un-weighted (unpriced) signals contribute nothing.
2. **Map to 0–100** via a sigmoid with two fitted anchors (`s0`,
   `temperature`) rather than a bare linear map (arbitrary endpoints) or a
   plain sigmoid (saturates so hard nearly every malware sample lands near
   99, and Low/Medium bands never get used).
3. **Apply L3** — the ML delta, clipped to ±10 and unable to reach Critical
   alone (see L3 section above).
4. **Apply gates as floors** — `max(score, floor)`, never an override. A
   gate can only raise a score, never lower one, and if the additive score
   already exceeds the gate's floor, the full additive reason chain survives
   rather than being replaced by the gate.

### The smoking-gun gates

Four gates (`L5/gates.py`), evaluated **ternary** (`fired` /
`not_fired` / `indeterminate`) rather than boolean — a gate whose input is
missing *because a layer's coverage failed* is `indeterminate`, never
treated as `false`, so a failed jadx run cannot masquerade as "this leg of
evidence is cleanly absent, therefore benign."

- **G1** — bank impersonation (L0) + credential-harvesting UI (L1).
- **G2** — SMS interception + exfiltration to an external C2, **both legs
  required to cite distinct finding ids**. This is deliberate: a single YARA
  rule like `Android_BFSI_SMS_Intercept_And_Forward` that detects reading
  *and* forwarding SMS inside one rule would otherwise satisfy both gate legs
  by itself, turning a gate into "a rule rename wearing a gate's clothes" —
  that kind of single-rule detection is meant to earn a large additive
  weight instead, not arm a gate alone.
- **G3** (accessibility abuse + overlay on a *known bank package*) and **G4**
  (dropper permission + embedded secondary APK) **ship disabled** — not
  because their logic is wrong, but because the evidence they need does not
  exist in the spine yet (G3 needs a per-package target list L0 doesn't
  record; G4 needs dropper-payload evidence L0 doesn't record either).
  Shipping them "enabled but always false" is explicitly called out as worse
  than shipping them off, because a gate that silently never fires reads as
  evidence of innocence rather than as an unmeasured capability.

### Why the weights are currently unsupported

This is the project's most emphasized open item. **T24**: at `n_benign = 4`
(the size of the original hand-picked benign set), the computed weights are
**sign-inverted, not merely imprecise** — A4 priced 32 of 45 signals
negative (as evidence of being *benign*), including `l0:brand_claim` — the
project's stated differentiator — at **−1.90**. The top-weighted signal in
the system at that sample size was `APK_Valid_Structure_Check` (+2.85), i.e.
"is a well-formed ZIP file." The closed-form requirement derived for a
correctly-signed weight is `B ≥ 213` (where `B` is the benign corpus size),
so L5 currently **refuses to arm a gate** and stamps every score it computes
`unsupported: true` — this is described in `CLAUDE.md` as "not a bug": the
system reports what it was given and declines to pretend otherwise. As of
the CLAUDE.md re-measurement snapshot, the benign corpus re-run was at
245/600, past the T24 threshold of 213 but the re-measurement pipeline
(labels → A4 → calibration → policy validation → score → evaluate) had not
been confirmed complete and re-verified as of that snapshot — this document
did not independently re-run that pipeline to confirm current support
status, and flags that as unverified.

### Why it's built this way

`L5/score.py`'s own docstring states the entire design constraint plainly:
"every point in a final score traces to a named signal or gate carrying the
evidence id that produced it" — the arithmetic exists to serve that
auditability, not the reverse. Gates are described as the **primary**
mechanism, not a bolt-on override, which is the direct replacement for the
proposal's original `0.45·rules + 0.30·ml + 0.25·llm` blend (`CLAUDE.md` §7).

> **ELI5:** L5 is the judge that adds up all the evidence into one number
> from 0–100. It doesn't just add every clue equally — three clues that are
> really "the same fact said three ways" only count once-and-a-bit, not
> three times. Some combinations of evidence (like "pretends to be your
> bank" + "has a fake login screen") are so damning on their own that they
> set a *minimum* score no matter what the math says — but two different
> clues have to actually be two different pieces of evidence, not the same
> finding wearing two hats. And right now, the judge is refusing to hand
> down harsh verdicts based on weights it hasn't measured confidently enough
> yet — it would rather say "I don't have enough data" than guess.

### Current limitations / MVP-only

- 🔴 **Every score currently emitted is stamped `unsupported`** per
  `CLAUDE.md` and should not be used as evidence until the support
  requirement (`n_benign ≥ 213`) is confirmed met by a completed
  re-measurement pipeline run.
- G3 and G4 ship disabled — two of the four designed gates are inert until
  L0 records the missing evidence types.
- `L5/policy.yaml` weights depend entirely on whatever `L5/weights/
  rule_weights_*.json` A4 last produced; a stale weights file silently
  scores under an outdated ruleset unless its `ruleset_version` is checked
  against the sample's own `l1.summary.ruleset_version` (trap **T30**: the
  weights file's own `ruleset_version` is stamped at scoring time and is
  *not* proof L1 was re-run under it).

---

## L6 — Output & Export

**Files:** `L6/report.py` (427 lines), `L6/api.py` (257 lines),
`L6/export.py` (474 lines).

L6 turns one spine into an HTML report (`L6/report.py`), and into
STIX 2.1 / CSV / YARA / Sigma exports plus a FastAPI JSON API
(`L6/api.py`, `L6/export.py`). The report renders a ranked, report-only "AI-
assisted code analysis" section from L4's per-class scores/bands, and the
export layer's own docstring states the standing rule plainly: **"Nothing an
LLM produced can enter an export"** — IOCs come from
`L1/engines/ioc_extract.py` reading the sample's own bytes, the verdict
comes from L5, and MITRE technique mapping comes from the findings' own
`mitre_techniques` fields. An export can legitimately be empty — a sample
with no extracted indicators produces a STIX bundle containing just the
malware object and no indicator objects, rather than a padded one, because
"an IOC list a bank cannot act on is worse than none, since somebody
eventually acts on it."

The API is bound to localhost by default and never given a flag to bind
`0.0.0.0` — the module docstring is explicit that this is the only real
protection, since the service accepts uploaded Android malware. Uploads are
touched only by androguard, zipfile, YARA and jadx-under-the-JVM, mirroring
the corpus-safety discipline used for the malware corpus itself; L2
detonation is a deliberately separate, non-reachable action from this
service. The dashboard is a single static HTML file served with no Node
build step, a deliberate simplicity choice for a project whose argument is
reproducibility on an analyst's own machine.

### Why it's built this way

The proposal's third design commitment, quoted directly in
`L6/export.py`'s docstring, is "operationalizable output: blockable IOCs,
auto-generated YARA/Sigma detection rules, STIX export, and
customer-advisory recommendations — not just a verdict." Keeping the LLM out
of the export path entirely is a direct consequence of the "nothing an LLM
produced enters an export" discipline stated above — this matters most
exactly here, because the output is meant to be loaded straight into a
blocklist or SIEM.

> **ELI5:** L6 is the report-writing and packaging desk. It takes everything
> the earlier layers found and turns it into a human-readable report and
> machine-readable files a bank's security team could actually load into
> their own tools — a list of bad URLs/domains/IPs, ready-made detection
> rules, a standard threat-sharing format. It refuses to let the AI's
> guesses sneak into those exported files — only things that were measured
> or extracted mechanically get exported, because a bad IOC in a blocklist
> can cause real harm.

### Current limitations / MVP-only

- Every export inherits L5's current `unsupported` status — a report or
  export generated today carries a score that L5 itself says should not be
  used as evidence.
- No production deployment story beyond localhost-bound FastAPI + a static
  HTML dashboard; this is appropriate for a hackathon/analyst-workstation
  scope, not a hardened multi-tenant service.

---

## Hard-won lessons

`CLAUDE.md` §6 records 31 numbered traps. Grouped by theme rather than as a
raw list:

### YARA correctness

The recurring failure mode is **scope mismatch between what a rule assumes
and what the scanner actually feeds it**. `uint32()` vs. `uint32be()`
byte-order (T1) silently disabled 27 of 43 rules from ever matching a ZIP.
Batch-scanning multiple files or a whole dex as one buffer (T2, T21) lets a
conjunctive rule be satisfied by tokens scattered across unrelated code,
manufacturing false positives; the fix in both cases was the same shape —
scan the smallest unit the condition's logic actually claims about (one
file, one dex class). Container-scope vs. member-scope confusion (T3, T20,
T28) meant rules gated on ZIP magic could never see the dex where app
strings actually live, while behaviour rules that *did* reach the deflated
container proved nothing and manufactured 82 false positives on a benign
set. A dead rule that self-matches its own declared strings (T25) is a
different diagnosis from a broken condition — it means the corpus simply
doesn't co-locate that vocabulary the way the rule assumed, which is what
led to the "relax the conjunction" repair strategy rather than "the regex is
wrong."

### Evidence integrity

Several traps are about **a record silently meaning something other than
what it appears to mean**. L0's own ingest script overwriting the shared
evidence file on every run (T10) is what forced the separate spine design.
Case-sensitive severity mapping (T11) and unreachable finding categories
(T12) silently downgraded or hid real detections without ever raising an
error. A metric redefined in code without a matching re-baseline (T15) means
every recorded before/after number quietly stops meaning what it used to. A
pipeline step that hits a resource floor, stops early, and still returns
exit code 0 (T30) is the sharpest version of this theme — a downstream
pipeline gated on "did the previous step succeed" cannot tell the difference
between "succeeded" and "silently gave up 41% of the way through," and
produced a clean-looking headline number (AUROC 0.9261) over a corpus that
was 59% pre-fix data.

### Corpus safety

The malware corpus (2.0 GB of live Android malware, per `CLAUDE.md` §4)
carries a small set of non-negotiable handling rules: never bulk-extract
(read one member at a time or extract-then-delete in a `finally`), detect
APKs by magic bytes rather than extension (45% of members are extensionless),
and never execute sample bytes — only androguard, zipfile, YARA and
jadx-under-the-JVM ever touch them. AES-protected zip members having
`CRC-32 = 0` by the WinZip AE-2 spec (T13) is a narrow but real trap: any
resume or dedup key based on CRC degenerates silently for 40% of the corpus.
This discipline was maintained even during this session's YARA repair
work — the validation probe read 90 malware members one at a time from the
zips, never extracted in bulk, and nothing touched was executed.

### Measurement discipline

The most consistently repeated lesson across the whole project: **never
estimate a rate from a hand-picked or small sample and report it as if it
generalizes.** "4 of 8 banking trojans undetected" (a plausible-sounding 50%)
became 92% at corpus scale (T19), because eight samples chosen for being
interesting are not a sample of anything. The Jeffreys-interval discipline
recurs throughout this session's YARA work specifically because of this: a
0/99-benign result on a new rule has a 95% upper bound near 3.7% — it is the
absence of evidence of a high false-positive rate, not evidence of a low
one, and every claim in `decisions/l1_l4_yara_improvements_2026.md` is
phrased that way rather than as a settled result. T24's arithmetic is the
same lesson applied to L5's weights: at `n_benign = 4`, the computed weights
are not just noisy, they are *sign-inverted*, and the fix is not a better
estimator but a larger `B`.

---

## What's missing right now, planned for the full version

Pulled from `todo.md`'s incomplete items, `CLAUDE.md` §7 "Open," and
follow-ups flagged in the decision/research logs, grouped by stage:

**L0**
- `_label_similarity`/`_best_label_sim` in `L0/ingest.py` still use
  `difflib` (T7-adjacent) and are flagged for audit, not yet removed.
- Stale pre-A6 malware `L0/artifacts/` on disk, not yet cleaned up (T16).

**L1**
- Both ransomware YARA rules still dead pending `resources.arsc` string
  extraction in `yara_scan.py` (a scanner change, deliberately deferred).
- No fresh full-corpus A4/rule-firing run has been executed against this
  session's repaired ruleset — the 37% detection figure predates the repair.
- The 8 new 2024–2026 technique rules are validated only for structural
  correctness, not malware-corpus detection rate (the local corpus is
  2020–2022 vintage).
- Full benign-corpus re-validation of the fixed rules (only a 99-app probe
  has run so far).
- 40% partial-decompilation rate is an unresolved ceiling on source-scope
  rule coverage.
- Phase 2 of the codebase refactor (27 `sys.path.insert` hacks → package-
  relative imports) is not started.

**Evidence Spine**
- No items flagged incomplete beyond what's implied by upstream/downstream
  layers.

**L2**
- **Network isolation is not enforced** — `enforce_isolation()` exists,
  has an unfixed chain-wiring bug, and is called from nowhere in the
  orchestrator.
- **The go/no-go checkpoint to detonate the India-12 demo set has not been
  given.**
- The SBI Quick Support sample's actual malicious payload has never been
  observed triggering in a live run — hook capture is verified reliable,
  hook triggering on this specific sample is not.
- `/system` read-only on the current AVD blocks system CA install and
  `/etc/hosts` DNS redirection (worked around, not fixed).
- L2 spine producer needs a working, isolated emulator before it can be
  trusted end to end; L2 integration tests that need a live emulator are
  skipped when unavailable.

**L3**
- **No model is trained.** `L3/model/` is empty; `l3` is `not_attempted` on
  every spine. Only the pipeline itself is verified (2020-only proof run).
  Full training needs ~6 GB and has not run in this repository.

**L4**
- The `GROUNDED → L5 ±5 pts` scoring edge is designed but explicitly not
  wired — deferred behind the same `n_benign ≥ 213` gate as L5 itself.
- A live-sample smoke test of the newer 3-agent pipeline against the SBI
  sample is still an open `todo.md` item, distinct from the standalone real-
  sample run in the worked example below.
- Call-stack-level code-to-network attribution (vs. today's string/host
  content matching) is out of scope, flagged as a separate future plan.

**L5**
- 🔴 **Every score is currently stamped `unsupported`** — weights are not
  confirmed safe to use as evidence.
- G3 (accessibility+overlay+bank-target) and G4 (dropper+embedded-payload)
  gates ship disabled; L0 does not yet record the evidence they need.
- The CICMalDroid banking corpus (2,505 labelled APKs, downloaded and
  audited) is deliberately **not yet integrated** — a corpus-composition
  decision recorded as needing a human call, not a technical blocker.

**L6**
- No items specific to L6 beyond inheriting L5's `unsupported` status on
  every report/export it produces today.

**Cross-cutting**
- A dedicated hard-negative BFSI benign panel (T27) — F-Droid has 5
  accessibility apps, 79 SMS apps, and zero commercial banking apps
  repo-wide, so it cannot validate the accessibility/BFSI rule classes no
  matter how large the benign corpus grows.
- Integration tests for the full L0→spine→L1→spine chain.

---

## How the layers work together — a worked example

The clearest illustration of why this project has multiple independent
evidence-gathering layers rather than betting everything on one is the
**SBI Quick Support impersonator** sample
(`8f05ecbb5f9fe721dfcd380669ab7ebb1dffc433ee0c4d5dce9936afa69564b0`,
package `com.sbi.complaintregister` — one of the India-12 demo set,
`AndroidMalware_2021/novTargetedIndianBanks.zip`).

**L4's static reasoning pass**, verified by reading
`L4/artifacts/8f05ecbb5f9fe721dfcd380669ab7ebb1dffc433ee0c4d5dce9936afa69564b0/deobfuscation.json`
directly, found a real `sources/com/sbi/complaintregister/SmsListener.java`
class with, among its mechanically **verified** (not just LLM-claimed) API
calls: `android.content.BroadcastReceiver.onReceive`,
`android.telephony.SmsMessage.createFromPdu`,
`android.telephony.SmsMessage.getDisplayOriginatingAddress`,
`android.telephony.SmsMessage.getDisplayMessageBody`, and
`android.telephony.SmsManager.sendTextMessage`. Its verified `iocs` field
contains exactly one URL: `https://complaintsregister.com/api/msgstore?
task=savemsg`. The unverified analyst summary (a free-text hunch, carried
separately from the mechanically-checked facts) reads: "Intercepts incoming
and outgoing SMS messages, exfiltrates them to a remote server, and sends
attacker-controlled SMS replies based on the server response," flagged
`suspicion.flag: true`, `first_verdict: malicious`, `confidence: high`. This
is a textbook SMS-interception-and-exfiltration banking trojan, and the L4
pipeline found it from static source alone.

**L2's live dynamic runs on the same sample**, per
`docs/l2_droidbot_reliability_log.md`'s entries for 2026-08-16, tell a
different story: two confirmed live detonation runs with Frida reliably
attached (7 and 8 re-attachments respectively across a restart-prone
session, all producing valid, parseable hook data) recorded **zero
`finding`-category hooks** — no `SmsManager.sendTextMessage`, no overlay, no
`DexClassLoader`, no `ClipboardManager` call ever observed at runtime,
despite DroidBot genuinely reaching and operating the app's real
`MainActivity` (not stuck on the splash screen) and the sandbox's injected
fake OTP SMS being available to intercept. (One earlier spine entry for this
same sample, dated 2026-08-14 and pointing to an artifact path under
`/tmp/tmp.SPMaUsZYWa/...`, records 11 L2 findings — but that path and
timing match the *synthetic* integration-test fixture from
`decisions/plan_l2_phase4.md`'s task 4f, not a genuine live detonation, and
predates the 2026-08-16 live-run fixes described above. It should not be
read as "L2 has already caught this sample live.")

**Why the gap:** the `SmsListener` class's malicious logic is almost
certainly gated behind a specific interaction the automated sandbox hasn't
reproduced yet — a form-submission flow, a server-response condition the
mitmproxy honeypot's generic fake API shapes don't match exactly, or
passive SMS-broadcast listening that the injected OTP didn't trigger for
reasons unrelated to navigation. This is explicitly recorded as a distinct,
still-open problem, narrower than "can the sandbox reach the app."

This is the concrete argument for the multi-layer design: **a real,
dangerous SmsListener class exfiltrating to a live-looking C2 endpoint was
found with high confidence by static reasoning over decompiled source,
while a fully-functioning dynamic sandbox — genuinely running the app, with
verified Frida hook capture — produced nothing, because the malicious code
path simply never executed during the automated run.** Neither layer is
individually sufficient here: L1's YARA static scan on this exact sample
fires **only `APK_Valid_Structure_Check`** (per
`decisions/l1_l4_yara_improvements_2026.md` §3.4's end-to-end scan table) —
this sample is caught by L0 impersonation and L4's reasoning, not by L1's
pattern rules at all. A pipeline betting everything on any single layer
being complete would have missed this sample; the combination — L0 flagging
the impersonation, L4 reading the actual SMS-theft logic from source, L2
still working to reproduce it live — is closer to what "evidence-driven"
is supposed to mean in this project's own framing.

---

## Sources checked while writing this document

- `CLAUDE.md`, `todo.md` (full read)
- `decisions/decision-0001-evidence-spine.md`,
  `decisions/decision-0002-codebase-refactoring.md`,
  `decisions/decision_l2_setup.md`, `decisions/decision_l2_code_fixes.md`,
  `decisions/decision_yara_improvement.md`,
  `decisions/l1_l4_yara_improvements_2026.md`,
  `decisions/plan_l2_network_isolation.md`, `decisions/plan_l2_phase3.md`
  (list only — not read in full for this document),
  `decisions/plan_l2_phase4.md`, `decisions/plan_l4_agentic_verdicts.md`,
  `decisions/plan_l4_rag_verdicts.md` (full read, except plan_l2_phase3.md)
- `docs/l2_droidbot_reliability_log.md` (full read)
- `docs/research/` file list and titles (not all read in full; the 2024-2026
  YARA techniques content was cross-checked against
  `decisions/l1_l4_yara_improvements_2026.md`'s own citations of it)
- Source files: `spine.py`, `L0/ingest.py` (partial), `L0/impersonation.py`
  (full), `L1/l1.py` (full), `L5/score.py` (full), `L5/gates.py` (full),
  `L3/train.py` (partial — header/docstring), `L4/deobfuscate.py`
  (partial — header), `L4/verify_verdict.py` (partial), `L6/export.py`
  (partial — header), `L6/api.py` (partial — header)
- `L4/artifacts/8f05ecbb5f9fe721dfcd380669ab7ebb1dffc433ee0c4d5dce9936afa69564b0/deobfuscation.json`
  (read directly, in full, to verify the worked example)
- `artifacts/8f05ecbb5f9fe721dfcd380669ab7ebb1dffc433ee0c4d5dce9936afa69564b0/evidence.json`
  (read directly to check the L2 spine block for the same sample, which is
  what surfaced the synthetic-artifact-path discrepancy noted above)
- `$SENTINEL_PYTHON -m pytest tests/ -q` run directly during this session:
  **285 passed**
- `tests/` directory listing (not individual test file contents)

Anything stated as a specific number in this document was read from one of
the above sources; anything stated as unverified is explicitly marked so in
context rather than presented as settled.
