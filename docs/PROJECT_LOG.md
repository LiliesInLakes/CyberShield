# APK Sentinel — Master Project Log

> Living document. Records **ideation**, **implementation**, and **possible improvements**
> for every phase (L0–L6). Append-only per phase; never rewrite history, add revisions.
>
> **Convention:** each phase gets four sections mirroring the four working domains —
> `RESEARCH` (feasibility & direction), `PLAN` (design, reviewed before any code),
> `IMPLEMENTATION` (what was actually built), `VALIDATION` (tests, evidence, confidence),
> plus a standing `IMPROVEMENTS` backlog.

---

## Document index

| Section | Contents |
|---|---|
| [Part 0 — Baseline Audit](#part-0--baseline-audit-2026-08-07) | Verified ground truth of the repo as of 2026-08-07 |
| [Part 1 — Phase L2](#part-1--phase-l2-dynamic-analysis) | Dynamic analysis: research → plan → build → validate |
| [Part 2 — Phase A Execution](#part-2--phase-a-execution) | A2 L1 finding quality · A6 L0 impersonation hardening |
| [Part 3 — Workstream A1](#part-3--workstream-a1--the-evidence-spine-2026-08-08) | The evidence spine: built, wired, measured |
| [Part 4 — Workstream A3](#part-4--workstream-a3--the-corpus-runner-2026-08-09) | Corpus runner + first full-corpus run (705 samples) |
| [Part 5 — Workstream B1](#part-5--workstream-b1--closing-the-detection-gap-2026-08-09) | Root cause of the 92% gap; dex scanning + BFSI rules; 8% → 37% |
| [Improvements Backlog](#improvements-backlog) | Deferred ideas, ranked |

---

# Part 0 — Baseline Audit (2026-08-07)

Everything below was **verified by execution or direct file inspection**, not read from
prior documentation. Where the repo's own docs disagree with observed behaviour, the
observation wins and the discrepancy is noted.

## 0.1 Layer status

| Layer | Claimed | **Verified** | Notes |
|---|---|---|---|
| L0 Ingestion & Triage | Complete | ✅ **Works** | Ran end-to-end on 8 APKs. Emits `L0/artifacts/<sha256>/evidence.json`. |
| L1 Static Analysis | Complete | ⚠️ **Partial** | jadx track works. **Ghidra track cannot run — Ghidra is not installed.** |
| L2 Dynamic Analysis | "Semi-implemented" | ❌ **Non-functional** | Scripts exist; pipeline is broken at 6 independent points (§0.3). Zero telemetry ever captured. |
| L3 ML Classifier | Planned | ❌ **Does not exist** | No code. |
| L4 GenAI Reasoning | Planned | ❌ **Does not exist** | No code. |
| L5 Hybrid Scoring | Planned | ❌ **Does not exist** | No code. |
| L6 Output & UX | Planned | ❌ **Does not exist** | No code. |

**Total source:** ~3,000 lines of Python + ~1,300 lines of YARA across 11 rule files.

## 0.2 The "evidence spine" is aspirational

The proposal's central architectural claim is a single `evidence.json` that every layer
appends to. **This does not exist in practice:**

- `L0/ingest.py` writes `evidence.json` with `l1`–`l6` hardcoded to `{"status": "pending"}`.
- Nothing ever updates those keys. There is no merge step anywhere in the repo.
- L1 writes a *separate* `L1/artifacts/<sha>/analysis.json`.
- L2 writes a *separate* `L2/artifacts/<sha>/analysis.json`.

Three disconnected files, not one spine. **This is the single most important structural
gap** — every downstream layer (L3/L4/L5) is specified to consume "the evidence spine",
so the spine must be made real before L3+ can be built on it.

## 0.3 L2 defect inventory (verified)

L2 is not "semi-implemented" — it is broken at six independent points, each of which
alone would produce zero output:

1. **Schema mismatch.** `L2/l2_engine.py` parses keys `runtime_behaviors`, `network`,
   `findings`. The `dynamic.json` files actually on disk contain `api_calls_observed`,
   `dropper_payload_writes`, `c2_beacons`, `runtime_confirmed_categories`. The parser can
   never match. Worse: **no script in the repo produces the on-disk schema** — those
   artifacts came from a script that no longer exists.
2. **Path mismatch.** `orchestrator.py` writes to `L2/sandbox/artifacts/<package_name>/`;
   `l2_engine.py` reads `L2/artifacts/<sha256>/`.
3. **Frida output is not JSONL.** The orchestrator pipes the `frida` **CLI**'s stdout into
   a file named `frida_hooks.jsonl`. The CLI prints human-readable `message: {...}` text,
   never raw JSON lines. Correct approach is the `frida` Python bindings with an
   `on('message')` handler.
4. **Wrong mitmproxy binary.** Launches `mitmproxy` (the interactive TUI) as a headless
   subprocess. Must be `mitmdump`.
5. **No traffic can reach the proxy.** Nothing sets the emulator's HTTP proxy and nothing
   installs a CA certificate. mitmproxy would capture nothing even if it started.
6. **Hook coverage misses the primary threat.** Hooks exist for `SmsManager.sendTextMessage`,
   `WindowManagerImpl.addView`, `DexClassLoader.$init`, `ClipboardManager.setPrimaryClip`.
   There is **no hook for incoming SMS / OTP interception** — the single most important
   banking-trojan behaviour in the threat model — and none for accessibility services or
   the notification listener.

Every `dynamic.json` on disk records `frida_event_count: 0` and empty behaviour arrays,
consistent with the above.

## 0.4 Other verified defects

| # | File | Defect | Severity |
|---|---|---|---|
| D1 | `L1/engines/ghidra_analyze.py:44-53` | Runs `analyzeHeadless` with `-noanalysis`, then extracts `getDefinedStrings()`. With analysis disabled Ghidra never populates defined strings — the extraction is near-empty by construction. A previous session disabled analysis to fix a hang and silently disabled the payload. | **High** |
| D2 | `L1/engines/yara_scan.py:87-90` | `data` is assigned inside `for inst in sm.instances[:2]` but read outside it. Empty `instances` ⇒ `NameError` or stale value leaking from the previous rule. | Medium |
| D3 | `L2/sandbox/honeypot.py:41-50` | `seed_contacts` iterates `(name, number)` but inserts **empty** `raw_contacts` rows — name and number are never bound. Fake contacts are not actually seeded. | Medium |
| D4 | `L2/sandbox/honeypot.py:77-84` | `content insert --uri content://sms` from the `shell` UID is blocked on API 29+ unless the caller is the default SMS app. Fake OTP seeding likely fails silently. Needs verification on the API 30/34 images present. | Medium |
| D5 | `L2/sandbox/mitm_addon.py:59` | `self.log[-1]["hijacked"] = ...` in `response()` assumes the last logged request is this flow's. False under any concurrency; annotations land on the wrong record. | Medium |
| D6 | `L0/ingest.py:42-44` | Silences androguard via stdlib `logging`, but androguard 4.x logs through **loguru**. Debug output floods stdout (confirmed: thousands of lines during the sweep). | Low |
| D7 | `source_env.sh` | Hardcoded absolute paths for a different machine (`/home/adios/...`). Unusable as shipped. | Low |
| D8 | `L1/engines/ghidra_analyze.py:94` | Error string still references the pre-port Windows path `D:\BOI\tools\ghidra\`. | Cosmetic |
| D9 | `L0/artifacts/<sha>/<sha>/` | A past run nested L1 output *inside* the L0 artifact tree (`analysis.json` + `jadx_src`), and an L2 `analysis.json` sits in `L0/artifacts/<sha>/`. Artifact-root plumbing has been mis-wired at least once. | Low |

## 0.5 Corpus reality — the binding constraint

This is the constraint that governs every downstream design decision.

**Malware:** `L0/dataset/<family>/<sha256>/` holds **metadata only** for ~52 real
banking-trojan samples across 17 families (AbereBot, Alienbot, Anubis, Backdoor, BankBot,
Banker, Cerberus, Covid, FakeCop, FluBot, Hydra, Sharkbot, SMS Stealer, Spy, Teabot,
Trojan, unknown). Each record has package name, app label, versions, min/target SDK, the
**full permission list**, high-risk permission subset, icon pHash, and APK-structure
routing info (dex count, native libs, arches, framework indicators, packing signals).

**The APK binaries are not present.** Consequences:
- No bytecode, strings, or code for these samples ⇒ **L1 cannot run on any real malware.**
- No executable ⇒ **L2 cannot detonate any real malware.**
- Only manifest/permission/structure features survive ⇒ this metadata is usable for
  **L3 features only**.

**Benign:** 4 real APKs (Proton Lumo, PennyWise, Notely, DuckAssist).
**Vulnerable-but-not-malicious training apps:** 5 (InsecureBankv2, PIVAA, UnCrackable L1/L2).

**Net:** 56 malicious feature-vectors vs 4 benign APKs. Any accuracy/precision/recall/AUROC
number produced from this is not defensible. Honest evaluation strategy is an open question
routed to the research domain.

### 🔴 Finding B5 — the corpus contains **zero** India-targeted samples

I enumerated the app label and package of all 56 records. The impersonation lure surface is:

| Lure cluster | Examples | Region |
|---|---|---|
| Turkish state/telco | `20GB HEDIYE INTERNET`, `EvdeKal`, `Sosyal Destek 30 GB`, `e-Devlet`, `Ayarlar(MN)`, `Temel Video player`, `Porno İzle` | 🇹🇷 Turkey |
| European courier | `DHL`, `DHL Express Mobile`, `UPS Mobile`, `postnord`, `OmaPosti`, `Voicemail` | 🇪🇺 EU (FluBot/FakeCop) |
| European bank | `BAWAG P.S.K. Security` | 🇦🇹 Austria |
| Thai government | `ไทยชนะ` (Thai Chana) | 🇹🇭 Thailand |
| Generic/security decoys | `Video Player`, `Flash Player`, `Сhrоme` (Cyrillic homoglyph), `Google Play`, `Google Play Protect`, `Norton 360`, `Authenticator 2FA` | — |

**Not one sample impersonates an Indian bank, UPI app, or Indian government service.** No SBI,
HDFC, ICICI, BOI, PhonePe, Paytm, BHIM, Income Tax, UMANG, DigiLocker, RTO/eChallan — nothing.

This is the most consequential finding in the audit, because it means:
- The **39-entity Indian bank whitelist** — the project's genuine differentiator — has **no
  positive test case**. It has never been demonstrated catching anything.
- The **India-specific YARA rules** (Drinik/ITR, UPI intents, `SBIINB`/`HDFCBK`/`BOIIND`
  sender IDs, Aadhaar/PAN/KYC lures) have no sample that could trigger them, even if the
  binaries existed.
- The entire "Indian BFSI" positioning currently rests on **reference data and rules, with
  zero corpus support.** A judge asking "show me it catching an Indian bank clone" cannot
  be answered today.

### Finding B6 — structural profile argues against the Ghidra investment

From the same enumeration: **7 / 56 samples (12.5%) carry any native `.so`**, and **0 / 56
carry a detected packing signal**. The native-analysis track — currently dead and requiring
a ~1 GB Ghidra install against ~20 GB free disk — would apply to roughly one sample in eight.
This is evidence for *deferring* Ghidra behind a capability check rather than treating it as
a blocking prerequisite.

### Finding B7 — the permission signal is degenerately strong

Permission frequency across the 56 malicious records:

| Count | Permission |
|---|---|
| 56/56 | `INTERNET` |
| **55/56** | **`READ_SMS`** |
| **55/56** | **`RECEIVE_SMS`** |
| **54/56** | **`SEND_SMS`** |
| 51/56 | `READ_CONTACTS` |
| 47/56 | `RECEIVE_BOOT_COMPLETED` |
| 43/56 | `WRITE_SMS` |
| 29/56 | `SYSTEM_ALERT_WINDOW` |

A classifier trained on this corpus would learn essentially **"requests SMS permissions ⇒
malware"** and score ~100% on its own test split. That rule fires on every legitimate Indian
OTP-reading app, every default SMS client, and every bank app that auto-reads OTPs — i.e.
precisely the hard negatives the proposal itself commits to measuring. This corroborates the
decision to source L3 training data externally rather than from this set.

## 0.6 Environment — better than expected

| Component | Status |
|---|---|
| Python | 3.13.14 (system). L0/L1 deps all importable: androguard, yara, PIL, imagehash, requests, cryptography, numpy. |
| L3+ deps | **Missing**: scikit-learn, xgboost, lightgbm, fastapi, pydantic. |
| jadx | ✅ present (`tools/jadx`) with bundled JDK 17 (`tools/jdk17`). |
| **Ghidra** | ❌ **absent**. Native track is dead until installed. |
| **KVM** | ✅ `/dev/kvm` present and world-accessible. |
| **Android emulator** | ✅ `tools/android-sdk/emulator/emulator` + `platform-tools/adb`. |
| **System images** | ✅ `android-30` and `android-34`, both `google_apis/x86_64` (⇒ `adb root` works; no Play Store ⇒ rootable). |
| **AVD** | ✅ `sentinel.avd` already defined. |
| **frida-server** | ✅ x86-64 Android ELF binary in `tools/`. |
| Disk | ~20 GB free. |

**Implication:** the L2 blockers are *software defects, not missing infrastructure.*
Every hardware/tooling prerequisite for dynamic analysis is already on the machine. This
substantially raises the expected value of repairing L2 rather than abandoning it.

### 🔴 Finding B8 — the `sentinel` AVD does not boot (BLOCKER for L2)

Attempted three times; **the emulator dumps core** every time, ~30–60 s into startup,
before `sys.boot_completed` is ever set. `adb devices` stays empty.

| Attempt | Flags | Result |
|---|---|---|
| 1 | `-no-window -no-audio -no-snapshot -no-boot-anim -writable-system -gpu off` | core dump |
| 2 | same, relaunched via `setsid` (to rule out process-group kill) | core dump |
| 3 | `-gpu swiftshader_indirect -feature -Vulkan -camera-back none -camera-front none` | core dump |

Ruled out:
- **Not OOM** — 8.3 GB available at crash time; AVD requests 2 GB.
- **Not a process-group kill** — persists under `setsid`/`disown`.
- **Not (only) Vulkan** — persists with Vulkan disabled and swiftshader forced, though the
  verbose log still shows Vulkan `ColorBuffer` allocations and multiple `RenderThread`s
  being created *after* `-gpu off`, which is itself suspicious.

Last log line before death is always `Emulator is performing a full startup`. No kernel OOM
or segfault entry is visible and `coredumpctl` is unavailable, so the crash reason is not yet
captured.

**Consequence:** L2 cannot be tested at all until this is fixed. Every L2 defect in §0.3 is
currently unverifiable in practice. Diagnosis is deferred to the L2 phase rather than pursued
now — chasing it here is exactly the "L2 rabbit hole eats the schedule" failure mode both
research agents independently warned about. Candidate next steps when the phase opens: run
without `-no-window` under a virtual display to surface a GUI-side assert; try the android-34
image instead of android-30; recreate the AVD from `avdmanager` rather than reusing the
existing one; check `emulator -accel-check` and the bundled Qt/libstdc++ against the Fedora
host libraries.

## 0.7 Baseline sweep — and the category error it exposes

`L0 → L1` was run over the **full** local corpus (8 APKs, all completed, exit 0):

| Sample | Class | Track | Decompiled | L1 time | Findings | Severities |
|---|---|---|---|---|---|---|
| UnCrackable L1 | vuln-training | jadx | 6 | 1 s | 1 | 1 med |
| UnCrackable L2 | vuln-training | combo | 283 | 2 s | **0** | — |
| PIVAA | vuln-training | jadx | 1,209 | 5 s | 6 | 1 crit, 2 high, 3 med |
| InsecureBankv2 | vuln-training | jadx | 2,992 | 1 s | 3 | 1 high, 2 med |
| DuckAssist | **benign** | jadx | 605 | 3 s | **3** | **1 crit**, 1 high, 1 med |
| Notely | **benign** | combo | n/a | 145 s | **3** | 1 high, 2 med |
| PennyWise | **benign** | combo | n/a | 38 s | **10** | **1 crit**, 1 high, 8 med |
| Proton Lumo | **benign** | combo | n/a | 14 s | **11** | **2 crit**, 2 high, 7 med |

> **Correction (2026-08-07):** an earlier revision of this table swapped Notely and
> PennyWise. Ground truth re-verified from `source_apk` inside each `analysis.json`:
> `ae1ce24a…` = Notely (3 findings), `1256daaa…` = PennyWise (10 findings). The rows above
> are correct. **Use the on-disk artifacts, not this table, as the regression oracle.**

**False-positive rate on the benign set: 4 / 4 apps flagged (100%), including three
`critical` findings.** The prior session note claiming "Pipeline validated: 4/4 vuln APKs
have 0 FPs" only ever measured the *vulnerable training* apps; the benign set was never
run. That claim does not survive contact with the benign corpus.

### 🔴 Finding B1 — L1 is a vulnerability scanner, not a malware detector

Most findings produced across the corpus fall into `category: other`, and are
**insecure-coding** findings rather than malicious-behaviour findings:

- `Android_WebView_JavaScriptEnabled`
- `Android_WebView_JavascriptInterface`
- `Android_SSL_TrustAll`
- `Android_Crypto_StaticIV`
- `Android_Secrets_Hardcoded`
- `Android_Dynamic_CodeLoading`

**Not one finding** landed in the categories the threat model is built on —
`sms_intercept`, `overlay_attack`, `accessibility_abuse`, `c2_communication`,
`data_exfiltration`, `phishing_impersonation`. The India-specific rules (Drinik/ITR, UPI
targeting, Indian SMS sender IDs, Aadhaar/KYC lures) have **never fired even once**.

The consequence is stark: **DuckAssist — a benign note-taking app — scores a `critical`
finding and is otherwise indistinguishable from InsecureBankv2.** On the evidence L1
currently produces, no downstream scoring layer could separate them.

Two distinct root causes, and it matters which is which:
1. The rule set that *does* fire is OWASP-MASVS-style app-hardening content (this is what
   MobSF already gives for free) rather than malware-behaviour content.
2. The banking-malware rules cannot fire because **the corpus contains no banking
   malware** — see §0.5. The pipeline has never been executed against a single instance
   of its actual target class.

Cause (2) is the deeper problem, and it is a *corpus* problem, not a code problem. It is
the highest-priority open question routed to the research domain.

### 🔴 Finding B2 — the obfuscated sample produces nothing

UnCrackable L2 is a deliberately obfuscated app carrying a native `.so`. L1 decompiled 283
files and produced **zero** findings; the raw-APK YARA scan also returned zero. With
Ghidra absent, the combo track silently degrades to jadx-only (`ghidra_run: false`) and
the packing/obfuscation detection story is entirely unproven.

Also note `combo_analyze` drops `decompiled_files` from its summary, so the combo track
reports `decompiled: None` — coverage metrics needed for the confidence axis (I7) are
lost exactly on the track where they matter most.

### 🔴 Finding B3 — malware-category rules fire on benign apps

Contradicting B1's first reading, the banking-malware rules *do* fire — **on benign
software.** PennyWise, an open-source expense tracker, triggers:

| Rule | Category asserted |
|---|---|
| `Android_Banking_Generic_OverlayEngine` | `overlay_attack` |
| `Android_Ransomware_Generic_File_Encryption` | `ransomware` |
| `Android_Dropper_Encrypted_Payload_Stage1` | `native_payload` |
| `Android_Clipboard_Hijacker` | clipper malware |
| `Android_Suspicious_Network_Communication` | `c2_communication` |
| `Android_SSL_TrustAll` | **critical** |

An expense tracker is being accused of being banking-overlay malware, ransomware, and a
dropper simultaneously. These rules are not discriminative — they match ambient Android
API usage present in most non-trivial apps.

PennyWise is in fact the corpus's best **hard negative**: it legitimately reads SMS to
parse bank transaction alerts, which is exactly the behaviour profile the proposal commits
to measuring false positives against. Driving its malware-category findings to zero *while
keeping* its OWASP-hardening findings is the sharpest available success criterion for L1
rule tuning.

### 🔴 Finding B4 — the raw-APK YARA scan produces meaningless matches

Proton Lumo's 11 findings, traced to their `location` fields, expose two compounding bugs:

**(a) One finding is emitted per matched *string*, not per matched rule.** YARA rules are
`condition`-based (`3 of them`, etc.). A single rule that legitimately fired **once** is
reported as up to 7 separate findings — inflating any downstream count-based score by a
multiple. Proton Lumo's `Android_Clipboard_Hijacker` alone appears **6 times** from one
rule match.

**(b) Scanning the raw compressed APK matches random bytes.** Actual `yara_apk` evidence
strings recovered:

| Reported as | Matched text | What it really is |
|---|---|---|
| clipper malware `$wallet1` | `19CreateSharedCounterEiPPv` | a C++ mangled symbol in a native lib |
| clipper malware `$wallet3` | `TouchExplorationStateChangeListene` | an AndroidX accessibility class name |
| clipper malware `$upi_id` | `p@q` | random bytes satisfying a UPI-ID regex |

**(c) No cross-engine dedup.** `l1.py` appends `scan_apk` results to the engine report
without deduplicating against `yara_source`. The same rule fires on both the decompiled
Java and the raw DEX inside the APK, producing paired duplicates (4 of Lumo's 11).

**Net effect:** finding *counts* are currently meaningless as a scoring input, and a
non-trivial share of finding *content* is noise. Any L5 scoring built on today's L1 output
would be scoring artefacts. **Fixing L1 finding quality is a hard prerequisite for L5.**

---

# Part 1 — Domain 1: Research & Direction

Two agents were given the same brief and opposing mandates — **PROPONENT** (find the path
where the plan works) and **SKEPTIC** (red-team it, propose a different direction if
warranted) — then each was given the other's statement for rebuttal.

## 1.1 Externally verified facts

Claims I re-verified myself rather than taking on an agent's word.

| # | Fact | Verification | Impact |
|---|---|---|---|
| R1 | **LAMDA dataset is real, ungated, MIT-licensed.** 2,016,762 rows, 3.23 GB parquet, 4,561 features, 2013–2025. Ships `feature_mapping.csv` mapping `feat_i` → original static token, plus a released global vocabulary and preprocessing objects. | Fetched the HF dataset card + README directly. | **L3 becomes viable.** Features are Drebin-style, extracted from `AndroidManifest.xml` (permissions, components, hardware features, intent filters) — a space L0 can already produce. |
| R2 | **MalwareBazaar API is free and self-service** (`auth.abuse.ch`), with `get_taginfo` / `get_siginfo` / `get_file`; samples ship zip-encrypted with password `infected`. | Fetched the API docs. | The repo's `L0/harvest_dataset.py` already implements the `ZIP_PASSWORD = b"infected"` convention — the plumbing exists. |
| R3 | **But MalwareBazaar is not an Android source.** A public recent export of 1,156 samples (2026-08-05→07) contained **1 `apk` + 5 `xapk`** vs 591 `elf`, 191 `js`, 183 `exe`. | PROPONENT pulled and parsed the export. | **Refutes SKEPTIC's #1 recommendation.** The Android sample problem needs a different source. |
| R4 | **Free, ungated Android malware binaries exist on GitHub:** `sk3ptre/AndroidMalware_2020\|2021\|2022` and `ashishb/android-malware`, ~1.9 GB total, plain `git clone`. Named archives cover Anubis, Cerberus, TeaBot, FluBot, AlienBot, Sharkbot, Medusa, Vultur, BRATA, Ginp, EventBot — the same families already in `L0/dataset/`. | PROPONENT queried the GitHub API. | **Primary candidate unblocker.** Caveat: sk3ptre last pushed 2021–2022 ⇒ binaries are 2020–2022 vintage. |
| R5 | **LAMDA is ~99.6% non-banking.** Banking families total ~1,513 of 369,906 malware (~0.4%). Zero `drinik`, `teabot`, `hydra`, `ermac`, `octo`, `tsarbot`. Top families are adware (`dowgin` 32,475, `kuguo` 20,966). Recent years collapse: 2023: 7,892; **2024: 794; 2025: 23**. | PROPONENT downloaded and counted `metadata.csv`. | L3 must be reframed as a **generic maliciousness prior**, not a banking-family classifier, with test horizon ≤2023. |
| R6 | **AndroZoo is not obtainable on this timeline.** Access conditions explicitly reject personal email ("gmail, qq will not be processed"); institutional address + faculty co-sign required. | PROPONENT fetched the access page. | The proposal names AndroZoo, Drebin, CICMalDroid, MalRadar — **all four are deadline-hostile or dated.** |
| R7 | **`fkie-cad/Sandroid_Dexray-Intercept` is live and pip-installable** (last push 2026-08-04). Frida-based, JSON output, auto-provisions frida-server. Hook categories: crypto, network, filesystem, IPC, process (DEX unpacking, native libs), services. **Documents no SMS-interception and no accessibility hooks.** | PROPONENT queried the GitHub API. | L2 should **adopt a maintained profiler** and write only the BFSI hook pack it lacks — which is precisely this project's differentiation. |
| R8 | **The L2 "active honeypot" targets the wrong channel.** FCM command delivery uses a persistent connection to `mtalk.google.com:5228` over Google's proprietary MCS binary protocol — it does not traverse an HTTP proxy on 8080. Injecting `200 OK` at `fcm.googleapis.com` intercepts the *server-side send API*, which a client-side trojan never calls. | SKEPTIC's protocol analysis; put to PROPONENT for rebuttal. | The README's headline L2 claim is likely mechanically unsound as built. |
| R9 | **Android CA trust is the expensive part.** User-installed CAs ignored since API 24; mitmproxy requires the **system** store via `-writable-system` + remount, or Magisk. Android 13+ moved the store into an APEX. mitmproxy issue #6498 tracks Android 14 breakage. | Both agents, consistent. | **Pin the AVD at API 30/31.** The existing `sentinel` AVD is already android-30 — correct by luck. |
| R10 | **Emulator infrastructure is fully present.** `/dev/kvm` live; `sentinel` AVD = android-30 `google_apis` x86_64 (rootable, no Play Store); emulator + adb + x86-64 `frida-server` in `tools/`. | Verified locally. | **L2's blockers are software defects, not missing infrastructure.** |

## 1.2 Where the two agents agreed (treated as settled)

1. **Build the evidence spine first.** Both ranked it Phase 0. Nothing downstream is meaningful
   without one merged `evidence.json`.
2. **The LLM contributes zero points to the score.** It is an evidence *generator* and
   *explanation* layer. Neither agent would let a 7B model's self-rated severity carry 25%
   of a bank-facing number.
3. **The `0.45/0.30/0.25` blend must go.** It sums incommensurable units (a rule-hit ratio,
   a calibrated probability, and a self-reported confidence) with weights that were never
   fit to anything. Replace with an auditable additive/log-odds scheme.
4. **Smoking-gun override gates are the best idea in the proposal** — keep them, and make
   them the *primary* mechanism rather than an override bolted onto an indefensible blend.
5. **Risk and confidence as separate axes is the second-best idea** — and it is what lets a
   failed detonation be represented honestly as a confidence penalty rather than a silent gap.
6. **Demote the "active honeypot" claim.** Both agents, for different reasons.
7. **Defer Ghidra.** Corroborated locally: only 7/56 samples (12.5%) carry native libs and
   0/56 show packing signals (Finding B6).
8. **Drop "Ask the Analyst" chat and the analyst feedback loop.** No time, no labels, no users.
9. **Boosted trees over static features is the right ML algorithm** — the dispute is entirely
   about training data, not the model class.

## 1.3 Live disagreements sent to rebuttal

| # | Dispute | SKEPTIC | PROPONENT |
|---|---|---|---|
| D-1 | **Sample source** | MalwareBazaar (afternoon unblock) | Refuted — MB is ELF/PE; use the GitHub repos |
| D-2 | **What comes second, after the spine** | **L5 scoring** — "if L3 and L4 both fail you still have a shippable product" | **L3 on LAMDA** — then L5+L6 as "the demo; protect it" |
| D-3 | **L3's fate** | Kill and replace; bound to ±10 points | Keep, reframe as generic prior; one term in a log-odds sum |
| D-4 | **L2 ambition** | Rescope to a "Behavioural Confirmation Harness" that reports its own failure rate | Adopt `dexray-intercept` + write the ~200-line BFSI hook pack |
| D-5 | **How to demo the India differentiator** | Reproduce published 2026 Indian IOCs | Anchor narrative on current intel while detonating older binaries |

**D-5 is the highest-priority unresolved question in the project** (see Finding B5): the
Indian whitelist and India-specific YARA rules are the stated differentiator and have no
positive test case in any available corpus, including the GitHub repos (FluBot, Cerberus,
TeaBot are European/Turkish campaigns).

## 1.4 Threat-intelligence currency

Both agents independently concluded **Drinik/SOVA is not wrong, but incomplete** as a 2026
anchor. The current India-relevant set to add to YARA vocabulary and report narrative:

- **TsarBot** — 750+ banking/finance/crypto apps, India explicitly in the target list with
  observed injection pages for Indian banks.
- **CloudSEK "Digital Lutera"** (2026-03-11) — weaponized **LSPosed** module hooking
  `SmsManager.sendTextMessage()` and `getLine1Number()`, Socket.IO C2, **injects fabricated
  SMS records into the device SMS database to defeat UPI SIM-binding** and reset UPI PINs
  without the physical SIM. *This is the sharpest India-specific technique found, and the
  existing Frida hook already covers one of its two hook points.*
- **RedHook** (Group-IB) — 53 commands; abuses **Android wireless debugging** to self-grant
  system-level privilege without rooting.
- **FatBoyPanel** (Zimperium) — ~900 samples distributed **via WhatsApp**, impersonating
  Indian government and banking apps.
- **CERT-In alert (March 2026)** — fake **e-challan / RTO** and gas-bill APK lures.
- **RTO eChallan dropper** (Feb 2026) — NP Protect packer, XOR strings, **deliberately
  corrupted ZIP with 862 entries to break apktool**, Firebase C2, 7-page Aadhaar/PAN/UPI-PIN
  funnel, **VT detection 11/66**.
- **Zimperium 2026 Banking Heist Report** — 34 active families, 1,243 institutions across
  90 countries, Android-malware-driven fraud **+67% YoY**; India among the most targeted
  with **42 targeted institutions**.
- **NFC relay** (Cleafy, 2026-05) — DevilNFC, NFCMultiPay: the emergent capability class.

## 1.5 Corpus acquired — and the India gap is CLOSED

User approved acquisition. Cloned into `corpus/malware_raw/` (gitignored; samples remain
password-zipped at rest; nothing executed).

**Actuals vs estimates:** 203 archives, **371 members**, **3.9 GB on disk** (agents estimated
1.9 GB). Free disk fell to 15 GB. Password probe with `infected`: **196/203 archives open
cleanly**; 1 genuine bad password (`MonkeyJump.zip`); 6 archives whose first member is not a
ZIP/APK (`ELF`, `MZ` PE, raw `dex\n`, `====`) — correctly identified as needing skip/special
handling. `pyzipper` installed (was in `requirements.txt`, never installed); it transparently
handles both ZipCrypto and AES members.

### ⭐ Finding B9 — the corpus contains genuine India-targeted samples

Contradicting Finding B5's conclusion for the *acquired* corpus, manifest parsing found:

| Archive | Package | Label | Perms | Significance |
|---|---|---|---|---|
| `novTargetedIndianBanks.zip` | `com.sbi.complaintregister` | **SBI Quick Support** | 9 (5 high-risk) | **Direct State Bank of India impersonation** |
| `fakeAarogyaSetu.zip` | `yps.eton.application` | Aarogya Setu - AddOn | 32 | Indian gov app impersonation |
| `fakeAarogyaSetu.zip` | `cmf0.c3b5bm90zq.patch` | **Aarogya Setu** | **51** | Indian gov app impersonation |
| `fakeAarogyaSetu.zip` | `com.android.tester` | **Aarogya Setu** | **51** | Indian gov app impersonation |
| `mayJioTarget.zip` | `vaccine.india.cororegister` | Vaccine Register | 12 | India COVID-vaccine lure |

The SBI sample's high-risk permissions are `READ_SMS`, `RECEIVE_SMS`, `SEND_SMS`,
`READ_PHONE_STATE`, `RECEIVE_BOOT_COMPLETED` — **the proposal's exact "SMS trifecta" plus
persistence**, on an app calling itself "SBI Quick Support".

**The project finally has real positive test cases for its stated differentiator.**

### 🔴🔴 Finding B10 — L0 impersonation detection MISSES ALL OF THEM

All 8 India-targeted samples were run through `L0/ingest.py`. Every single one:

```
verdict: unknown | matched_bank: None | findings: 0
```

**An APK named "SBI Quick Support", packaged `com.sbi.complaintregister`, requesting the SMS
trifecta, produces zero impersonation findings.** This is the flagship capability, and it
fails on the first real Indian bank clone it has ever been shown.

Six independent root causes, all verified:

| # | Root cause | Effect |
|---|---|---|
| **RC1** | **All 39 whitelist entries have `icon_phash: null`** | The icon perceptual-hash check — a headline README feature — **can never fire.** There is nothing to compare against. |
| **RC2** | **All 39 entries have `cert_sha256: null`** | The positive cert-whitelist match (`+0.9` strong trust) **can never fire.** |
| **RC3** | **`extract_cert_info()` is broken on androguard 4.x** — see B11 | `self_signed` / `debug_signed` are `None`, so the self-signed and debug-signed red flags never fire either. |
| **RC4** | Package matching is **exact equality only** (`pkg == manifest["package_name"]`) | `com.sbi.complaintregister` vs whitelisted `com.sbi.lotusintouch` share the `com.sbi` vendor prefix — a screaming signal — and it is never compared. |
| **RC5** | Label similarity uses `difflib.SequenceMatcher` against `app_label` + `alt_labels` | "SBI Quick Support" vs "YONO SBI" scores far below the 0.9 threshold. |
| **RC6** | The substring fallback tests `bank_name` (`"state bank of india"`) against the label | Fails. **Nothing anywhere checks for the token `SBI`.** Brand *tokens* are never extracted from `bank_name`. |

Net: of the four advertised impersonation signals (package, label, icon, certificate),
**two are inert for want of reference data (RC1, RC2), one is broken by a code defect (RC3),
and the remaining one is too brittle to match a real clone (RC4–RC6).**

### 🔴 Finding B11 — certificate extraction is broken (systemic, 100% failure rate)

`L0/ingest.py:extract_cert_info` line ~167:

```python
der_bytes = cert.public_bytes(encoding=__import__("cryptography").x509.base.serialization.Encoding.DER)
```

androguard 4.x's `apk.get_certificates()` returns **`asn1crypto.x509.Certificate`** objects,
which have **no `.public_bytes()`** method. Verified directly:

```
get_certificates() -> 1 certs; type: Certificate
has .public_bytes? False | has .dump()? True
!! ingest expression FAILS: AttributeError 'Certificate' object has no attribute 'public_bytes'
```

The `except` branch then calls `get_certificates_der_v2()`, which succeeds — so `present` and
`sha256_fingerprint` get set and the failure is **silent**, while `issuer`, `subject`,
`self_signed` and `debug_signed` stay `None`.

The correct asn1crypto API works and yields the right answer:

```
.dump() -> sha256 94b02bc7b318a5c4591d9529…
issuer  : OrderedDict({'common_name': 'Android Debug', …})
subject : OrderedDict({'common_name': 'Android Debug', …})
self_signed : True
```

**The SBI-impersonating sample is both self-signed AND `Android Debug`-signed.** Under
correct extraction it would trigger `cert_weight = -0.5` plus a **high**-severity
`debug_signed` finding — "APK signed with Android debug key, not intended for release" — on
an app claiming to be State Bank of India. That is a textbook critical impersonation red
flag, and it is being dropped by a one-line API mismatch.

> **Consequence for planning:** Phase A's scope must expand. L0 impersonation hardening
> (RC1–RC6 + B11) is now the **highest-value work in the project** — it is the differentiator,
> it has real positive test cases for the first time, and it currently scores 0/8.

## 1.6 Direction decision

**Confirmed build order** (user-selected, and the proponent conceded to it):

> **Phase A: spine + L1 finding quality + L0 impersonation hardening** → **L5 scoring +
> L6 minimal** → L3 (drift exhibit) → L2 → L4 threaded throughout → Ghidra last.

**Standing decisions carried forward:**
- The LLM contributes **zero points** to the score; it generates evidence and explanation only.
- The `0.45/0.30/0.25` blend is **replaced** by an auditable additive/log-odds scheme with a
  versioned YAML policy file.
- Smoking-gun override gates become the **primary** mechanism, not an override.
- Gate (iv) (dropper + embedded APK) is **rewired to statically observable evidence** — no
  network dependency.
- The mitmproxy **"response hijacking" claim is deleted, not demoted** (B-R8).
- L2 adopts `dexray-intercept` and contributes only the BFSI hook pack it lacks.
- L3 is reframed as a **generic maliciousness prior / drift-methodology exhibit**, bounded to
  ±10 points, never a verdict.
- L4 drops hierarchical summarisation (≈35–40 min/APK CPU-only); becomes **verified
  deobfuscation**, ~6–8 calls/APK, on a 3B model, with an execution verifier.
- Claim discipline: **"we encode India-specific detection logic and validate it against real
  India-targeted samples and published 2026 IOCs"** — now upgraded from aspiration to fact by B9.

---

# Part 2 — Phase A Execution

## 2.1 Plan & review

Plan: [`docs/plans/phase_a_plan.md`](plans/phase_a_plan.md). Independently reviewed →
**APPROVED WITH CHANGES.** The review measured what the plan had deferred, and found a
blocker plus several wrong assumptions. Highlights:

- **🔴 BLOCKER — the ZIP magic constant is byte-reversed.** 27 of 43 rules gate on
  `uint32(0) == 0x504B0304`. YARA's `uint32()` is **little-endian**, so a real ZIP header
  `50 4B 03 04` reads as `0x04034B50`. **The condition was always false on every APK ever
  made.** I verified independently before acting:
  ```
  first 4 bytes of pivaa.apk: 504b0304
    uint32(0)   == 0x504B0304  -> no match     (as written)
    uint32(0)   == 0x04034B50  -> MATCH        (little-endian)
    uint32be(0) == 0x504B0304  -> MATCH        (big-endian)
  ```
  **63% of the rule set was dead.** The raw-APK path had never produced a single true
  detection — 100% of its output was `scope="source"` rules leaking through.
- **The review's trap warning was the most valuable thing in it.** The plan's strongest
  predicted check (`Lumo 11 → 4`) would have been *satisfied by the failure mode*: wiring
  the scope filter makes the APK path go to zero, which looks like success but actually
  reflects 27 already-dead rules. We would have signed off, run the corpus for hours, and
  attributed the deaths to `_strip_byte_checks`. Mitigation adopted: **"the APK path must
  fire ≥1 rule on a known-good APK" is now a gate, not a discovery.**
- **Per-file scanning measured at 1.2 s** on the largest sample — 25× under the plan's 30 s
  gate, and *faster* than the batching it replaces. Two-pass cut entirely.
- **Resume-by-CRC32 is impossible**: all 148 AES members are WinZip AE-2, whose spec mandates
  `CRC-32 = 0`. The proposed key degenerates for 40% of the corpus.
- **`L0/ingest.py:run_l0` destructively truncates `evidence.json`** with `l1`…`l6` = pending
  on every run — so the spine must NOT live in `L0/artifacts/`.
- Disk fear was overstated: peak is governed by the largest single sample (~0.5 GB), not the
  corpus × blowup. Corpus runtime is ~2.5–4 h, not 90 min.
- Cut list applied: two-pass scanning, the validator package, the password-probe step
  (done: 370/371 members open), `pip install pyzipper` (done), `--keep-sources flagged`.

## 2.2 Implementation

| # | Change | Files |
|---|---|---|
| 1 | **Endianness fix** — `uint32(0) == 0x504B0304` → `uint32be(0) == 0x504B0304` (27 sites). Chose `uint32be` over `0x04034B50` because the constant then reads as the literal ZIP magic and will not be "corrected" back later. | 8 `.yar` files |
| 2 | `_strip_byte_checks` regex widened to strip `uint32be(0)`/`uint32le(0)`, else the source path breaks. | `yara_scan.py` |
| 3 | **Per-file scanning** replaces the 500-file batch blob. Root cause of the 100% benign FP rate: concatenation let `3 of ($wm*) and 2 of ($phish*) and …` be satisfied by strings scattered across unrelated files. | `yara_scan.py:scan_sources` |
| 4 | **One finding per (rule, sample)**, via a `_RuleHit` accumulator. Breadth preserved as `detail.scopes / locations / matched_string_ids / match_count / samples` — never as counts. | `yara_scan.py` |
| 5 | **`merge_findings()`** — cross-scope dedup is now *structural*: a rule firing in both source and APK scope collapses to one finding by construction, not by a fragile evidence-string comparison. | `yara_scan.py`, `l1.py`, `combo_analyze.py` |
| 6 | **APK scanning is additive** — raw container (for ZIP-structure rules) **plus** decompressed members (`classes*.dex`, manifest, `assets/`, `res/raw/`, `lib/`). The container alone is deflated and structurally near-blind. | `yara_scan.py:scan_apk` |
| 7 | **Scope filter wired into the APK ruleset** (bug N3) and `_filter_scope` taught to honour `scope = "both"` (its regex previously matched only `apk\|source`, so `both` was indistinguishable from unscoped). | `yara_scan.py` |
| 8 | **Category from rule meta**, regex catalog demoted to fallback; 5 malware-behaviour rules annotated. Previously `CLIPBOARD_HIJACK`, `NOTIFICATION_ABUSE`, `SCREEN_CAPTURE`, `PACKING`, `MESSAGING_C2` were **unreachable**. | `yara_scan.py`, 3 `.yar` files |
| 9 | **Case-insensitive severity** — 35 rules use Title Case and were silently downgraded to MEDIUM. | `yara_scan.py:_severity` |
| 10 | **jadx timeout no longer discards partial work** — `TimeoutExpired` escaped the handler that exists precisely to salvage partial output. Matters once the corpus run uses a short timeout on obfuscated malware. | `jadx_analyze.py` |
| 11 | **Combo engine survives corrupted archives** — `_run_engines` caught only `RuntimeError`; `zipfile.BadZipFile` killed the whole sample. Deliberately-corrupted ZIP structure is a documented technique in this project's own threat intel. | `combo_analyze.py` |
| 12 | **Combo summary carries jadx's forward** instead of building a fresh dict — restores `decompiled_files` on the combo track. Adds `ghidra_available/attempted/ok` + `analysis_gaps`. | `combo_analyze.py` |
| 13 | **`ruleset_version()`** — sha1 over the rule corpus, recorded in the L1 summary. | `yara_scan.py`, `l1.py` |
| 14 | **Drinik rule tuned** (see §2.3 — a critical FP found during validation). | `apk_india_banking.yar` |

## 2.3 Validation

### Regression vs the frozen baseline (`tests/baseline/pre_A2/`)

| Sample | Class | Before | After | Malware-cat |
|---|---|---:|---:|---:|
| PennyWise | benign | 10 | 6 | **0** |
| Notely | benign | 3 | 2 | **0** |
| Proton Lumo | benign | 11 | 5 | **0** |
| DuckAssist | benign | 3 | 4 | **0** |
| InsecureBankv2 | vuln | 3 | 4 | 0 |
| PIVAA | vuln | 6 | 6 | 0 |
| UnCrackable L1 / L2 | vuln | 1 / 0 | 2 / 1 | 0 |

> **A2 PASS CRITERION MET — zero malware-category findings across all four benign apps.**
> (Counts rose slightly on some samples because the endianness fix revived 27 rules and
> added member scanning; the criterion is category, not count.)

### 🔴 Finding B12 — a critical FP, caught only because the rules finally work

With 27 rules revived, **PennyWise (a benign expense tracker) matched
`Android_India_Drinik_ITR_Impersonation` at `critical` severity.** Matched strings:
`$itr2="income tax"`, `$itr5="ITR"`, `$acc1="AccessibilityService"`, `$fb2="fcm"`.

The rule's condition is `2 of ($itr*) and 1 of ($acc*) and (1 of ($drinik*) or 1 of ($fb*))`.
Its only real discriminators are the Drinik-specific strings (`LocalCapture`,
`LocksAndIntercepts`, `GAnalytics`) — but the `or 1 of ($fb*)` disjunction let the mere
*presence of the Firebase SDK* substitute for family-specific evidence, while `"ITR"`
matched any 3-character occurrence and `"AccessibilityService"` is ambient in most apps.

Fix (surgical, intent preserved): `$itr5` → `/\bITR\b/`; Firebase strings narrowed from the
**SDK** (`"firebase"`, `"fcm"`) to the actual exfiltration **endpoints**
(`firebaseio.com`, `fcm.googleapis.com`, `.firebasedatabase.app`) — which is what the threat
model actually describes. Re-verified: PennyWise 7 → 6 findings, **0 malware-category.**

### 🔴 Finding B13 — first-ever run against real banking malware: 4/8 detected

Eight real trojans, one member each, extract→analyse→delete:

| Family | Findings | Malware-cat | Categories |
|---|---:|---:|---|
| **SBI-clone** | 2 | **0** ❌ | — |
| **fakeAarogyaSetu** | 1 | **0** ❌ | — |
| **Cerberus** | 2 | **0** ❌ | — |
| **FluBot** | 6 | **0** ❌ | — |
| Anubis | 4 | 1 ✅ | `screen_capture` |
| SharkBot | 6 | 1 ✅ | `clipboard_hijack` |
| TeaBot | 8 | 1 ✅ | `screen_capture` |
| AlienBot | 5 | 1 ✅ | `native_payload` |

**Detection went 1/8 → 4/8 purely from the category annotation** — `Android_Clipboard_Hijacker`
and `Android_Screen_Recording_RAT` were firing correctly all along but resolving to `other`,
so true positives were invisible. That is a measurement bug, not a detection bug, and it was
concealing real capability.

**The remaining 4/8 gap is genuine and is the top open problem.** Cerberus, FluBot, the SBI
clone and fake Aarogya Setu produce *only* findings that benign apps also produce
(`Android_Dynamic_CodeLoading`, `Android_WebView_*`, `Android_Secrets_Hardcoded`). **On today's
L1 output those four are indistinguishable from a note-taking app.** The India-specific rules
did not fire on the India-targeted samples.

> This is precisely the measurement the project has never been able to make. It is now the
> input to rule tuning, and it is exactly what A4's rule-firing report is for.

---

## 2.4 Workstream A6 — L0 impersonation hardening

Planned separately (new scope arising from B10/B11), reviewed independently. Planning
surfaced six further verified findings, renumbered here to avoid collision with B12/B13.

### Finding B14 — package + label match alone grants `verdict: trusted`

`L0/ingest.py:impersonation_check` lines 251-252:
```python
if pkg_match and label_sim >= 0.9:
    matched_bank = bank.get("bank_name")   # -> verdict "trusted"
```
A sideloaded APK that copies `com.phonepe.app` **and** the label "PhonePe" is marked
**trusted with no certificate verification whatsoever.** Package name is attacker-controlled
for sideloaded APKs. This is worse than the B10 false negatives: the system does not merely
miss the clone, it **actively vouches for it.**

### Finding B15 — icon extraction was broken for a second, independent reason

`extract_icon_phash` called `apk.get_app_icon()`, whose default `max_dpi=65536` selects the
`anydpi-v26` **adaptive-icon binary XML** in preference to any raster. PIL cannot decode it,
and the `except` swallowed the failure into `icon.error`. **Fixed** with a dpi ladder
(640 → 480 → 320 → 240 → 160 → 65536), taking the first decodable raster.

**Result: 8/8 India samples now yield a perceptual hash, up from 3/8.** The SBI clone went
from `phash: None` to `d0f60f993b26292e`.

### Finding B16 — populating `icon_phash` would detect nothing on this corpus

Minimum pHash distance between genuine bank icons and any India-sample icon is **22**,
against a threshold of **8**. These clones do not copy the icon; they copy the *name*.

This demotes the icon workstream from detection work to **honesty/coverage work** — the
README claims a capability that currently cannot fire. Threshold 8 is confirmed safe with
large headroom (closest unrelated pair anywhere in the corpus is 12).

### Finding B17 — 22 of 39 whitelist package names do not exist

Probing all 39 Play Store listings: 17 resolve, **22 return HTTP 404** — including HDFC,
Axis, Kotak, PNB, Indian Bank, IOB, UCO, IndusInd, Yes, IDBI, RBL, DigiLocker, Income Tax.
**The whitelist compares against fabricated identifiers.** Any vendor prefix derived from
them would be a false-positive generator. Correcting these requires analyst confirmation and
must not be automated.

### Finding B18 — `self_signed` is a ~100% base-rate flag

All 17 analysed APKs are self-signed, including all four benign apps. **Every** Android APK
is self-signed; that is how the platform works. The flag is recorded but must carry **weight
zero on its own** — only the conjunction of a brand claim and an anomalous signer matters.

### ⭐ Finding B19 — certificate anomalies are the real differentiator: 8/8 vs 0/4

Rewriting cert extraction correctly (`L0/certinfo.py`, replacing the broken
`cert.public_bytes` path of B11) and classifying signer anomalies gives, **measured**:

| Sample | Anomalies (excluding `self_signed`) |
|---|---|
| `com.sbi.complaintregister` "SBI Quick Support" | `debug_keystore` (CN=Android Debug) |
| 4× fake Aarogya Setu | `aosp_test_key` (CN=O=Android, notBefore **2008-02-29**) |
| 3× mayJioTarget | `debug_keystore`, `empty_dn` (subject = `{country_name: "debugging"}`), `absurd_validity` (**999 years**) |
| PennyWise · Proton Lumo · Notely · DuckAssist | *none* |
| InsecureBankv2 · UnCrackable L1/L2 | *none* |
| PIVAA | `debug_keystore` — **genuine true positive** (really is CN=Android Debug) |

```
*** 8/8 India malware flagged | 0/4 benign false positives ***
```

**This is the strongest detection result in the project**, and it needs no reference data at
all — unlike the icon and cert whitelists, which are empty (B16, RC1/RC2). It generalises:
it keys on properties no legitimate publisher ever ships, rather than on a list of known
brands.

### Finding B20 — an FP caught during implementation

First implementation flagged **duckAssist** (benign) with `placeholder_dn`. Cause: its cert
carries `state_or_province_name: "Unknown"` and `locality_name: "Unknown"` — the values
`keytool` writes for unspecified *geographic* fields, entirely normal on self-generated
certs. Fix: restrict placeholder matching to **identity-bearing** attributes
(`common_name`, `organization_name`) and drop the over-broad `"test"`/`"none"`/`"na"`
tokens. Re-verified: 0/4 benign FPs.

### A6 implementation status

| Item | Status |
|---|---|
| `L0/certinfo.py` — correct asn1crypto API, per-scheme coverage, loud failure, anomaly classification | ✅ landed |
| `extract_cert_info` re-exported from `ingest.py` for backwards compatibility | ✅ landed |
| `extract_icon_phash` dpi ladder + dHash + `attempted_sources` | ✅ landed |
| Brand-token matching (RC5/RC6), package similarity (RC4), verdict decision table (B14) | ✅ landed |
| Whitelist v2 schema + curated `brand_tokens` for 39 entities + Aarogya Setu added | ✅ landed |
| Icon reference population, cert blocklist, substring matching, `cert_scheme_mismatch` | ❌ **cut by review** |

### A6 review outcome — APPROVE WITH CHANGES, and a blocker I had introduced

The review confirmed all six planning claims and then caught a **regression created by my
own B11 fix**:

> **🔴 Fixing the certificate bug armed a branch that had never executed, and it
> immediately produced a `critical` false positive on a benign app.**

`impersonation_check` gated bank-impersonation on
`_best_label_sim(app_label, bank) >= 0.6`. `difflib.SequenceMatcher("duckassist",
"iassist")` = **0.706**, and `"iAssist"` is an Income Tax alt-label. Before B11,
`self_signed` was always `None`, so the branch was dead code. After B11 it fired:

```
org.diekaiju.duckassist_245.apk   suspicious   ['critical: self_signed_bank_impersonation']
```

Measured, the gate fired on **0/8 India samples and 1/4 benign** — precision zero on the
target class. This is the same class of trap as Phase A's `_SEV_MAP` ordering hazard: a fix
that switches on previously-unreachable logic. **Freeze the benign baseline before touching
a detector** is now a standing rule (`tests/baseline/pre_A6/`).

Other review corrections adopted:
- **Substring/compact matching cut** — over 110 (package,label) pairs it produced 1 false
  positive (`"BOI Mobile"` compacts to `boimobile`, which contains ICICI's `imobile` — a
  cross-brand FP *inside the reference data*) and **0 unique true positives**.
- **Cert blocklist cut** — marginal detection exactly zero; all three malicious signer
  certs are already caught by the DN anomaly rules, which also removes the only place
  corpus labels would have leaked into the detector.
- **Icon reference population deferred** — the review's decisive control: *a genuine app's
  Play-listing icon does not match its own APK icon* (Lumo 16, Notely 30, PennyWise 26, all
  ≫ threshold 8). Web-sourced references cannot be compared to APK-extracted foreground
  layers at any threshold. Non-functional as designed, not merely low-yield.
- **`vendor_claiming_dn` added** — a self-signed cert naming a major device vendor is a lie
  by construction. Closes AlienBot (`CN=Android, O=Google Inc.`) at zero benign cost.
- **`weak_key` in, `cert_scheme_mismatch` out** — the latter flags Notely and Lumo, which
  are correctly v2-only with no v1 signature.

### ⭐ A6 measured outcome

Full inventory: 8 India-targeted + 13 other malware + 4 benign + 4 vuln + 56 dataset metas.

| Class | n | Flagged | Critical |
|---|---:|---:|---:|
| **India-targeted malware** | 8 | **8/8** | 5 |
| Other malware | 13 | 12/13 | 0 |
| **Benign** | 4 | **0/4** ✅ | 0 |
| Vuln-training | 4 | 1/4 (PIVAA, genuine `CN=Android Debug`) | 0 |
| Dataset metas (brand matcher) | 56 | 0 brand claims | — |

Representative output — the demo beat:

```
novTargetedIndianBanks  SBI Quick Support   impersonation_likely
    high: cert_debug_keystore   critical: brand_impersonation
fakeAarogyaSetu         Aarogya Setu        impersonation_likely
    high: cert_aosp_test_key    critical: brand_impersonation
```

**From `verdict: unknown`, 0 findings on all 8 → 8/8 flagged with an attributed entity and
a stated reason.** Regression vs `tests/baseline/pre_A6/`: **0 benign regressions**; the
duckAssist false positive is gone.

### Finding B21 — environment reproducibility broke mid-session

`python3` resolved to a pyenv 3.10 shim without androguard/yara/imagehash/pyzipper; the
working interpreter is `/usr/bin/python3.13`. `source_env.sh` still carried another
machine's absolute paths (backlog item I3) and could not help. **Rewritten** to derive all
paths from its own location and to probe for an interpreter that can actually import the
dependencies, exporting `$SENTINEL_PYTHON`.

---

# Part 3 — Workstream A1 — The Evidence Spine (2026-08-08)

Plan of record: [`docs/plans/phase_a_plan.md`](plans/phase_a_plan.md) §A1, as amended by the
review recorded in §2.1. A1 was the last unbuilt piece of the foundation: the proposal's
central architectural claim ("every stage appends to a single Evidence JSON record") and the
contract every layer from L3 up is specified against. Until now it was fiction — L0, L1 and
L2 wrote three disconnected files and nothing merged them.

## 3.0 🔴 Finding B22 — the environment broke again, and this time silently

Before any A1 work could run: **`/usr/bin/python3.13` no longer exists.** Fedora moved to
Python 3.14 and the interpreter that held androguard / yara-python / imagehash / pyzipper
went with it. No interpreter on the machine could import the dependencies.

The failure mode was worse than the outage. `source_env.sh`'s probe loop fell through to
`export SENTINEL_PYTHON="${SENTINEL_PYTHON:-python3}"` and **printed
`APK Sentinel environment ready`** over a Python that could not import androguard. B21's fix
made the path derivation portable but left the fallback silent.

**Fixed two ways.** A repo-local `env/` venv on 3.14 now holds every dependency — the only
interpreter this repo controls, immune to the next distro upgrade — and `source_env.sh`
already prefers it. The bare-`python3` fallback now prints a loud warning with the rebuild
command instead of claiming success. *A green "ready" banner over a broken environment is a
worse defect than a red one.*

## 3.1 Implementation

| # | Change | Files |
|---|---|---|
| 1 | **`spine.py`** — schema `apk-sentinel-0.2` at a **new top-level `artifacts/<sha256>/evidence.json`**. Not under `L0/artifacts/`: `run_l0` rewrites that file wholesale on every run (T10), so a spine stored there is destroyed by the next L0 run. | `spine.py` (new) |
| 2 | **`LayerStatus`** — `not_attempted` / `running` / `complete` / `partial` / `failed` / `skipped`. `pending` is gone; it could not distinguish "never ran" from "running". `partial` earns its place immediately: every combo-track sample lands there because Ghidra is absent. | `spine.py` |
| 3 | **Single writer.** `update_layer()` does read → merge-this-layer-only → atomic write (`tempfile` + `os.replace` + `fsync` of file *and* directory). L1 never read-modify-writes a file L0 owns. A cooperative lock file covers the other half of the race — two processes each writing back a document missing the other's layer. | `spine.py` |
| 4 | **Dual finding identity.** `id` = ordinal `F001`… after a deterministic sort over `(layer, −severity, category, engine, finding_key)`; `fingerprint` = `sha1(finding_key)[:12]`. The discriminator is the **detector** (YARA rule name), not the matched text — so re-tuning a rule's strings does not re-identify its finding, while renaming the rule does. | `spine.py` |
| 5 | **L0 promotion — the highest-value item in A1.** `L0/promote.py` lifts `l0.impersonation.findings` and the certificate signals into the unified array with `engine="l0_impersonation"`. Promotion is lossless: the original L0 record rides along verbatim in `detail.l0_finding`. | `L0/promote.py` (new) |
| 6 | **`Category.CERTIFICATE_ANOMALY`** added. Signer anomalies were the only route left to `other`, which is exactly how T12 hid five real categories. Its MITRE list is **deliberately empty** — no ATT&CK Mobile technique cleanly describes an anomalous *signer*, and a plausible-looking unverified ID is the kind of claim this project does not make. | `L1/schema.py` |
| 7 | **Coverage and gaps first-class.** Per-layer `coverage` blocks plus a flat top-level `analysis_gaps`. Gaps are contributed by layers *and derived*: an evidence layer that never ran emits one automatically, so a never-attempted detonation shows up as `detonation_not_attempted` rather than as silence. **This is the mechanism that turns a failed detonation into an honest confidence penalty.** | `spine.py` |
| 8 | **L1 failure is recorded, not dropped.** `dispatch()` writes `status: failed` with the exception before re-raising. A sample missing from the spine is indistinguishable from one never attempted; a corpus run would have under-reported its own coverage. | `L1/l1.py` |
| 9 | Wiring: `run_l0` and `dispatch` each fold themselves in after writing their own artifact. Layer-local files are unchanged, so every existing reader still works. | `L0/ingest.py`, `L1/l1.py` |
| 10 | Debug tools surface the spine — `inspect_evidence` lists it first, `summarize_results` prints the unified findings with their evidence IDs and MITRE mappings. | `tools/debug/*` |

### 🔴 Finding B23 — I widened a frozen measurement without noticing

`spine.MALWARE_CATEGORIES` (the machine-readable form of the A2 benign pass criterion) was
first written with **14** categories. The criterion recorded in the plan and used for every
before/after number in §2.3 is **9**. The extra five — `packing_obfuscation`,
`notification_abuse`, `screen_capture`, `messaging_c2`, `certificate_anomaly` — would have
silently redefined the metric, and PIVAA immediately showed the consequence: it registered
`malware_category = 1` purely because it is genuinely debug-signed.

Corrected to exactly the nine, with the constant carrying an explicit warning that widening
it requires a re-baseline. Certificate anomalies are now counted on their **own line**
(`counts.certificate_anomaly`) — they are simultaneously the strongest measured India-malware
discriminator (8/8 vs 0/4) *and* a property of a legitimate debug-signed training app, which
is precisely why they belong in neither bucket.

> **The general trap:** a metric defined in prose and re-implemented in code later is a metric
> that will drift. The re-implementation must be pinned by a test — `tests/test_spine.py`
> now asserts the exact nine-element set.

## 3.2 Validation

Environment rebuilt, then **L0 + L1 re-run over all 8 local samples**.

### A1 changed no detection (it is plumbing, and must behave like it)

Diffed every L1 `analysis.json` against a pre-A1 snapshot: **0 samples drifted** — identical
rule sets and identical counts (Notely 2, PennyWise 6, Lumo 5, DuckAssist 4, InsecureBankv2 4,
PIVAA 6, UnCrackable L1 2, L2 1). The only intended output change is `mitre_techniques` on
`phishing_impersonation`, which gained `T1655` (Masquerading) alongside `T1660`.

### The spine reconciles

| Sample | L0 findings | L1 findings | Spine | mal-cat | l0 | l1 | gaps |
|---|---:|---:|---:|---:|---|---|---|
| Notely | 0 | 2 | 2 | 0 | complete | partial | detonation, ghidra |
| PennyWise | 0 | 6 | 6 | **0** | complete | partial | detonation, ghidra |
| Lumo | 0 | 5 | 5 | 0 | complete | partial | detonation, ghidra |
| DuckAssist | 0 | 4 | 4 | 0 | complete | complete | detonation |
| InsecureBankv2 | 0 | 4 | 4 | 0 | complete | complete | detonation |
| PIVAA | 1 | 6 | 7 | 0 | complete | complete | detonation |
| UnCrackable L1 / L2 | 0 / 0 | 2 / 1 | 2 / 1 | 0 | complete | complete / partial | detonation (+ghidra on L2) |

Spine count equals L0 + L1 findings for **8/8** samples. Ordinals contiguous `F001…Fnnn`,
fingerprints unique, and the string `pending` appears **nowhere** in any spine.
**A2 pass criterion re-verified through the spine: 0 malware-category findings on all four
benign apps.**

### ⭐ The India differentiator now carries evidence IDs

Re-ran L0 over the 8 India-targeted samples straight from the encrypted corpus (one member at
a time, magic-byte APK detection, extraction deleted in a `finally`, `corpus/_work` residue
verified **0**). This reproduces the A6 outcome and, for the first time, gives it citable IDs:

```
novTargetedIndianBanks  SBI Quick Support     impersonation_likely  → State Bank of India
    F001 [critical] phishing_impersonation  brand_impersonation
    F002 [high]     certificate_anomaly     cert_debug_keystore
    smoking_gun_inputs: brand_claim=True, sms_trifecta=True,
                        cert_anomalies=[debug_keystore, vendor_claiming_dn]

fakeAarogyaSetu (×4)    Aarogya Setu          impersonation_likely  → Aarogya Setu
    F001 [critical] phishing_impersonation  brand_impersonation
    F002 [high]     certificate_anomaly     cert_aosp_test_key
    F003 [high]     phishing_impersonation  label_spoof            (3 of the 4)

mayJioTarget (×3)       Vaccine Register /    impersonation_suspected
                        Registerlaptop
    F001 [high]     certificate_anomaly     cert_debug_keystore
    smoking_gun_inputs: cert_anomalies=[debug_keystore, empty_dn, absurd_validity]
```

**8/8 flagged, 5 critical — every finding now addressable as `F00n`.** Before A1 the
bank-impersonation hit existed only inside a nested L0 blob: L5 had nothing to score and L6
had nothing to cite. `smoking_gun_inputs` rides in `layers.l0.summary`, which is the literal
input to L5's override gates.

> **Caveat, stated plainly:** the malware `L0/artifacts/` on disk were **stale** — written
> 2026-08-07, before A6, still showing `verdict: unknown` on all 8. Backfilling spines from
> them would have recorded a pre-A6 picture as current. They were regenerated from the corpus
> instead. *An artifact directory is not a source of truth unless its provenance is checked.*

### Test suite

`tests/test_spine.py` — **28 tests, all passing** (`./env/bin/python -m pytest tests/ -q`).
Beyond the plan's list, two are worth naming: the atomicity test **actually `SIGKILL`s a child
process mid-write** and asserts the previous spine survives byte-for-byte; and the insertion
test asserts ordinals shift while fingerprints hold, which is the entire justification for
carrying two identities.

## 3.3 Open after A1

1. **L1 detection gap is untouched** — 4 of 8 real banking trojans still produce only findings
   benign apps also produce. A1 does not address it and was never meant to. Highest-priority
   detection work.
2. **The spine has no L2–L6 producers yet.** The contract is exercised by two layers; the
   `partial`/`failed` paths are unit-tested but not yet driven by a real L2.
3. **A3 corpus runner** is now unblocked and is the next planned step — with A1 landed, a
   corpus run produces spines that A4 can consume directly.
4. `iter_spines()` exists as A4's entry point but has no consumer yet.

---

# Part 4 — Workstream A3 — The Corpus Runner (2026-08-09)

Plan of record: [`phase_a_plan.md`](plans/phase_a_plan.md) §A3, amended before implementation
by [`phase_a3_amendment.md`](plans/phase_a3_amendment.md). The amendments were measured, not
reasoned: two of them would have caused the run to fail partway through.

## 4.1 Plan amendments (measured before writing code)

| # | Amendment | Evidence |
|---|---|---|
| **M1** | **The corpus is 699 candidates, not ~355.** The plan's N5 table counts only zip members and missed 328 loose APKs in `android-malware/`, 32 of which are not `.apk`-named. Running zips only would have silently analysed half the corpus — the exact failure the plan warned about for extensions, one level up. | Direct enumeration |
| **M2** | 🔴 **Disk is governed by decompiled sources, not samples.** 8 samples produced **897 MB** of `jadx_src` (~112 MB each). Projected over 699: **~78 GB against 16 GB free** — death around sample ~140. The plan's `--keep-sources` governs the 1.45 GB of *samples*, which was never the constraint. `jadx_analyze` even caches `jadx_src` deliberately, so nothing ever reclaimed it. | `du -sh L1/artifacts` |
| **M3** | **`--jobs N` cut.** M2 makes disk *more* binding than the plan assumed, so parallelism multiplies the peak for no gain — jadx already runs `-j 4` internally. Shipping the flag would hand the user a way to worsen the one real constraint. | — |
| **M4** | Resume key restated: `(zip_relpath, member_name)`, **unique across all 371 members** and readable from the central directory without decrypting. Confirms T13 by measurement — exactly the 148 AES members have `CRC == 0`. | Central-directory scan |
| **M5** | **The extension trap runs both ways.** 157/371 members extensionless; 32 loose ZIP-magic files not named `.apk`; **4 loose files named `.apk` that are not archives at all**; 7 ZIP-magic files with no manifest+dex. Acceptance is magic + `AndroidManifest.xml` + `classes*.dex`, and every rejection is recorded with a reason. | Enumeration |

> M2 is the one that matters. The plan *observed* the 20× blowup and still wrote its disposal
> policy about samples. **Noticing a number and wiring it to the right control are different
> acts.**

## 4.2 Implementation

`tools/corpus_run.py` — one member at a time, never `extractall`; loose APKs analysed **in
place** (they are the corpus at rest, not an extraction, so they are neither copied nor
deleted); `corpus/_work/` not `/tmp`; deletion in a `finally` owned by the function that
created the tree; free-space guard; append-only `run_log.jsonl` fsynced per record; atomic
resume index; **no execution, enforced by construction**.

Supporting changes: `harvest_dataset.open_encrypted()` is now the shared pyzipper→stdlib
ladder (and `unpack_and_harvest` is marked superseded, with its three silent defects
documented in the docstring); jadx timeout is configurable via `SENTINEL_JADX_TIMEOUT` so it
reaches the engine through the combo track; **partial decompilation is now recorded as a
`decompilation_partial` coverage gap** instead of passing as complete; androguard's loguru
sink is silenced for batch runs (backlog I2).

`tools/corpus_summary.py` reports a run's coverage, verdicts and detection gap. It refuses to
imply discrimination: every sample is malware, so there is no benign denominator.

Tests: `tests/test_corpus_run.py`, **18 tests** on synthetic fixtures — both directions of the
extension trap, rejection-always-carries-a-reason, resume-key uniqueness and CRC-independence,
`materialise` extracting exactly one member, loose samples never copied, and a test that pins
the AE-2 `CRC == 0` measurement so the resume key is never "improved" back onto it.
**46 tests pass overall.**

## 4.3 The run

**705 samples in 56.8 minutes (4.8 s/sample).** 651 ok · 27 skipped · 27 errors.
Disk started at 12.8 GB free and **ended at 13 GB** — flat, as M2 predicted. Corpus
unchanged afterwards (2.0 GB, 307 loose APKs intact, **0 files executable**), `corpus/_work`
removed, and every corpus `jadx_src` reclaimed. 639 distinct SHA-256 from 705 records — the
sha-keyed spine deduplicates repackaged samples across archives by construction.

### ⭐ Finding B24 — the corpus contains **12** India-targeted samples, not 8

A3 found **four previously undocumented ICICI Bank impersonators**, all `impersonation_likely`
with a named entity and a stated reason:

| Archive | Label | Package | Signer | SMS trifecta |
|---|---|---|---|---|
| `AndroidMalware_2021/sepTaxPayer.zip` | **iMobile** | `direct.uujgiq.imobile` | debug keystore + vendor-claiming DN | **yes** |
| `AndroidMalware_2022/Sep_infoStealer.zip` ×3 | **ICICI Rewards** | `com.example.test_app` | AOSP test key / debug keystore | no |

`iMobile` is ICICI Bank's actual app brand, and `direct.uujgiq.imobile` squats it in a
namespace ICICI does not own — caught by `package_brand_segment`, with `label_spoof` and a
cert anomaly alongside, and the SMS trifecta present. The `Sep_infoStealer` trio ship under
**`com.example.test_app`** — the unmodified Android Studio template package — while labelling
themselves *ICICI Rewards*.

**This upgrades the project's central claim from 8 India-targeted samples to 12, across three
impersonated entities (Aarogya Setu, ICICI Bank, SBI) plus the Jio/vaccine lures.** It is also
the first result produced *by* the pipeline rather than by hand-picking known archives — which
was the entire point of building A3.

### 🔴🔴 Finding B25 — the detection gap is **92%**, not 50%

| | |
|---|---:|
| Known-malware samples analysed | 651 |
| With ≥1 **malware-category** finding | **50 (8%)** |
| Characterised *only* by hygiene/structural rules | **601 (92%)** |

Every sample here is known malware, so 92% is a **false-negative rate for the malware-category
rule set** on this corpus. The previous estimate — "4 of 8 real banking trojans undetected"
(50%, Finding B13) — was drawn from 8 hand-picked samples and was **optimistic by a factor of
nearly two**. `other` (OWASP/hygiene rules) fires on 651/651; the malware-behaviour categories
fire on almost nothing:

```
native_payload 18 · screen_capture 12 · data_exfiltration 11 · overlay_attack 6
clipboard_hijack 4 · evasion 1 · notification_abuse 1 · c2_communication 1
```

`sms_intercept`, `ransomware`, `accessibility_abuse` and `packing_obfuscation` fired on
**zero** samples across the entire corpus. For a corpus of banking trojans and SMS stealers,
zero `sms_intercept` is not a threat-landscape observation — it is a broken rule class.

> This is now the project's **single highest-priority defect**, and A4's per-rule report is
> the instrument for fixing it. Caveats that stand: corpus vintage is 2020–2022, and with no
> benign denominator none of these are discrimination rates.

### 🔴 Finding B26 — 25 samples (3.8%) are lost to a single androguard parser error

All 27 errors but two are `ResParserError: UTF-16 String is not null terminated!` — androguard
failing on malformed resource tables. Malformed resources are a *documented anti-analysis
technique*, so this is not an incidental parse failure: it is an evasion the pipeline
currently loses to, silently, at the very first layer. The remaining two are one truncated
resource buffer and one archive whose password is not `infected`
(`Users/twyatt/MonkeyJump…` — a mis-packed member, not a corpus-wide password problem).

### Coverage — what the pipeline could not see

| Gap | Samples |
|---|---:|
| `detonation_not_attempted` | 651 / 651 (L2 is dead — T14) |
| **`decompilation_partial`** | **259 / 651 (40%)** |
| `ghidra_unavailable` | 147 / 651 (23% carry native libs) |
| `icon_not_extracted` | 18 / 651 |

**40% of the corpus does not fully decompile inside 180 s.** This is a new number — the gap
only exists because A3 added `decompile_complete` tracking. It interacts directly with B25:
part of the 92% may be findings that were never reachable because the source was never
produced. **A4 must separate "rule did not fire" from "code was never decompiled", or it will
calibrate weights against samples the scanner never actually read.** Whether 180 s is simply
too short is an open, measurable question.

### L0 triage across the corpus

| Verdict | Samples |
|---|---:|
| `unknown` | 294 (45%) |
| `suspicious` | 282 (43%) |
| `impersonation_suspected` | 67 (10%) |
| **`impersonation_likely`** | **8 (1.2%)** |

L0 says nothing at all about 45% of known malware — expected and correct, since L0 only reads
*manifest-declared identity* and most of this corpus impersonates nothing (adware, botnets,
non-India trojans). The impersonation detector is precise, not broad, by design.

## 4.4 Open after A3

1. **B25 — the 92% false-negative rate** is now the top priority, ahead of L2 and L3.
2. **B26 — androguard resource-parser robustness**; 3.8% of any corpus is lost at L0.
3. **The 40% partial-decompilation rate** must be understood before A4's weights mean anything.
4. A4 is unblocked: 648 spines are on disk and `spine.iter_spines()` reads them.
5. The benign denominator is still **4 apps**. A4 can compute honest weights only for rules
   that fire; every weight it emits will be marked unsupported at `n_benign = 4`.

---

# Part 5 — Workstream B1 — Closing the Detection Gap (2026-08-09)

Analysis: [`docs/plans/detection_gap_analysis.md`](plans/detection_gap_analysis.md).
Scope approved: the targeted scan-target fix **and** rewriting the `sms_intercept` /
`accessibility_abuse` rule classes.

## 5.0 Answering the standing question: no model has been trained

There is no `L3/` directory, no model artifact of any kind on disk, and neither
`scikit-learn` nor `xgboost` is installed. **The 92% false-negative rate was produced
entirely by the YARA rule set.** No ML component exists in the pipeline to blame or credit.

## 5.1 Root cause

### 🔴 Finding B27 — the rule set was structurally blind to the dex

Every malware-behaviour rule carried a container gate,
`filesize < N MB and uint32be(0) == 0x504B0304`. There are three places the scanner looks and
the gate is fatal in all three:

| Scan target | ZIP magic | Behaviour strings | Result |
|---|---|---|---|
| Raw APK container | ✅ passes | ❌ deflated, invisible (T3) | cannot match |
| `classes*.dex` | ❌ **fails** (`dex\n035`) | ✅ **plaintext** | **short-circuits false** |
| Decompiled `.java` | gate stripped | scattered across files | see B28 |

Proved directly on the ICICI `iMobile` clone. `SmsManager`, `createFromPdu`,
`getMessageBody` and `sendTextMessage` are all present in its dex. The same trivial rule:

| Target | `uint32be(0)==0x504B0304 and 2 of them` | `2 of them` |
|---|---|---|
| container | False | False |
| **classes.dex** | **False** | **True** |

`scan_apk` used the **container ruleset for the member pass**, so the gate applied to members
that can never satisfy it. T1 had turned a never-true condition into one true only on the
container — where the strings cannot be read. The rule set went from dead to blind.

### Not the cause: decompilation

Detection was 5% on fully-decompiled samples and **12% on partial** — higher, not lower. The
leading hypothesis was rejected by the data.

## 5.2 🔴 Finding B28 — the first fix reintroduced T2's false positives, one level down

Stripping the gates and scanning the whole dex doubled apparent detection (30% → 60% on a
60-sample probe) — and immediately produced false positives on the benign set:

```
PennyWise (expense tracker) → Android_India_SMS_OTP_Stealer
                            → Android_Ransomware_Generic_File_Encryption
Notely (note app)           → Android_Spyware_Keylogger_Credential_Theft
```

**A `classes.dex` is the whole application concatenated, third-party SDKs included.**
Scanning it as one buffer is exactly the batch-blob defect T2 fixed for Java sources —
`2 of ($sms*) and 1 of ($exfil*)` satisfied by strings in unrelated library code.

> **That 60% was never real.** It was the same mechanism that produced the false positives,
> measured on malware where nothing flagged it as wrong. The benign gate is what exposed it —
> the third time in this project (T7, B12, now B28) that arming a dormant code path produced
> an immediate false positive.

**Resolution: one buffer per dex class.** A class is the dex-level equivalent of a source
file, so conjunction means "in the same class" again. Library namespaces are dropped with the
same exclusion list the source path uses.

**Then recall collapsed to 2%** — because the first per-class buffer held only class/method
names and `const-string` operands. The rules key on API references, which a dex stores as
*invoke operands*, not string literals. Measured on the ICICI sample:

| Buffer content | SmsManager | createFromPdu | getMessageBody | sendTextMessage |
|---|---|---|---|---|
| names + const-string | ✗ | ✗ | ✗ | ✗ |
| **+ invoke/field operands** | ✓ | ✓ | ✓ | ✓ |

With invoke operands the APIs resolve **inside the malware's own classes**
(`direct/uujgiq/imobile/Rnaneeli` holds both `createFromPdu` and `getMessageBody` — a genuine
SMS interceptor), which is precisely the co-location a multi-group condition needs.

## 5.3 The BFSI rule set — authored from measurement, not imagination

Mined per-class API co-occurrence over 50 malware and 4 benign apps before writing anything:

| Primitive | Malware | Benign |
|---|---:|---:|
| `sms_send` | 15/50 | **0/4** |
| `overlay` | 18/50 | **0/4** |
| `pkg_enum` | 19/50 | **0/4** |
| **`accessibility`** | 32/50 | **4/4** ⚠ |

> **`AccessibilityService` appears in 4 of 4 benign apps.** It is a ~100% base-rate token
> exactly like `self_signed` (T6) and carries no information alone. Any accessibility rule
> keyed on it alone fires on every benign app that ships an accessibility helper. Every rule
> in the new file therefore requires a *combination* observed in malware classes and no benign
> class — `accessibility + overlay` (7/50, 0/4), `sms_read_cp + sms_send` (12/50, 0/4),
> `sms_abort + sms_recv` (2/50, 0/4).

`L1/yara_templates/apk_bfsi_primitives.yar`, 8 rules. Strings are bare method names so they
match **both** representations (`Landroid/...;->sendTextMessage` in dex,
`.sendTextMessage(` in jadx output).

Also landed: all 51 rules now declare `category` (18 previously fell back to a name regex and
landed in `other`, invisible to the metric — T12 finished); `evasion` and
`packing_obfuscation` were deliberately kept **out** of `MALWARE_CATEGORIES` so annotating
them could not inflate the headline number.

## 5.4 ⭐ Measured outcome — full corpus re-run, 703 samples, 66.7 min

| Measure | Before | After |
|---|---:|---:|
| **Samples with ≥1 malware-category finding** | **50 / 651 (8%)** | **238 / 649 (37%)** |
| `sms_intercept` | **0** | **197 (30%)** |
| `accessibility_abuse` | **0** | **25** |
| `notification_abuse` | 2 | 16 |
| `overlay_attack` | 6 | 10 |
| `packing_obfuscation` | 0 | 1 |
| `ransomware` | 0 | **0** |
| **Benign malware-category findings** | 0 / 4 | **0 / 4** ✅ |
| India set, malware-category findings | 14 | **21** |

**4.8× improvement with the benign false-positive rate held at zero**, and benign finding
counts byte-identical to the frozen `pre_B1` baseline (6/2/5/4 benign, 2/1/7/4 vuln).

The India-targeted samples are now caught **by behaviour, not only by brand**:

```
novTargetedIndianBanks (SBI clone)   → Android_BFSI_SMS_Intercept_And_Forward
sepTaxPayer (ICICI iMobile squat)    → Android_BFSI_SMS_Mailbox_Harvest
Sep_infoStealer ×3 (ICICI Rewards)   → Android_BFSI_SMS_Suppression
```

`SMS_Suppression` is the sharpest of these: the sample intercepts the incoming message *and
aborts the broadcast*, so the victim never sees the OTP.

### Predictions vs outcome — two missed

| Prediction | Outcome |
|---|---|
| Corpus detection 8% → **45–60%** | ❌ **37%.** The 45–60% was extrapolated from the whole-dex probe that B28 later showed was inflated by lost co-location. Corrected mid-course; recording the original miss. |
| Benign malware-category **0 → 0** | ✅ held, and it is what caught B28 |
| `sms_intercept` stays < 5% until rules rewritten | ✅ 0% before; **30%** after the rewrite |
| Dead rules 20 → **fewer than 8** | ❌ **18 of 51.** See below. |

### 🔴 Finding B29 — the legacy rules are still dead; the gain came from routing around them

18 rules still fire on nothing, including **every India-specific legacy rule**
(`Android_India_SMS_OTP_Stealer`, `Android_India_FakeBank_App`, `Android_India_UPI_Targeting`,
`Android_India_Drinik_ITR_Impersonation`) and **both ransomware rules** — which is why
`ransomware` remains 0 across 649 known-malware samples.

The 8% → 37% gain is almost entirely the eight new BFSI rules. The old rules were not fixed,
they were bypassed. **The India-specific rule file currently contributes nothing to India
detection** — that comes from L0 impersonation plus the new BFSI primitives. Stated plainly
because the file's name implies otherwise.

## 5.5 Open after B1

1. **18 dead rules**, notably ransomware (0/649) and the entire India-specific file. Each
   needs the same treatment the SMS/accessibility classes just got: mine real co-occurrence,
   rewrite the condition, validate against benign.
2. **The benign denominator is still 4.** Every "0/4 benign" above is the absence of evidence
   of a high false-positive rate, not evidence of a low one. Backlog I14 blocks honest weights.
3. B26 (`ResParserError`, 25 samples) and the 40% partial-decompilation rate are untouched.
4. A4 is now worth running: 33 rules fire, with per-rule counts across 649 spines.

---

# Improvements Backlog

Ranked by (value ÷ cost). Items are promoted into a phase plan when picked up.

| ID | Improvement | Rationale | Cost |
|---|---|---|---|
| ~~I1~~ | ~~**Make the evidence spine real**~~ | ✅ **Done — Part 3.** `spine.py`, top-level `artifacts/`. | — |
| ~~I2~~ | ~~Replace androguard's loguru sink~~ | ✅ Done — Part 4; `corpus_run.py` removes the loguru sink for batch runs. | — |
| ~~I3~~ | ~~Fix `source_env.sh` to derive paths from `$(dirname $0)`~~ | ✅ Done in A6 (B21); hardened again in Part 3 (B22) — the silent fallback now warns. | — |
| I4 | Install Ghidra, then re-test D1 (`-noanalysis` vs. string extraction). | Native `.so` analysis is a stated differentiator and is currently 100% dead. | Medium |
| I5 | Fix the `data`-out-of-scope bug in `yara_scan._findings_from_matches` (D2). | Latent `NameError` on the raw-APK scan path. | Trivial |
| ~~I6~~ | ~~Deterministic finding IDs + evidence-ID references~~ | ✅ **Done — Part 3.** Ordinal `F001`… plus insertion-stable fingerprints. | — |
| ~~I7~~ | ~~Record per-layer coverage metrics as first-class fields~~ | ✅ **Done — Part 3.** Per-layer `coverage` + derived `analysis_gaps`. | — |
| I8 | Refresh the stale malware `L0/artifacts/` (pre-A6, 2026-08-07) or delete them. | They read as current and are not (B23 caveat). A stale artifact is worse than a missing one. | Trivial |
| I9 | Pin dev dependencies (`pytest`) in a `requirements-dev.txt`. | `requirements.txt` has no test dependency; the suite needs pytest installed by hand. | Trivial |
| I10 | **307 unencrypted `.apk` files (638 MB) sit loose under `corpus/malware_raw/android-malware/`.** | They arrived that way with the upstream repo clone, but §4's "samples stay password-zipped at rest" is not actually true of 45% of the corpus by count. Decide: re-zip, or document the exception. Not a silent fix — it is a policy call. | Low |
| ~~I11~~ | ~~Repair the malware-category rule set (B25)~~ | ✅ **Part 5.** 8% → 37%; `sms_intercept` 0 → 30%, `accessibility_abuse` 0 → 25 samples, benign FPs held at 0. | — |
| **I15** | 🔴 **18 rules still fire on nothing (B29)** — both ransomware rules and the entire India-specific file. | `ransomware` is 0/649 on a corpus containing ransomware. The 37% came from routing around these rules, not fixing them. | High |
| **I12** | Harden L0 against `ResParserError` (B26) — androguard dies on malformed UTF-16 in resource tables. | 3.8% of the corpus is lost at the first layer, to a documented anti-analysis technique. A partial manifest parse beats none. | Medium |
| **I13** | Investigate the 40% `decompilation_partial` rate; measure whether 180 s is simply too short. | Confounds every per-rule weight A4 will compute — "rule missed it" and "jadx never produced the file" are different facts. | Medium |
| **I14** | Grow the benign set beyond 4 apps (F-Droid bulk download is free and fast). | Every A4 weight is `unsupported (n_benign=4)` until this lands. | Low |

---


# Part 6 — Workstream A4, pricing the signals (2026-08-11)

Build order from §1.6 is `A4 → L5 + L6-minimal → L3 → L2 → L4`. This part covers
Phase 0 (foundations), A4 itself, and the benign-corpus work A4 turned out to
require *before* its numbers mean anything.

## 6.0 Foundations

- **Baseline frozen.** The entire A1/A2/A3/A5/A6/B1 body of work had accumulated
  untracked — `spine.py`, all of `tests/`, `L0/{certinfo,impersonation,promote}.py`,
  `apk_bfsi_primitives.yar`, both corpus tools, `CLAUDE.md`, `docs/plans/`. Committed
  as-is on branch `pipeline-l2-l6`, tagged `baseline-post-B1`. The working agreement
  says *freeze a baseline before touching a detector*; there was nothing to diff against.
  Also caught: `tools/android-sdk/` (8.7 GB) and `tools/frida-server` (107 MB) were
  untracked **and** unignored.
- **897 MB reclaimed**, and T18 re-attributed. `corpus_run.py`'s disposal is not the
  leak — it reclaims correctly and the 703-sample run left no residue. The residue is
  from running `L1/l1.py` directly, which has no disposal policy *by design*: a manual
  run is usually one you want the sources for. Fix is `tools/reclaim_disk.py`, a sweeper
  you point at the residue, not a behaviour change that would sabotage debugging.
- **`SENTINEL_DATA_ROOT`** → `/mnt/SharedData` (276 GB free, vs 14 GB on `/`).
  Benchmarked before adopting, because ntfs-3g runs through FUSE: androguard full-parse
  of a 46 MB APK is **1.22× ext4**. Negligible.

## 6.1 🔴 Finding B30 — at n_benign = 4, the weights are not merely weak, they are inverted

A4 (`tools/rule_firing_report.py`) was run at the corpus as it stood: **640 malware,
4 benign**. The result is not "wide error bars". It is a sign error across most of
the ruleset.

| weight | m/M | b/B | signal |
|---:|---:|---:|---|
| **+2.85** | 625/640 | 3/4 | `yara:APK_Valid_Structure_Check` |
| +1.90 | 273/640 | 0/4 | `l0:verdict:suspicious` |
| +1.64 | 233/640 | 0/4 | `l0:sms_trifecta` |
| … | | | |
| −1.26 | 19/640 | 0/4 | `yara:Android_BFSI_Accessibility_Driven_Exfil` |
| **−1.90** | 10/640 | 0/4 | **`l0:brand_claim`** |
| −2.38 | 6/640 | 0/4 | `yara:Android_Clipboard_Hijacker` |
| −3.00 (raw −3.86) | 1/640 | 0/4 | `yara:Android_Dropper_Encrypted_Payload_Stage1` |

**32 of 45 signals are priced negative** — as evidence of being *benign*. The
highest-weighted signal in the entire system is "is a well-formed ZIP". And
`l0:brand_claim` — the bank-impersonation signal that is this project's whole
differentiator — prices at **−1.90**.

This is not a defect in the formula; it is the formula reporting, correctly, that
the benign denominator carries no information. The Jeffreys 95% upper bound on a
benign rate of 0/4 is **0.445**: *"zero false positives"* over four apps is
statistically consistent with a rule that fires on 44% of benign software. Every
previous claim of `0/4 benign false positives` in this log should be read with
that interval attached.

**The size requirement is closed-form, not a guess.** With `b = 0`, the weight is
positive iff

```
B  >  0.5 · (M − m + 0.5)/(m + 0.5) − 0.5
```

| rule prevalence `m` (of M = 640) | benign apps needed |
|---|---:|
| m = 125 (`SMS_Suppression`) | 2 |
| m = 19 (`Accessibility_Driven_Exfil`) | 16 |
| m = 6 (`Clipboard_Hijacker`) | 49 |
| m = 1 (`Dropper_Encrypted_Payload_Stage1`) | **213** |

**B ≥ 213 makes every currently-negative signal sign-correct.** Backlog item I14
is therefore not "low priority polish" as recorded — it is a hard prerequisite for
L5, and it has a number.

Frozen as `tests/baseline/pre_I14/` so the benign corpus's effect is a diff.

## 6.2 Finding B31 — none of the 18 dead rules is structurally broken

The standing hypothesis (B29, and the A4 plan) was that dead rules might be
malformed or filtered out of the ruleset they needed to be in. **Refuted, mechanically.**

Each rule was compiled alone and matched against a buffer built from its own
declared string literals. A rule that cannot match a buffer containing all of its
own strings has a broken condition. **All 18 dead rules self-match.**

So they are not broken; the corpus does not contain their vocabulary co-located in
one class. That is a different problem with a different fix, and conflating the two
would have sent I15 rewriting rules that were never wrong.

## 6.3 The shared signal namespace

`signals.py` — A4 prices signals, L5 spends them. If each derived "what signals does
this spine carry" independently, they would drift the moment either changed, and a
weight applied to the wrong signal is undetectable by inspection. Both import it;
12 tests pin the vocabulary. `self_signed` is filtered defensively as well as
upstream (T6).

`corpus/labels.json` (`tools/corpus_labels.py`) — spines are keyed by sha256 and
carry no class. Conflicts fail loudly rather than resolving silently. The four
`vuln` apps are `excluded`, not `benign`: intentionally-vulnerable training apps
are neither malicious nor benign-representative, and folding them into B would
corrupt the denominator.

## 6.4 The benign corpus (I14)

`tools/fdroid_fetch.py`, targeting ~600 apps against the B ≥ 213 requirement.

**Stratified on declared permissions, which is the point.** `index-v2.json` carries
`manifest.usesPermission` per version, so the apps most likely to produce a false
positive are selected *before* downloading anything. A uniform sample would be
mostly offline utilities no banking rule could match, and 0 FPs against that would
measure nothing.

🔴 **Measured limits of this corpus, to be carried into every report derived from it:**

| Limit | Consequence |
|---|---|
| Only **5** of 4178 F-Droid packages declare an accessibility service | `accessibility_abuse` rules stay thinly validated regardless of corpus size |
| Only **79** declare any SMS permission | the 197-sample `sms_intercept` signal is tested against a small panel |
| Every app is F-Droid- or developer-signed | `certificate_anomaly` ≈ 0 by construction; any cert weight is an **upper bound** |
| Ad-SDK and tracker free by policy | packing/obfuscation/secret base rates far below a Play Store population |
| **No commercial banking apps exist on F-Droid** | the benign set contains **none** of the app class most likely to trip a bank-impersonation rule |
| Benign 2024–2026 vs malware 2020–2022 | part of every weight measures *era*, not malice — not separable on this corpus |

The named mitigation for row 5 is a separate hard-negative panel of real BFSI APKs,
reported separately and never merged into B. Not in scope here; recorded so the gap
is visible rather than implied.

## 6.5 L4 unblocked, and a hallucination worth keeping

The proposal's LLM layer now has a working provider (`L4/provider.py`). Model chosen
by measurement: four free models were given the same obfuscated SMS-interceptor class.

| model | result |
|---|---|
| `nemotron-3-ultra-550b:free` | decoded the Base64 C2 URL correctly (`.../gate.php`), 7 behaviour tags, valid JSON, 30 s |
| `north-mini-code:free` | faster (17 s), decoded the same string as `get.php` — **wrong** |
| `gemma-4-31b-it:free` | HTTP 429, rate-limited upstream |
| `gpt-oss-20b:free` | HTTP 400, reasoning cannot be disabled |

**That `get.php` is the single most useful result of the exercise.** The model
asserted a decoded value that `base64.b64decode` refutes in a microsecond, and no
amount of RAG grounding would have caught it, because the claim is about *the sample*
rather than about the threat landscape. `main.tex` §3.3 has been rewritten
accordingly: the primary anti-hallucination control is **mechanical verification**,
with retrieval second.

**Claim discipline applied to `main.tex`.** The proposal's headline commitment was
*"an open-weights LLM option ensures no live malware sample ever leaves the bank's
perimeter"*. That is now false for this build: decompiled sample code goes to a
hosted API. Rewritten to state the provider is pluggable, that the on-premise
backend is **specified but not implemented**, and that every LLM result reported was
produced by a hosted model. `LocalProvider` raises rather than falling back, so the
gap cannot be mistaken for a working feature. The React dashboard claim was likewise
corrected to the FastAPI + no-build-toolchain dashboard actually being built.

## 6.6 L5 built, and a prediction recorded before the benign corpus lands

`L5/{policy.yaml,score.py,gates.py,confidence.py,promote.py,l5.py,validate_policy.py}`,
27 tests. Additive log-odds with per-family redundancy decay → sigmoid map with two
operationally-defined anchors → L3 bounded to ±10 → gates as **floors**, never overrides.

**`validate_policy.py` refuses to arm a gate whose rules are not measurably specific.**
Against the B=4 weights it reports 15 problems and blocks both enabled gates, because
every rule's benign-rate 95% upper bound is 0.445 against a limit of 0.02. This is I14
enforced in code rather than in prose: **no gate can fire until the benign corpus lands.**

Running L5 against the current weights on the SBI Quick Support trojan
(`8f05ecbb…`, `com.sbi.complaintregister`, a confirmed India banking trojan):

```
score 18 (Informational)   confidence 0.50 (moderate)
  brand    -1.90  l0:brand_claim               F001
  hygiene  +2.85  yara:APK_Valid_Structure_Check F005
  (ungrp)  -2.00  l0:verdict:impersonation_likely
```

**A confirmed banking trojan scores 18 out of 100.** This is the machinery working
correctly and the weights being worthless: L5 faithfully reports what A4 measured,
and stamps the whole result `unsupported`. It is the clearest single demonstration
of B30 that this project has.

📉 **Falsifiable predictions, recorded now, to be checked after the benign corpus:**

| # | Prediction |
|---|---|
| P1 | SBI Quick Support moves from **Informational (18)** to **High or Critical** |
| P2 | `l0:brand_claim` flips from −1.90 to **positive** |
| P3 | `APK_Valid_Structure_Check` becomes **degenerate** and is priced at 0 |
| P4 | ≥20 of the 32 negative signals flip positive |
| P5 | `validate_policy.py` passes, and G1/G2 become armable |
| P6 | Some benign apps **will** fire malware-category rules — the 0/4 FP rate will not survive 600 apps |
| P7 | `Android_Secrets_Hardcoded` gets `ben_rate > 0.5` and stays priced ≤ 0 |

## 6.7 The evaluation harness, and two more measurements of B30

`tools/evaluate.py` — score distributions, AUROC with a bootstrap interval,
per-band operating points with Jeffreys intervals, k-fold cross-validation that
**refits A4's weights on each training fold**, and the proposal's four-way ablation.

Run against the corpus as it stands (640 malware, 4 benign), it produced two
findings that sharpen B30 considerably.

### B32 — at B = 4 the weights overfit badly, and only cross-validation shows it

```
AUROC in-sample       0.9695   95% CI [0.9293, 0.9945]
AUROC cross-validated 0.8270   95% CI [0.6898, 0.9594]
gap                  +0.1425
```

A4 fits its weights on the same corpus L5 is evaluated on, so an in-sample
AUROC partly measures how well the weights memorised which rules fired on which
malware families. **0.97 is not a result; it is the absence of a holdout.** Any
future report that quotes an in-sample figure alone is quoting this artefact.
The harness now prints both, always, and flags a gap above 0.05 explicitly.

### B33 🔴 — the India samples currently score *worse* than generic malware

```
class                n   median      IQR
benign               4      3.0   [ 2.0,  5.5]
india_malware       14     16.0   [11.2, 17.5]
malware            626     35.5   [17.0, 66.5]
```

The 14 India-targeted samples — the entire differentiator, the thing a judge
asks to see — sit at **half** the median of generic malware. The cause is
mechanical and already known: `l0:brand_claim` is priced at −1.90 (B30), so a
sample carrying bank impersonation is *penalised* for it, and the India set is
exactly the population that carries it. The differentiator is currently
anti-correlated with the score.

This is the most legible statement of why I14 blocks everything downstream.

### A denominator bug, caught by writing the test

The first version of this harness reported a benign denominator of **8**
against a real one of 4: `y = 1 if malware else 0` swept the four
intentionally-vulnerable training apps (InsecureBankv2, PIVAA, UnCrackable
L1/L2) into the negative class. `corpus_labels.py` classifies them `excluded`
precisely to prevent this, and the harness folded them back in.

A false-positive rate is a statement about what you divided by, so doubling the
denominator halves every FPR — silently, and in the flattering direction. They
are now scored separately as negative controls, where the question is
"does a deliberately insecure but non-malicious app get flagged?", and a High
there is a defect regardless of what the benign FPR says.

📉 **Two more predictions for the post-corpus re-run**, added to §6.6's list:

| # | Prediction |
|---|---|
| P8 | `india_malware` median rises **above** the general malware median |
| P9 | the in-sample/cross-validated AUROC gap falls below 0.05 |

