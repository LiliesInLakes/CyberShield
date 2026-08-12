# CLAUDE.md — APK Sentinel / CyberShield

Working context for this repository. Read this before changing anything.

> **Detailed history, measurements and rationale live in
> [`docs/PROJECT_LOG.md`](docs/PROJECT_LOG.md).** This file is the short version:
> what the project is, what actually works, and the traps that will waste your time.

---

## 1. What this is

Evidence-driven Android **banking-malware** analysis pipeline, built for the
**PSB Cybersecurity, Fraud & AI Hackathon 2026** (Bank of India · IIT Hyderabad ·
DFS, Ministry of Finance · IBA). Target threat: fraudulent APKs impersonating
Indian banks, UPI apps and government services.

Seven layers, glued by a single evidence record:

| Layer | Purpose | **Verified status** |
|---|---|---|
| **L0** Ingestion & triage | Hashing, manifest, icon pHash, certificate, **bank-impersonation check**, routing | ✅ works |
| **L1** Static analysis | jadx decompile + YARA (source, per-class dex, APK scopes); Ghidra for native | ⚠️ 37% malware-category detection (was 8%); **18 rules still dead** (B29) |
| **Spine** | Merged `artifacts/<sha256>/evidence.json`, stable evidence IDs | ✅ works (L0+L1 wired) |
| **L2** Dynamic analysis | Emulator detonation, Frida hooks, mitmproxy | ❌ **non-functional**, not wired to the spine; AVD core-dumps (T14) |
| **L3** ML classifier | Calibrated maliciousness prior, bounded ±10 | ⚠️ built + feature bridge verified; **no model trained yet** |
| **L4** GenAI reasoning | Verified deobfuscation + report generation | ✅ works — OpenRouter free tier, execution verifier, $0.00/call |
| **L5** Hybrid scoring | Auditable additive score + smoking-gun gates | ⚠️ built; **gates refuse to arm** while weights are unsupported (T24) |
| **L6** Output & UX | Dashboard, report, IOC export | ✅ works — STIX 2.1 / CSV / YARA / Sigma, FastAPI, HTML report |

🔴 **Every score the system currently emits is stamped `unsupported` and is not
usable as evidence.** That is not a bug: A4 measured that at `n_benign = 4` the
weights are sign-inverted (T24/B30), so L5 reports what it was given and refuses
to arm a gate. The benign corpus is what changes this — see §7.

**The differentiator is L0 bank-impersonation detection.** MobSF answers "is this app
insecure?"; this answers "is this app pretending to be your bank, and how do we know?"

---

## 2. Environment — read this first

**Dependencies live in the repo-local `env/` venv.** They were previously installed against
`/usr/bin/python3.13`, which a Fedora upgrade deleted — taking androguard, yara-python,
imagehash and pyzipper with it. Never depend on a system interpreter again.

```bash
source source_env.sh          # sets $SENTINEL_PYTHON, JADX_DIR, JDK17_HOME, ANDROID_SDK_ROOT
$SENTINEL_PYTHON L0/ingest.py <apk>
```

If `source_env.sh` warns that no interpreter has the dependencies, rebuild:

```bash
python3 -m venv env && ./env/bin/pip install -r requirements.txt && ./env/bin/pip install pytest
```

`source_env.sh` derives all paths from its own location — do not reintroduce absolute paths.

| Tool | State |
|---|---|
| jadx + bundled JDK 17 | ✅ `tools/jadx`, `tools/jdk17` |
| **Ghidra** | ❌ absent — native track degrades gracefully; only ~12% of samples have native libs |
| Android SDK, emulator, adb, frida-server, `/dev/kvm` | ✅ all present |
| **`sentinel` AVD** | ❌ **core-dumps on boot** (see §6) |

---

## 3. Commands

```bash
source source_env.sh

$SENTINEL_PYTHON L0/ingest.py <apk>            # -> L0/artifacts/<sha256>/evidence.json
$SENTINEL_PYTHON L1/l1.py <apk>                # -> L1/artifacts/<sha256>/analysis.json
                                               # both also fold into artifacts/<sha256>/evidence.json
$SENTINEL_PYTHON tools/debug/summarize_results.py <apk>
$SENTINEL_PYTHON -m pytest tests/ -q

# Corpus (safe, resumable — see §4). Full run: ~57 min, 705 samples.
$SENTINEL_PYTHON tools/corpus_run.py --dry-run
$SENTINEL_PYTHON tools/corpus_run.py --match novTargetedIndianBanks
$SENTINEL_PYTHON tools/corpus_run.py                 # everything; re-run to resume
$SENTINEL_PYTHON tools/corpus_summary.py             # newest run's report

# Benign corpus (I14) and the weights L5 spends
$SENTINEL_PYTHON tools/fdroid_fetch.py select --n 600 && \
$SENTINEL_PYTHON tools/fdroid_fetch.py download
$SENTINEL_PYTHON tools/corpus_run.py --corpus-root "$SENTINEL_DATA_ROOT/fdroid/apks" \
                                     --source loose --label benign_fdroid
$SENTINEL_PYTHON tools/corpus_labels.py build --benign-root "$SENTINEL_DATA_ROOT/fdroid/apks" \
                                              --benign-id benign_fdroid
$SENTINEL_PYTHON tools/rule_firing_report.py         # A4 — read the support stamp (T24)

# Scoring, calibration, evaluation
$SENTINEL_PYTHON tools/fit_calibration.py --apply    # refuses below n_benign=100
$SENTINEL_PYTHON L5/validate_policy.py               # blocks gates on unmeasured rules
$SENTINEL_PYTHON L5/l5.py <sha256> --explain         # the audit trail
$SENTINEL_PYTHON L5/l5.py --all                      # score every spine, idempotent
$SENTINEL_PYTHON tools/evaluate.py --ablation --folds 5

# L3 (needs ~6 GB), L4, L6
$SENTINEL_PYTHON L3/fetch_lamda.py
$SENTINEL_PYTHON L3/train.py --train-until 2022
$SENTINEL_PYTHON L4/deobfuscate.py <sha256> --src L1/artifacts/<sha256>/jadx_src
$SENTINEL_PYTHON L6/report.py <sha256> --out report.html
$SENTINEL_PYTHON L6/export.py <sha256> --format stix,csv,yara,sigma --out-dir /tmp/x
$SENTINEL_PYTHON -m uvicorn L6.api:app --host 127.0.0.1 --port 8000   # localhost only

# Disk. corpus_run disposes of jadx_src itself; direct l1.py runs do not (T18).
$SENTINEL_PYTHON tools/reclaim_disk.py --dry-run
```

---

## 4. 🔴 Malware corpus — safety rules

`corpus/malware_raw/` holds **2.0 GB of live Android malware** in **two populations**:

| Population | Count | State at rest |
|---|---:|---|
| Zip members (203 archives) | 371 | password-protected (`infected`), 148 AES |
| **Loose APKs in `android-malware/`** | **328** | ⚠️ **unencrypted** (upstream repo ships them this way) |
| **Total candidates** | **699** | |

Code that iterates only the zips silently analyses half the corpus. `tools/corpus_run.py`
covers both. Non-negotiable:

1. **Never commit.** `corpus/` is in `.gitignore`.
2. **Never bulk-extract.** Samples stay inside password-protected zips at rest
   (password `infected`; use `pyzipper` — many members are AES).
3. **One at a time.** Read a member into memory (`APK(data, raw=True)`) or extract to a
   temp dir and delete in a `finally`. Never `extractall`.
4. **Never execute.** Only androguard, zipfile, YARA and jadx-under-JVM touch sample bytes.
5. **Detect APKs by `PK\x03\x04` magic, not extension** — 45% of members are extensionless.
6. No detonation until the emulator boots *and* networking is host-only with a snapshot.

**India-targeted samples — 12, across three impersonated entities** (the demo set):

| Archive | Impersonates |
|---|---|
| `AndroidMalware_2021/novTargetedIndianBanks.zip` | `com.sbi.complaintregister` / "SBI Quick Support" |
| `AndroidMalware_2020/fakeAarogyaSetu.zip` | 4× "Aarogya Setu" (Indian gov app) |
| `AndroidMalware_2021/mayJioTarget.zip` | 3× India COVID/Jio lures |
| **`AndroidMalware_2021/sepTaxPayer.zip`** | **"iMobile" / `direct.uujgiq.imobile` — ICICI namespace squat, SMS trifecta** |
| **`AndroidMalware_2022/Sep_infoStealer.zip`** | **3× "ICICI Rewards" under `com.example.test_app`** |

The last two rows were **found by the pipeline** during the first full corpus run, not
hand-picked (Finding B24).

---

## 5. Conventions

- Layer-local artifacts keyed by SHA-256: `<LAYER>/artifacts/<sha256>/`.
- **The merged spine is `artifacts/<sha256>/evidence.json`** (top level, not under a layer).
  Written *only* through `spine.update_layer()`, which merges one layer and replaces the file
  atomically. Never write it directly; never read-modify-write another layer's block.
- All findings share the `L1Finding` schema (`L1/schema.py`): `engine`, `category`,
  `severity`, `evidence`, `location`, `mitre_techniques`, `observation`, `detail`.
  In the spine each also carries `layer`, `id` (`F001`…) and `fingerprint`.
  **Cite `id`; diff on `fingerprint`** — ids shift when findings are inserted, fingerprints
  do not.
- `observation`: `inferred` (static) → `observed` (runtime) → `confirmed` (analyst).
- Layer status is a `LayerStatus`, never the string `pending`. `partial` is real and means
  "ran, with a coverage gap" — the gap belongs in `analysis_gaps`.
- Style: `from __future__ import annotations`, dataclasses, `pathlib`, type hints.
- **Regression baselines are frozen** in `tests/baseline/` (`pre_A2/` for L1 findings,
  `pre_A6/` for L0 impersonation). Use the **on-disk artifacts** as the oracle, never a
  table in a doc — *and check their mtime first* (see T16).

---

## 6. 🔴 Traps — things already discovered the hard way

Each of these cost real time. Do not rediscover them.

| # | Trap |
|---|---|
| **T1** | **YARA `uint32()` is little-endian.** 27 of 43 rules gated on `uint32(0) == 0x504B0304`, which is **never true** for a ZIP. Now `uint32be(0) == 0x504B0304`. If you add a rule, use `uint32be`. |
| **T2** | **Never concatenate files for YARA.** Batching 500 `.java` files let conditions like `3 of ($wm*) and 2 of ($phish*)` be satisfied by strings scattered across unrelated files — this caused a **100% false-positive rate on benign apps**. `scan_sources` scans per file. Batch size is a *correctness* parameter. |
| **T3** | **A raw APK scan is structurally near-blind** — everything is deflated. `scan_apk` scans the container (for ZIP-structure rules) **plus decompressed members**. Both passes are required; removing either kills a rule class. |
| **T4** | **androguard 4.x returns `asn1crypto` certs**, not `cryptography` ones. Use `cert.sha256`, `cert.issuer.native`, `cert.dump()` — **not** `cert.public_bytes()`. The old code's `except` hid the failure behind a plausible-looking result. See `L0/certinfo.py`. |
| **T5** | **`apk.get_app_icon()` defaults to `max_dpi=65536`**, which picks the adaptive-icon **binary XML** that PIL cannot decode. Icon extraction silently failed on ~half of all APKs. Use the dpi ladder in `extract_icon_phash`. |
| **T6** | **`self_signed` is a ~100% base-rate flag** — every Android APK is self-signed (22/22 locally, including all benign). It carries **zero weight alone**. Only signer *anomalies* discriminate. |
| **T7** | **Never fuzzy-match app labels.** `difflib` scored `"duckAssist"` vs the Income Tax alt-label `"iAssist"` at 0.706 and raised a **critical bank-impersonation finding on a benign note-taking app**. Use whole-token / whole-phrase matching only (`L0/impersonation.py`). |
| **T8** | **Never auto-derive brand tokens.** Derivation proposes `assist` for Income Tax (recreating T7), `phone` for PhonePe, and Devanagari `बैंक` for every bank. `brand_tokens` in the whitelist are **hand-curated**. |
| **T9** | **22 of 39 original whitelist package names return HTTP 404** — fabricated identifiers. Only `package_verified: true` entries may carry a `vendor_prefixes` entry, or you seed a fake namespace. |
| **T10** | **`L0/ingest.py:run_l0` destructively overwrites `evidence.json`** with `l1`…`l6` = pending on every run. The evidence spine must **not** live in `L0/artifacts/`. |
| **T11** | **Rule severity is case-sensitive.** 35 rules use `"Critical"`/`"High"`; the map was lowercase, silently downgrading them all to MEDIUM. Fixed in `_severity()`. |
| **T12** | **Set `category` in rule meta.** The name-regex fallback left `clipboard_hijack`, `notification_abuse`, `screen_capture`, `packing_obfuscation`, `messaging_c2` **unreachable** — hiding real detections as `other`. |
| **T13** | **AES zip members have `CRC-32 = 0`** (WinZip AE-2 mandates it). Any resume/dedup key based on CRC degenerates for 40% of the corpus. |
| **T14** | **The `sentinel` AVD core-dumps on boot** — not OOM, not a process-group kill, not Vulkan. L2 is untestable until fixed. Do **not** rabbit-hole here; it ate a research agent's warning budget for a reason. |
| **T15** | **A metric defined in prose and re-implemented in code will drift.** `MALWARE_CATEGORIES` was rewritten with 14 categories against a criterion of 9, silently redefining every recorded before/after number. It is now pinned by a test. Widening it requires a re-baseline, not a commit. |
| **T16** | **An artifact directory is not a source of truth unless you check its provenance.** The malware `L0/artifacts/` are pre-A6 and still read `verdict: unknown` on all 8 India samples. Anything derived from them records a picture that was already known to be wrong. Check mtimes, or regenerate. |
| **T17** | **A green "ready" banner over a broken environment is worse than a red one.** `source_env.sh` fell through to a dependency-less `python3` and printed success; the failure surfaced much later as a confusing `ModuleNotFoundError`. It now warns. Dependencies live in `env/`, not in a system interpreter. |
| **T18** | **jadx output, not samples, is what fills the disk.** ~112 MB of `jadx_src` per sample vs a ~2 MB APK — ~78 GB projected over the corpus, against ~13 GB free. `corpus_run.py --keep-decompiled none` reclaims it per sample. A disposal policy aimed at the samples protects 1.45 GB and ignores 78. **The corpus runner is not the leak** — it disposes correctly. Running `L1/l1.py <apk>` *directly* has no disposal policy (deliberately: a manual run is one you want the sources for), and eight such runs on the test apps had quietly accumulated 904 MB. Sweep with `tools/reclaim_disk.py`. |
| **T19** | **Never estimate a rate from the hand-picked set.** "4 of 8 banking trojans undetected" (50%) became **92%** at corpus scale. Eight samples chosen because they were interesting are not a sample of anything. |
| **T20** | **A member is not the container.** Behaviour rules gated on `uint32be(0) == 0x504B0304` can never match a `classes.dex` (`dex\n035`), and the container itself is deflated — so the gate made the scanner blind to the one place the app's strings live in plaintext. `scan_apk` uses a **separate member ruleset** with container gates stripped. |
| **T21** | **A dex is the whole app concatenated — scan it per class.** Whole-dex scanning is T2's batch-blob bug one level down: it made an expense tracker match an OTP stealer *and* a ransomware rule. Conjunction only means something inside one class. |
| **T22** | **A dex stores API calls as invoke operands, not string literals.** A per-class buffer of names + `const-string` only found **0 of 4** SMS APIs in a confirmed SMS trojan; adding invoke/field operands found all four. |
| **T23** | **`AccessibilityService` is a ~100% base-rate token** — present in 4/4 benign apps, exactly like `self_signed` (T6). Never key an accessibility rule on it alone; require a combination. |
| **T24** | 🔴 **At `n_benign = 4` the computed weights are sign-inverted, not merely imprecise.** A4 prices **32 of 45 signals negative** — as evidence of being *benign* — including `l0:brand_claim`, the differentiator, at **−1.90**. The top-weighted signal in the system is `APK_Valid_Structure_Check` (+2.85), i.e. "is a well-formed ZIP". The Jeffreys 95% upper bound on 0/4 is **0.445**, so every historical "0/4 benign false positives" claim means "somewhere between 0% and 44%". The requirement is closed-form: with `b=0`, `w>0` iff `B > 0.5·(M−m+0.5)/(m+0.5) − 0.5`, so **B ≥ 213**. Never quote a weight without its support stamp. |
| **T25** | **A dead rule that self-matches is not broken.** Compile a rule alone against a buffer of its own declared strings: if it fires, its condition is fine and the *corpus* lacks the vocabulary co-located in one class. All 18 dead rules pass this test (B31), refuting the "stripped/malformed" hypothesis. Conflating "rule is wrong" with "behaviour is absent here" sends you rewriting rules that were never wrong. |
| **T26** | **The LLM will confidently mis-decode a string, and RAG cannot catch it.** In model selection, `north-mini-code` decoded `aHR0cDovLzE5Mi4xNjguMS4xMDAvZ2F0ZS5waHA=` as `.../get.php`; it is `gate.php`. Retrieval grounds claims about the *threat landscape*, not about *this sample*. Anything a decoder, parser or hash can settle must be verified mechanically before it reaches a report. |
| **T27** | **F-Droid cannot validate the accessibility or BFSI rule classes.** Measured across all 4178 packages: **5** declare an accessibility service, **79** declare any SMS permission, and **zero** are commercial banking apps. It is also entirely F-Droid/developer-signed, so `certificate_anomaly` is ~0 by construction and any cert weight measured against it is an **upper bound**. Growing B fixes the arithmetic (T24); it does not make these rule classes tested. |

---

## 7. Where things stand

### Landed and measured

**L1 finding quality** — endianness fix (T1), per-file scanning (T2), additive APK member
scanning (T3), one finding per `(rule, sample)` with breadth as `detail` fields, structural
cross-scope dedup via `merge_findings()`, category/severity fixes (T11, T12), jadx timeout
salvage, combo engine surviving corrupted archives.

**L0 impersonation** — correct certificate parsing + signer-anomaly classification
(`L0/certinfo.py`), icon dpi ladder (T5), whole-token/phrase brand matching
(`L0/impersonation.py`), curated `brand_tokens` for 39 entities, **Aarogya Setu added**
(4 of 8 India samples impersonate it), verdict is now a function of findings rather than of
`matched_bank`.

**Evidence spine (A1)** — `spine.py`: merged record at top-level `artifacts/`, single atomic
writer, `LayerStatus` enum, ordinal ids + insertion-stable fingerprints, per-layer coverage
and derived `analysis_gaps`. L0 impersonation and certificate findings are **promoted into
the unified findings array** (`L0/promote.py`), so the India differentiator finally has an
evidence ID for L5 to score and L6 to cite. 28 tests in `tests/test_spine.py`.

**Corpus runner (A3)** — `tools/corpus_run.py` + `tools/corpus_summary.py`. Both populations,
one member at a time, resumable without decrypting, `jadx_src` reclaimed per sample (T18).
First full run: **705 samples in 57 min, disk flat**.

| Measurement | Before | After |
|---|---|---|
| Malware-category findings on benign apps | 5 (incl. ransomware + overlay on an expense tracker) | **0 / 4** |
| India-targeted samples flagged by L0 | **0 / 8** (`verdict: unknown`) | **8 / 8**, 5 critical |
| Certificate anomalies: India malware vs benign | n/a (parsing broken) | **8/8 vs 0/4** |
| Other (non-India) malware flagged | n/a | 12 / 13 |
| Real banking trojans with a malware-category L1 finding | 1 / 8 | **4 / 8** |
| **India-targeted samples known in the corpus** | 8 (hand-picked) | **12** (4 found by the pipeline, B24) |
| **Malware-category detection, full corpus** | *believed 50%* → measured **8%** (B25) | **37% (238 / 649)** — B1 |
| `sms_intercept` findings across the corpus | **0 / 651** | **197 / 649 (30%)** |
| `accessibility_abuse` findings | **0 / 651** | **25 / 649** |
| Benign malware-category findings (held) | 0 / 4 | **0 / 4** |

**Detection repair (B1)** — root cause was T20/T21/T22: rules gated on ZIP magic could never
match the dex, and naive whole-dex scanning reintroduced T2's false positives. Fixed with a
separate member ruleset + per-class dex buffers + `L1/yara_templates/apk_bfsi_primitives.yar`,
8 rules authored from measured per-class API co-occurrence (50 malware vs 4 benign).

### Open

1. 🔴 **18 of 51 rules still fire on nothing** (B29) — including **both ransomware rules**
   (`ransomware` is 0/649 on a corpus that contains ransomware) and **every India-specific
   legacy rule**. B1 took detection from 8% → 37% by adding the BFSI rule file, i.e. by
   routing *around* the broken rules rather than repairing them. India detection currently
   comes from L0 impersonation plus the new BFSI primitives, not from
   `apk_india_banking.yar`. Each dead rule needs the same treatment: mine real per-class
   co-occurrence, rewrite the condition, re-validate against benign.
2. **40% of the corpus does not fully decompile in 180 s** (`decompilation_partial`). This
   confounds item 1: "the rule missed it" and "jadx never produced the file" are different
   facts, and A4 must separate them before any weight it computes means anything.
3. **3.8% of samples die at L0** on `ResParserError` (B26) — androguard vs malformed UTF-16
   in resource tables, which is a documented anti-analysis technique.
4. ~~**Rule-firing report (A4)**~~ — ✅ done, `tools/rule_firing_report.py`. Its result is
   T24/B30: 32 of 45 signals priced negative at `n_benign = 4`.
5. **L2 emulator boot** (T14), then `dexray-intercept` + a BFSI hook pack (incoming SMS,
   accessibility, notification listener). L2 has no spine producer yet. **Detonation of any
   sample is user-approved**; a go/no-go checkpoint is owed after the India-12 stage.
6. **Stale malware `L0/artifacts/`** (pre-A6, T16) — largely superseded by the corpus run,
   but the pre-A6 files remain.
7. 🔴 **No L3 model is trained.** The pipeline is verified end to end (a 2020-only proof run
   gave AUROC 0.9965 in-year, 0.8978 on 2024 — the drift exhibit), but `L3/model/` is empty
   and `l3` is `not_attempted` on every spine. The full train needs ~6 GB.
8. **The benign corpus does not contain the class of app most likely to be a false positive**
   (T27): F-Droid has 5 accessibility apps, 79 SMS apps and **zero** commercial banking apps
   repo-wide. Growing B fixes the arithmetic, not the coverage. The named mitigation is a
   separate hard-negative BFSI panel, reported separately and never merged into B.

### The nine predictions, recorded before the benign corpus landed

Written down in `docs/PROJECT_LOG.md` §6.6 and §6.7 so the result is a diff rather than a
recollection. The two that decide whether B30's diagnosis was right:

- **P1** SBI Quick Support moves from **Informational (18)** to High or Critical.
- **P8** `india_malware` median rises **above** the general malware median
  (currently 16.0 vs 35.5 — the differentiator is anti-correlated with the score).

If those do not move, the diagnosis was wrong and the log says so.

### Decided direction (from a two-agent research debate; see PROJECT_LOG §1)

- Build order: **spine → L5 scoring + L6 minimal → L3 → L2 → L4 threaded throughout**.
- **The LLM contributes zero points to the score** — it generates evidence and explanation.
- The proposal's `0.45·rules + 0.30·ml + 0.25·llm` blend is **replaced** by an auditable
  additive scheme with a versioned YAML policy; smoking-gun gates are the *primary*
  mechanism, not an override.
- **L3 trains on LAMDA** (HuggingFace `IQSeC-Lab/LAMDA`, MIT, ungated) as a *generic*
  maliciousness prior bounded to ±10 points — LAMDA is ~99.6% non-banking, so it must not
  make banking claims. AndroZoo/Drebin/MalRadar are unobtainable on this timeline.
- The mitmproxy **"response hijacking" claim is deleted**: FCM commands ride
  `mtalk.google.com:5228` over a binary protocol and never traverse an HTTP proxy.
- **Claim discipline:** *"we encode India-specific detection logic and validate it against
  real India-targeted samples and published 2026 IOCs"* — not "we detect Indian banking
  trojans in the wild".

---

## 8. Working agreement

The user runs this as a four-domain loop: **research → plan → implement → test**, one phase
at a time, with **no code written before a plan has been reviewed**, and no moving to the
next phase below ~99% confidence in the current one.

Practical consequences:

- Plans go in `docs/plans/`; reviews are recorded in `docs/PROJECT_LOG.md`.
- **Measure before claiming.** Every number in the docs above was produced by running
  something. Predictions in plans are written as falsifiable, then checked.
- **Freeze a baseline before touching a detector**, then diff against it.
- When a fix arms a code path that never previously executed, **assume it will produce a
  false positive** and test the benign set immediately — that is exactly how T7 was caught.
