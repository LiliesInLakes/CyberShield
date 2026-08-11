# Phase A — Implementation Plan (DRAFT, under review)

**Status:** drafted 2026-08-07 · awaiting independent review · **no code written yet**
**Scope:** Evidence spine · L1 finding quality · safe corpus runner · rule-firing report · India inject-list test

Phase A is the foundation for the decided build order:
**spine → L5 scoring + L6 minimal → L3 → L2 → L4 threaded throughout.**

---

## 0. Findings the planner discovered by reading the code

These are *root causes* beneath the symptoms recorded in `PROJECT_LOG.md` §0.7, and several
were missed by both the baseline audit and the research debate.

### N1 — PROJECT_LOG §0.7 had Notely and PennyWise swapped
Verified from `source_apk` inside each `analysis.json`: `ae1ce24a…` = Notely (3 findings),
`1256daaa…` = PennyWise (10 findings). **Corrected in PROJECT_LOG.** The app accused of
being ransomware + banking-overlay + dropper is PennyWise, an expense tracker that
legitimately reads SMS to parse bank alerts — making it the corpus's best hard negative.
**Use the on-disk artifacts, never the table, as the regression oracle.**

### N2 — Batch scanning defeats every multi-condition rule *(root cause of the 100% FP rate)*
`yara_scan._scan_batch` concatenates **500 `.java` files into one buffer** and evaluates rule
conditions against the blob. `Android_Banking_Generic_OverlayEngine` requires
`3 of ($wm*) and 2 of ($phish*) and 1 of ($target_pkg*) and 1 of ($anti*)` — under batching
those need only appear *somewhere across 500 files*, not together in one. Every multi-group
condition in the rule set is effectively defeated. `location` then points at the file holding
the *first* matched string, which is why reported locations look arbitrary.

> **Batch size is a correctness parameter, not a performance knob.**

### N3 — `_compile_rules()` never applies `_filter_scope`
The scope mechanism exists but is wired only into `_compile_source_rules()`. The raw-APK scan
therefore runs all 43 rules including the 15 marked `scope = "source"`. This alone explains
every garbage `yara_apk` match in Finding B4.

### N4 — 37 of 43 rules have their severity silently downgraded
`_SEV_MAP` has lowercase keys; only the 6 rules in `apk_vulnerabilities.yar` use lowercase
`severity` meta. The 37 malware-behaviour rules use `"Critical"`/`"High"`/`"Medium"` and fall
through to `Severity.MEDIUM`. **Every `critical`/`high` in the baseline comes from the OWASP
file.** Separately, `Category.PACKING`, `CLIPBOARD_HIJACK`, `NOTIFICATION_ABUSE`,
`SCREEN_CAPTURE`, `MESSAGING_C2` are **unreachable** — no `_CATALOG` regex maps to them.

### N5 — The corpus does not match assumptions

| Fact | Value | Consequence |
|---|---|---|
| archives | 203 | — |
| member files | 371, **1.56 GB uncompressed** | ~350 candidate APKs, not 56 |
| `*.apk` extension | 205 / 371 (55%) | `harvest_dataset`'s `rglob("*.apk")` **silently skips 45%** |
| members per zip | up to 5 | `harvest_apk(apks[0])` takes only the first |
| AES-encrypted (`compress_type 99`) | **148 / 371** | stdlib `zipfile` cannot read these |
| `pyzipper` installed | **NO** (though it is in `requirements.txt`) | hard prerequisite |
| nested `.zip` members | 6 | recurse or explicitly skip |
| on-disk corpus | **3.9 GB** | free disk now **15 GB** |

### N5b — India-relevant archives are present *(closes the top open risk from the debate)*
| Archive | Members | Why it matters |
|---|---|---|
| `AndroidMalware_2021/novTargetedIndianBanks.zip` | 1 APK (AES) | **Explicitly named for targeting Indian banks** |
| `AndroidMalware_2021/mayJioTarget.zip` | 3 APKs (AES) | `com.jio.myjio` is whitelist entry #39 |
| `AndroidMalware_2020/fakeAarogyaSetu.zip` | 4 members (ZipCrypto, **extensionless**) | Fake Indian government app |
| `AndroidMalware_2021/marchAlienBot.zip` | 2 APKs (AES) | Alien documented targeting Axis/ICICI/HDFC/BoB |

---

## 1. Design decisions

### A1 — Evidence spine

**Canonical merged file at `L0/artifacts/<sha256>/evidence.json`.** The three existing
artifacts stay in place as layer-local outputs. `L0/ingest.py:run_l0` already writes this
path and both debug tools already read it; moving to a new top-level `artifacts/` costs a
migration and two tool rewrites for no Phase-A benefit. *Flagged: semantically odd for L0's
directory to hold L5/L6 output — deferred to Phase B.*

**Single writer.** A `spine.py:update_layer()` does read → merge → atomic write
(`tempfile` + `os.replace`). L1 never read-modify-writes a file L0 owns.
*Rejected: letting L1 write the spine directly — no locking, and A3 may run concurrently.*

**Dual finding identity:**
- `id` — ordinal `F001`… assigned after a deterministic sort over
  `(layer_index, -severity_rank, category, engine, finding_key)`. What L5/L6 cite.
- `fingerprint` — `sha1(finding_key)[:12]`. Stable across ruleset changes and insertions;
  lets two runs be diffed.

The spine records `ruleset_version` (sha1 over sorted `yara_templates/**/*.yar`) so it is
visible exactly when ordinals may have shifted.
*Rejected: content-hash-only IDs (unreadable); ordinal-only (any new rule renumbers every citation).*

**Addition beyond brief — highest-value item in A1:** promote `l0.impersonation.findings`
and the cert signals into the unified `findings` array with `engine="l0_impersonation"`.
Without this the bank-whitelist hit — the India differentiator — has no evidence ID for L5
to cite, and the "show me it catching an Indian bank clone" demo has nothing to point at.

**`LayerStatus` enum:** `not_attempted` (replaces `pending`) · `running` · `complete` ·
`partial` · `failed` · `skipped`. `partial` matters: combo track with Ghidra absent is
neither complete nor failed.

**Coverage first-class:** a per-layer `coverage` block plus a flat top-level
`analysis_gaps: []` of machine-readable strings (`"ghidra_unavailable"`,
`"native_libs_unanalyzed:6"`, `"detonation_not_attempted:emulator_boot_failure"`). L5's
confidence axis reads `analysis_gaps` directly. **This is the mechanism that turns a failed
detonation into an honest confidence penalty rather than a silent gap.**

### A2 — L1 finding quality

**(a) One finding per (rule, sample).** Not per string, not per (rule, file), not per
(rule, scope). Rationale: `len(findings)` must be interpretable by L5 as "how many distinct
detections fired". Per-string inflates 6×; per-(rule, file) lets a rule touching 40 files
swamp one touching 1; per-(rule, scope) still double-counts source+apk. Collapsing to
(rule, sample) makes **cross-engine dedup structural rather than a post-hoc filter.**

Breadth is preserved as *fields*, not counts: `detail.scopes`, `detail.locations[:20]`,
`detail.location_count`, `detail.matched_string_ids`, `detail.match_count`,
`detail.samples[:8]`. Lumo's `Android_Clipboard_Hijacker` goes 6 → 1.

*Flagged for reviewer:* counter-argument is analyst ergonomics (one row per file to click
through). If reviewer prefers (rule, file), **L5's contract must change to "count distinct
rules, not findings" — and that must be decided now, not after L5 exists.**

**(b) Raw-APK noise — four layered fixes, in order:**
1. **Wire the scope filter into the APK path** (fixes N3). Three lines. Deletes all 7 of
   Lumo's `yara_apk` findings. *Highest-leverage fix in A2.*
2. **Give the 25 unscoped rules an explicit scope**, defaulting to `source`; introduce
   `scope = "both"` for the few that need it. *Flagged: touches 25 rules; default is a judgement call.*
3. **Stop scanning the compressed container.** Replace `rules.match(str(apk_path))` with
   structured member iteration — scan `classes*.dex` (decompressed), `AndroidManifest.xml`,
   `assets/**`, `res/raw/**`, `lib/**/*.so` as separate targets. `location` becomes a real
   member path, turning byte-noise into legible native-strings findings.
4. **Post-match validators** keyed by (rule, string_id): Base58Check for BTC/Tron wallets,
   hex word-boundaries for ETH, real UPI handle suffixes for `$upi_id` (kills `p@q`), and a
   generic <90%-printable-ASCII reject. **Policy:** if every instance fails, drop the finding
   *and record it in a `suppressed` array* — a suppressed detection must stay visible.
   *Rejected: entropy gates and minimum match counts — unnecessary once 1–4 land, and each adds an untunable knob.*

**(f) Discrimination — fix the mechanism now, defer rule rewriting.**
- **Fix the batch-blob bug (N2).** Recommend per-file scanning, **gated on measurement**: if
  per-file scanning of Notely exceeds ~30 s, fall back to two-pass (batch to find candidate
  rules, re-scan that batch's files with only those rules to confirm per-file).
- **Declare `category` in rule meta**, demoting `_categorize()`'s regex to a fallback.
  Restores the five unreachable categories.
- **Fix `_SEV_MAP` case.** ⚠ **Must land *after* the scope and batch fixes** — it raises
  severities on 37 rules, so premature application shows a wall of `critical` on benign apps.
- **Explicitly out of scope:** rewriting rule conditions. Phase A produces the *evidence*
  for tuning (A4); tuning is Phase B.

**(d)** The `data`-out-of-scope `NameError` disappears with the rewrite; keep a named
regression test so it is demonstrably closed rather than incidentally closed.

**(e)** `combo_analyze` builds `summary` from `dict(jr.summary)` and overlays; split
`ghidra_run` into `ghidra_available` / `ghidra_attempted` / `ghidra_ok`.

### A3 — Safe corpus runner

New `tools/corpus_run.py`. **Reuses `harvest_dataset.py`'s unzip-one-at-a-time *pattern* but
not the function** — `unpack_and_harvest` globs `*.apk` (misses 45%), takes `apks[0]` only,
and `extractall`s the whole archive. Reusing it would silently analyse ~120 of ~350 samples
with nobody noticing. Instead the pyzipper→zipfile fallback ladder is refactored into a
shared `open_encrypted(zip_path)` in `harvest_dataset.py` that both callers use.

- **APK detection by magic, not extension** — `PK\x03\x04`, plus `AndroidManifest.xml` and
  ≥1 `classes*.dex`. *This is the check that catches the 45% silent-skip.*
- **Stream one member at a time** — `zf.open(member)` → temp dir → L0 → L1 →
  `shutil.rmtree` in a `finally`. **Never `extractall`.**
- **Temp dir is `corpus/_work/`, not `/tmp`** — `/tmp` is tmpfs on Fedora and would consume RAM.
- **Disposal policy.** Observed blowup: Notely 21 MB → 411 MB (~20×). At 5× on 1.56 GB that
  is ~8 GB against 15 GB free; at 20× it is fatal.
  `--keep-sources {none,failed,flagged}` **default `none`**; deletion in a `finally` inside
  the function that created the tree; pre-flight and between-sample free-space guard
  (`--min-free-gb`, default 5).
- **Resumability without extraction** — `corpus/run_index.json` keyed by
  `(zip_relpath, member_name, member_crc32)`. CRC-32 is in the zip central directory and
  readable **without decrypting**, so a resumed run skips completed members without touching
  a malware byte. Secondary check invalidates on `ruleset_version` change.
- **No execution, enforced by construction** — nothing is ever `chmod +x`'d or invoked. The
  only code touching sample bytes is `androguard.APK()`, `zipfile`, `yara`, and jadx-under-JVM.
- **Timeouts** — jadx 600 s → 180 s for corpus runs; per-sample wall-clock guard.
- **Sequential by default**, `--jobs N` opt-in; binding constraint is disk, not CPU.
- **Password probe pass** before the full run — try decrypting 16 bytes of one member per
  zip, report which archives reject `infected`.
- Per-sample record appended to `corpus/runs/<ts>/run_log.jsonl` (append-only, crash-safe).

### A4 — Rule-firing report

`tools/rule_firing_report.py` reads **the spines, not raw artifacts** — making A4 the first
real consumer of A1 and validating the spine contract by using it.

Per rule: `mal_hits`, `mal_rate`, `ben_hits`, `ben_rate`, `discrimination`, and a
**Jeffreys-smoothed log-odds** `log((m+0.5)/(M−m+0.5)) − log((b+0.5)/(B−b+0.5))`.
**That log-odds is the L5 additive weight — computed rather than asserted.**

> **Honesty requirement.** `B = 4` benign apps. A rule with `ben_hits = 0` gets a large
> apparent log-odds that `n=4` cannot support. The report **must** print a Jeffreys 95%
> interval on `ben_rate` and mark any weight from `B < 30` as `unsupported (n_benign=4)`.

Three free, actionable extra columns:
- **Dead rules** — fired on nothing. Disambiguate "not in corpus" from "condition broken by
  `_strip_byte_checks`" by also running each rule **unstripped** against raw `classes.dex`;
  fires on dex but never on stripped source ⇒ flag `stripped_broken`.
- **Degenerate rules** — fired on ~100% of both classes.
- **Scope split** — validates A2(b) landed.

Header must state the **2020–2022 vintage caveat**.

### A5 — India inject-list test

**Both a generated YARA rule and a standalone grep.**

The generated rule (`tools/gen_india_target_rules.py` →
`L1/yara_templates/generated/apk_india_target_list.yar`) is primary: it rides the existing
scan path, lands in the spine automatically, and A4 counts it like any other rule. Each
`$pkg_NN` maps 1:1 to a whitelist entry, so per-package granularity survives in
`detail.matched_string_ids`.

The standalone `tools/india_inject_scan.py` (~80 lines) exists because the artifact shown to
a judge is a table of *sample → matched entity → file → surrounding source line*, and that
needs line context a YARA finding does not carry.

**Hit tiers — the negatives matter as much as the positives:**

| Tier | Criterion |
|---|---|
| **T1 strong** | Exact whitelist `package_name` literal in source/dex strings, in a file **not** under `_EXCLUDE_SOURCE_PREFIXES` |
| **T2 medium** | ≥3 distinct Indian bank/UPI package names **in the same file** — an inject list is a *list*; one package is coincidence |
| **T3 weak** | Whitelist `bank_name`/`alt_labels` text, Indian sender IDs (`SBIINB`, `HDFCBK`, `BOIIND`), or `upi://` |
| **not a hit** | match only under `androidx/`, `com/google/`, `kotlin/`; or partial substring |

**Priority order:** `novTargetedIndianBanks` → `mayJioTarget` → `fakeAarogyaSetu` →
`marchAlienBot` → the 11 Cerberus/Anubis archives → Medusa/Sharkbot/BRATA/Vultur/TeaBot.

> **Documented failure mode:** Anubis/Cerberus/Alien often fetch the inject list from C2 at
> runtime or store it XOR/Base64-encoded. Static grep then finds nothing. **If the result is
> zero hits, the report says zero hits** and it goes in PROJECT_LOG. The fallback — a clearly
> labelled synthetic positive — must never be produced silently.

---

## 2. Ordering & dependencies

```
Step 0  Prereqs — pip install pyzipper; freeze tests/baseline/pre_A2/;
        correct PROJECT_LOG N1; password probe pass
Step 1  A2.0 trivial independent fixes (scope filter N3, combo summary,
        ghidra unavailable signal, androguard loguru silence)
Step 2  A1a schema + spine.py contract          ∥ Step 1
Step 3  A2.1 finding-model rewrite              ← LONG POLE
        ⚠ MEASUREMENT GATE: per-file Notely < 30 s, else two-pass
Step 4  A2.2 _SEV_MAP case fix                  ← MUST follow Step 3
Step 5  A1b wire l1.py + jadx/combo into spine
Step 6  A5a rule generation  ∥  A4 report code  ← A5a MUST precede Step 7
Step 7  A3 corpus_run.py — smoke on 3 zips, then full run (~90 min)
Step 8  A4 report run  ∥  A5b india_inject_scan
Step 9  Regression check vs tests/baseline/pre_A2
```

**Hard constraints:** A2.1 before A3 (else 90 min produces findings you throw away) ·
A5a before A3 (else India rules absent from the corpus run) · A2.2 after A2.1.

---

## 3. Test plan — falsifiable predictions

Freeze `tests/baseline/pre_A2/<sha>.json` **before touching `yara_scan.py`**.

| Sample | sha | Now | Predicted | Reasoning |
|---|---|---|---|---|
| Proton Lumo | `b1617603` | 11 | **4** | All 7 `yara_apk` findings vanish — every one is from a `scope="source"` rule. **Strongest single check.** |
| PennyWise | `1256daaa` | 10 | **5–6** | Overlay/Ransomware/Dropper need co-located string groups — should die under per-file. Clipboard dies on Base58Check. |
| Notely | `ae1ce24a` | 3 | **2–3** | Clipboard likely dies on wallet validation. |
| DuckAssist | `b4df57d5` | 3 | **3** | Tight single-file OWASP rules. **Must not change.** |
| InsecureBankv2 | `b18af2a0` | 3 | **3** | **Must not change.** |
| PIVAA | `57887e1d` | 6 | **5** | Dropper_Stage1 dies under per-file. |
| UnCrackable L1 | `1da8bf57` | 1 | **1** | **Must not change.** |
| UnCrackable L2 | `4c7980ef` | 0 | **0** | **Must not regress upward.** |

**A2 pass criterion — deliberately NOT "zero findings on benign".** DuckAssist and Lumo
genuinely do use JS-enabled WebViews; suppressing that would be wrong.

> **Zero *malware-category* findings** (`sms_intercept`, `overlay_attack`,
> `accessibility_abuse`, `c2_communication`, `data_exfiltration`, `ransomware`,
> `native_payload`, `clipboard_hijack`, `phishing_impersonation`) **on all four benign apps.**
> OWASP-hardening findings in `category: other` are expected and correct.

PennyWise currently has 5 such findings. Driving that to 0 while keeping its OWASP findings
is the measurable success of A2.

**Other suites:** spine idempotency · ID stability across runs and under insertion · status
transitions (assert never the string `"pending"`) · debug-tool backcompat on v0.1 and v0.2
spines · `kill -9` atomicity · extensionless-APK detection · corpus hygiene
(`corpus/_work` empty; no stray `.apk`) · disposal (<5 MB artifact growth over 20 samples) ·
resume without decrypting · disk guard · A5 positive control (InsecureBankv2 must be **0**
India hits) and exclusion control.

---

## 4. Open questions for the reviewer

1. **Per-file vs two-pass YARA scanning** — planner recommends per-file with a measurement
   gate but would rather ship two-pass unconditionally than risk a mid-build surprise.
2. **Finding granularity (rule, sample) vs (rule, file)** — must be decided now, because it
   changes L5's contract.
3. **Spine location** — `L0/artifacts/` (zero migration, semantically wrong) vs a new
   top-level `artifacts/`.
4. **Default scope for the 25 unscoped rules** — `source` changes 25 rules at once; a rule
   genuinely needing APK context loses its detection silently until A4's dead-rule column.
5. **`pip install pyzipper`** — 40% of corpus unreadable without it. ✅ *approved*

## 5. Risks

6. `_strip_byte_checks` may already have broken rules in ways per-file scanning exposes as
   total silence. A4's unstripped-dex comparison disambiguates, but Phase B's scope may grow.
7. Severity-fix ordering is fragile — gate A2.2 on the benign malware-category count already
   being 0.
8. **The 4-benign denominator is not fixable in Phase A.** A4's weights will be honest but
   weak. F-Droid bulk download is free and fast if L5 needs better calibration — flagged, not
   smuggled into scope.
9. Zip password may not be `infected` for all 203 archives — probe pass covers it.
10. **Host AV / SELinux quarantine** could silently corrupt samples mid-run. Verify no
    on-access scanner and exclude `corpus/` before the full run.
11. **A5 may legitimately return zero.** Plan commits to reporting that rather than
    manufacturing a positive.
12. **Detonation stays out of Phase A.** The emulator does not boot (B8); that is L2's problem.
