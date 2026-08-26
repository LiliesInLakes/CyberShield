# The 92% detection gap — root-cause analysis

**Measured 2026-08-09** against the 705-sample corpus run and 648 spines.
Status: analysis complete, remediation plan **awaiting review** (no detector touched yet).

---

## 0. First, the question that has to be answered plainly

**No model has been trained.** There is no `L3/` directory, no model artifact of any kind on
disk, and neither `scikit-learn` nor `xgboost` is installed. The 92% false-negative rate is
produced entirely by the YARA rule set. There is no ML component anywhere in the pipeline to
blame or to credit — L3 remains unbuilt, exactly as CLAUDE.md §1 states.

---

## 1. What the gap is not

**It is not failed decompilation.** This was the leading hypothesis and the data rejects it:

| Decompilation | Samples | With ≥1 malware-category finding |
|---|---:|---:|
| complete | 392 | 20 (**5%**) |
| partial | 259 | 30 (**12%**) |

Detection is *higher* on partially-decompiled samples. Detection also rises with the amount of
source recovered (7% → 3% → 9% → **24%** across file-count buckets), which is the opposite of
"we cannot see the code". Decompilation coverage is a **confounder for A4's weights**, not the
cause of the gap.

---

## 2. P1 — the dominant cause: every behaviour rule is gated on ZIP magic, so none of
them can match the dex

Every malware-behaviour rule carries a container gate:

```
condition: filesize < 20MB and uint32be(0) == 0x504B0304 and (…behaviour strings…)
```

There are exactly three places the scanner looks, and the gate is fatal in all three:

| Scan target | ZIP magic? | Behaviour strings visible? | Result |
|---|---|---|---|
| Raw APK container | ✅ passes | ❌ **deflated — invisible** (T3) | cannot match |
| `classes*.dex` (decompressed) | ❌ **fails** (`dex\n035`) | ✅ **present in plaintext** | **short-circuits false** |
| Decompiled `.java` | gate stripped | ✅ present, but scattered | see P2 |

**Direct proof.** One confirmed India-targeted banking trojan (`sepTaxPayer.zip`, ICICI
`iMobile` clone, SMS trifecta declared). The strings are unambiguously present:

```
SmsManager        container=False  dex=True
getMessageBody    container=False  dex=True
createFromPdu     container=False  dex=True
sendTextMessage   container=False  dex=True
```

The same trivial rule, with and without the gate the shipped rules carry:

| Target | `uint32be(0)==0x504B0304 and 2 of them` | `2 of them` |
|---|---|---|
| raw container | False | False |
| **classes.dex** | **False** | **True** |
| AndroidManifest.xml | False | False |

The evidence is sitting in the dex and the gate forbids looking at it. Against the **real**
shipped rule set, only 2 rules fire on that dex; with byte gates stripped, 3 — and corpus-wide
the difference is far larger (§4).

> T1 recorded that `uint32(0)` was byte-reversed and "63% of the rule set was dead". Fixing the
> endianness turned a never-true condition into a sometimes-true one — but *sometimes-true only
> on the container*, which is precisely where the strings cannot be seen. **The rule set went
> from dead to structurally blind.**

## 3. P2 — per-file source scanning vs whole-app rule authorship

The rules were authored to evaluate against a whole application. T2 (correctly) replaced
500-file batch blobs with per-file scanning, because batching let
`3 of ($wm*) and 2 of ($phish*) and 1 of ($target_pkg*)` be satisfied by strings scattered
across unrelated files — a 100% false-positive rate on benign apps.

That fix changed the evaluation unit from "the app" to "one `.java` file", and multi-group
conditions rarely survive it. Measured over the rule set:

| | Rules | Mean AND-ed groups per condition |
|---|---:|---:|
| Rules that fired somewhere | 23 | 3.0 |
| **Rules that never fired** | **20** | **4.2** |

**These two facts are in tension and the resolution is the dex.** `classes.dex` is a single
file containing the whole application's string table — app-level aggregation *by construction*,
with no cross-app contamination. It gives the rules the scope they were written for without
reintroducing the failure T2 fixed.

## 4. Measured upside of the proposed change

60 samples drawn at random across archives, scanning `classes*.dex`, shipped rules vs the same
rules with container gates removed:

| | Shipped | Gates stripped |
|---|---:|---:|
| **Samples with ≥1 malware-category hit** | 18 / 60 (**30%**) | **36 / 60 (60%)** |
| Distinct rules firing | 10 | **26** |

Per category (hit counts):

| Category | Shipped | Stripped |
|---|---:|---:|
| native_payload | 0 | **41** |
| c2_communication | 3 | **29** |
| overlay_attack | 0 | **15** |
| data_exfiltration | 0 | **12** |
| ransomware | 0 | **8** |
| accessibility_abuse | 0 | **4** |
| sms_intercept | 0 | **1** |
| clipboard_hijack | 16 | 16 |

16 rules are unlocked, including every previously-dead class the corpus should have tripped:
`Android_Ransomware_Generic_File_Encryption`, `Android_Banking_Generic_OverlayEngine`,
`Android_Dropper_Encrypted_Payload_Stage1`, `Android_Spyware_Keylogger_Credential_Theft`.

> **Honest caveat, and it matters:** `sms_intercept` goes 0 → **1**. The dex fix is necessary
> but **not sufficient** for the single most important category in a BFSI threat model. Those
> rules have an independent authoring defect and will not be fixed by scan-target changes.

## 5. P3 — rule metadata is still half-missing

Of 43 rules: **18 have no `category` meta** and **16 have no `scope` meta**.

Category-less rules fall back to a name-regex catalogue, and most land in `other` — which is
excluded from the malware-category count. So a rule can fire and still be invisible to the
metric. This is T12 only partially fixed: A2 annotated 5 rules and left the rest.

`scope`-less rules are kept in **both** rulesets by `_filter_scope`, so they are compiled into
the APK path where — per P1 — they cannot match anyway.

## 6. Ranked pain points

| # | Cause | Evidence | Fix cost |
|---|---|---|---|
| **P1** | Container gate (`uint32be`/`filesize`) forbids matching the dex, where the strings are | 30%→60% measured | **Low** |
| **P2** | Per-file `.java` scanning cannot satisfy whole-app conditions | dead rules 4.2 vs 3.0 AND-groups | Low (same fix as P1) |
| **P3** | 18/43 rules have no `category`; 16/43 no `scope` | rule-set scan | Low |
| **P4** | `sms_intercept` / `accessibility_abuse` rule *content* is wrong for this corpus | 0→1 even after P1 | **Medium — authoring** |
| P5 | 3.8% of samples die at L0 on `ResParserError` (B26) | 25/705 | Medium |
| P6 | 40% partial decompilation confounds A4's weights | 259/651 | Medium |

---

## 7. Recommendation on rebuilding L0–L2

**Do not rebuild L0.** It is the one measurably working layer: 12/12 India-targeted samples
flagged with a named entity, **0/4 benign false positives**, certificate anomalies 8/8 vs 0/4.
Rewriting it would destroy validated behaviour to fix a defect that lives in L1. Fix only its
robustness gap (P5).

**Do not rewrite L1's code.** Its plumbing is correct and tested — spine integration, structural
cross-scope dedup, per-file scanning, severity/category mapping, ruleset versioning. **The
defect is the scan-target model and the rule metadata, not the engine.** A rewrite would
re-litigate T1–T3, T11 and T12, every one of which was paid for once already.

**L2 has nothing to preserve** — the AVD does not boot (T14) and no dynamic analysis has ever
run. When it is picked up it is a green-field build, which is already the plan.

## 8. Proposed remediation (Phase B1) — **not yet implemented**

Per the working agreement this touches detectors, so it needs a frozen baseline and review
before any code.

1. **Freeze `tests/baseline/pre_B1/`** — current spines for the 4 benign + 4 vuln + 12 India
   samples.
2. **Add the dex as a first-class scan target** with container gates stripped, reusing the
   existing `_strip_byte_checks` path. One change, the entire P1/P2 upside.
3. **Give all 43 rules explicit `scope` and `category` meta.** Mechanical; closes P3.
4. **Re-validate the benign set immediately.** Arming a path that never executed *will* produce
   false positives — that is exactly how T7 and B12 were caught. The pass criterion is
   unchanged and non-negotiable: **0 malware-category findings on the 4 benign apps.**
5. **Re-run the corpus** (~57 min) and re-measure the gap.
6. **Then, separately, the `sms_intercept` rule class (P4)** — authoring work against real
   samples, which no scan-target change will do for us.

**Falsifiable predictions**, to be checked rather than assumed:

- Corpus malware-category detection: **8% → 45–60%**.
- Benign malware-category findings: **0 → 0**. If this breaks, step 2 is wrong and stops.
- `sms_intercept` remains **< 5%** until P4 is done separately.
- Dead rules: 20 → fewer than 8.
