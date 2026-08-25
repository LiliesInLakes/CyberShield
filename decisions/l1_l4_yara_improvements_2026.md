# L1 YARA coverage + repair, and the L4 knowledge base extension

**Date:** 2026-08-16
**Status:** Implemented; working tree left uncommitted for review
**Scope:** 8 new technique rules, 16 over-conjunctive/dead rules repaired, 1
anti-discriminative rule tightened, 9 new structural tests, 8 new L4 KB entries
**Inputs:** `docs/research/yara_new_techniques_2024_2026.md`,
`docs/research/yara_rule_diversification_approaches.md`,
`decisions/decision_yara_improvement.md` (the earlier triage of the same rules)

---

## 0. What to believe from this document

Everything below that is stated as a number was produced by running something,
and the sample it was produced on is named next to it. Two claims are
deliberately **not** made:

1. **These rules are not validated against the benign corpus.** The measurements
   here come from a 188-sample probe (89 malware, 99 benign) plus the 10 local
   test APKs — not the 604-app benign corpus and not the 640-sample malware
   corpus. A 0/99 benign result has a Jeffreys 95% upper bound near 3.7%; it is
   the absence of evidence of a high false-positive rate, not evidence of a low
   one (T24's arithmetic, one denominator down).
2. **No detection-rate improvement at corpus scale is claimed.** The headline
   "37% malware-category detection" figure is unchanged and unmeasured under this
   ruleset. Section 6 lists exactly what has to run to move it.

---

## 1. What was added — `L1/yara_templates/apk_emerging_techniques_2026.yar`

Eight rules, one per technique category in the gap research, included in
`index.yar`.

| Rule | Technique | Category / severity | Condition shape |
|---|---|---|---|
| `Android_ATS_OnDevice_Transfer_Automation` | ATS / on-device fraud | `accessibility_abuse` / Critical | `2 of ($auto*) and 1 of ($fraud*)` |
| `Android_RAT_VNC_Remote_Screen_Control` | VNC remote control | `screen_capture` / Critical | `1 of ($vnc*) and 1 of ($cap*)` |
| `Android_C2_MQTT_Channel` | MQTT C2 | `c2_communication` / High | `2 of ($mqtt*) and 1 of ($ctx*)` |
| `Android_Session_Cookie_Theft` | Cookie / session theft | `data_exfiltration` / High | `1 of ($ck*) and 2 of ($tok*)` |
| `Android_OTP_Theft_NonSMS_Channel` | OTP theft beyond SMS | `notification_abuse` / Critical | `1 of ($src*) and 1 of ($tgt*)` |
| `Android_USSD_Shortcode_Abuse` | USSD abuse | `c2_communication` / High | `1 of ($ussd1,$ussd2,$ussd3) and 2 of ($tel*,$ussd4)` |
| `Android_Dropper_Delayed_Staged_Payload` | Delayed / staged droppers | `native_payload` / High | `1 of ($stage*) and 2 of ($evade*)` |
| `Android_C2_DNS_Over_HTTPS` | DoH C2 | `c2_communication` / High | `2 of ($doh*) and 1 of ($ctx*)` |

Design constraints applied to all eight:

- **Exactly two token groups**, one *capability* and one *context*, using the
  "N of M" idiom from the diversification research rather than `all of them`.
  Enforced by a test, not by intent (`tests/test_yara_emerging_rules.py`).
- **No rule fires on a single primitive.** The research flags MediaProjection,
  Accessibility, CookieManager, NotificationListenerService and DoH as having
  legitimate counterparts, three of them at a ~100% benign base rate (T23/T6).
  In every rule the high-base-rate token sits in the group that is *not*
  sufficient on its own.
- **`scope = "both"`, never `"apk"`.** The container pass takes only
  `scope = "apk"` rules (T28); a behaviour conjunction over a deflated ZIP proves
  nothing, and the last rule allowed to do it scored 82 benign hits to 0 malware
  hits.
- **Bare method/class names only**, so a literal is a substring of both the dex
  invoke operand and the jadx call expression (T22). Tested.
- No `filesize`/`uint32be` gates, no hex strings: both are stripped for the
  source and member passes anyway, and a gate that survives only in the container
  pass is a gate on a scope these rules never reach.

One rule was changed by measurement during authoring:
`Android_Session_Cookie_Theft` originally allowed `addJavascriptInterface` and
`evaluateJavascript` in its context group. That made it fire on **duckAssist**, a
benign WebView assistant in `testing_apps/good_apps/`. Both tokens were replaced
with named session material (`auth_token`, `cookie=`); the rule then measured
2/89 malware, 1/99 benign (from 3/89, 3/99).

---

## 2. What was repaired — 16 dead rules

The A4 report re-run at the start of this session (against the **existing**
1,248 spines, no fresh corpus run needed) confirmed **16 dead rules**, all of
them in the `self_match` class: their conditions fire against their own declared
strings, so the condition syntax was never the problem (T25/B31). The problem is
the shape the earlier triage named — four or five `N of ($group*)` clauses ANDed
together, requiring a whole malware kit inside one dex class.

**Approach chosen: relax in place, not split.**
`decisions/decision_yara_improvement.md` proposed decomposing each dead rule into
two or three new primitives. That is a defensible design, but it creates new
signal names with no measurement history, and A4 prices signals by name — every
split rule would enter L5 as an unmeasured signal while the old name's history
became unreachable. Relaxing in place keeps the signal identity, so the next A4
run produces a genuine before/after on the same row. The split remains available
if a relaxed rule measures badly.

Every repaired condition is now **at most two top-level groups**, enforced by
`test_repaired_rules_use_at_most_two_token_groups`.

| Rule | Before | After |
|---|---|---|
| `Android_Ransomware_Generic_File_Encryption` | `3 of ($enc*) and 2 of ($file*) and 1 of ($note*) and 2 of ($ext*)` | `1 of ($note*) and 2 of ($enc*,$file*,$ext*)` |
| `Android_Ransomware_Locker_Screen` | `3 of ($admin*) and 2 of ($overlay*) and 1 of ($demand*) and 1 of ($pay*)` | `2 of ($admin*,$overlay*) and 1 of ($demand*,$pay*)` |
| `Android_Spyware_SMS_Call_Log_Harvester` | `2 of ($sms*) and 2 of ($call*) and 2 of ($contact*) and 2 of ($exfil*)` | `2 of ($sms*,$call1,$call2,$contact1,$contact2) and 1 of ($exfil*)` |
| `Android_Spyware_Generic_GPS_Surveillance` | `3 of ($loc*) and 2 of ($svc*) and 2 of ($exfil*) and 1 of ($stealth*)` | `2 of ($loc*,$svc*,$exfil*) and 1 of ($stealth*)` |
| `Android_Suspicious_Command_Execution` | `2 of ($exec*) and 1 of ($shell*) and 1 of ($cmd*) and (1 of ($native*) or $hex_elf)` | `1 of ($exec*) and 2 of ($shell*,$cmd*,$native*)` |
| `Android_Fraud_SMS_Subscription_Abuse` | `2 of ($sms*) and 1 of ($premium*) and 1 of ($bill*) and 1 of ($bypass*)` | `1 of ($sms*) and 2 of ($premium*,$bill*,$bypass*)` |
| `Android_Fraud_Click_Jacking_Tapjacking` | `2 of ($tap*) and 2 of ($touch*) and 2 of ($acc*) and 1 of ($spoof*)` | `1 of ($tap*) and 2 of ($acc*,$spoof*,$touch*)` |
| `Android_Evasion_Anti_Analysis_VirtualMachine` | `3 of ($build*) and 2 of ($vm*) and 1 of ($debug*)` | `1 of ($vm*) and 1 of ($build*,$debug*)` |
| `Android_Dropper_Native_Library_Loader` | `2 of ($lib*) and 2 of ($path*) and 2 of ($api*) and 1 of ($extract*) and $hex_elf` | `1 of ($extract*) and 2 of ($lib*,$api*)` |
| `Android_Banking_Zanubis_AccessibilityOverlay` | `(all of ($acc_svc*) or all of ($ws*)) and 2 of ($overlay*) and (any of ($target*) or $hex_ws)` | `(1 of ($target*) or $hex_ws) and 2 of ($acc_svc*,$ws*,$overlay*)` |
| `Android_Banking_TaxiSpy_RAT` | IOC group `and 2 of ($rat*) and 1 of ($bank*)` | IOC group `and 1 of ($rat*,$bank*)` |
| `Android_Banking_Ankara_Stealer` | `2 of ($sms*) and 2 of ($web*) and 2 of ($cred*) and any of ($c2_*)` | `any of ($c2_*) and 2 of ($sms*,$web*,$cred*)` |
| `Android_India_Drinik_ITR_Impersonation` | `2 of ($itr*) and 1 of ($acc*) and (1 of ($drinik*) or 1 of ($fb*))` | `(1 of ($drinik*) or 1 of ($fb*)) and 2 of ($itr*,$acc*)` |
| `Android_India_UPI_Targeting` | `(3 of ($upi*) or 3 of ($bank*)) and 1 of ($upi_str*) and 1 of ($overlay*)` | `(1 of ($pkg*) or 1 of ($bank*)) and 2 of ($upistr*,$overlay*)` |
| `Android_India_SMS_OTP_Stealer` | `2 of ($sms*) and 1 of ($otp*) and 2 of ($india*) and 1 of ($exfil*)` | `2 of ($sms*) and 1 of ($india*,$otp*,$exfil*)` |
| `Android_India_FakeBank_App` | `2 of ($name*) and 2 of ($lure*) and 2 of ($web*)` | `1 of ($name*) and 2 of ($lure*,$web*)` |

### 2.1 Strings removed or narrowed, and why

These were not relaxations — they were tokens that made a group *unconditionally
true*, which is the opposite of what an `N of` clause is for.

| Rule | Token | Problem |
|---|---|---|
| `Android_India_SMS_OTP_Stealer` | `$otp3 = /[0-9]{4,6}/` | Matches any four consecutive digits — a version code, a colour constant. Replaced with `"verification code"`. |
| `Android_India_UPI_Targeting` | `$upi1..5` vs `$upi_str1..3` | 🔴 `3 of ($upi*)` also captured the `$upi_str` group, so the rule's "two groups" were one. Prefixes renamed to `$pkg*` / `$upistr*`. |
| `Android_Fraud_SMS_Subscription_Abuse` | `"900"`, `"909"`, `"806"` | Any three consecutive digits. Replaced with a `smsto` regex, `"shortcode"`, `"premium_number"`. |
| `Android_Ransomware_Locker_Screen` | `$demand4 = "FINE"` | Substring of `ACCESS_FINE_LOCATION`. Replaced with `"pay the fine"`. |
| `Android_Ransomware_Generic_File_Encryption` | `"PAYMENT"`, `"DECRYPT"` | `Cipher.DECRYPT_MODE` puts "DECRYPT" in every class that decrypts anything. |
| `Android_Ransomware_Generic_File_Encryption` | `"BITCOIN"` | **Measured**: fired on 2/99 benign and 0/89 malware — F-Droid apps carry Bitcoin donation addresses. Narrowed to `"bitcoin address"`. |
| `Android_Spyware_SMS_Call_Log_Harvester` | `"NUMBER"`, `"DURATION"`, `"DISPLAY_NAME"` | Bare provider column names, ordinary in any dialer UI class. Removed. |
| `Android_Dropper_Native_Library_Loader` | `lib/armeabi-v7a/` etc. | ZIP directory entries, not strings the loading class holds. |
| `Android_Suspicious_Command_Execution` | `$hex_elf` | Rule is `scope = "both"`, so it never runs on the container, and both other passes strip hex strings. Dead weight. |

### 2.2 Also fixed: the most anti-discriminative rule in the system

`Android_Clipboard_Hijacker` is a separate todo item, not one of the 16 dead
rules — it fires, in the wrong direction. A4: **100/604 benign vs 6/640 malware,
weight −2.97**. Cause: `$upi_id = /[a-zA-Z0-9._-]+@[a-zA-Z]+/`, which matches
every e-mail address in every licence header, plus three unanchored wallet
regexes that match any long alphanumeric run.

Now: wallet patterns are `\b`-anchored, and a UPI VPA must end in a real PSP
handle (`oksbi|okaxis|ybl|paytm|upi|…`). Measured on the probe: benign hits
**3/99 → 1/99**, malware unchanged at 0/89.

---

## 3. Validation — what was actually run

### 3.1 Syntax (all rule files, all three rulesets)

`_compile_rules()`, `_compile_source_rules()` and `_compile_member_rules()` all
compile. This matters because the three rulesets are different textual
transformations of the same files: the first repair pass compiled standalone and
broke `_compile_source_rules()` with `unreferenced string "$path1"` after the
stripper removed the condition that used it.

### 3.2 T25 self-match, every rule in the ruleset

Each rule compiled alone against a buffer of its own declared strings:
**57 of 59 match**. The two that do not are harness artefacts, confirmed by
reading them:

- `APK_Anomalous_No_Certificate` — its condition is `... and not $cert1 and not
  any of ($cert2,$cert3,$cert4)`, so a buffer containing its own strings is
  exactly what it must *not* match.
- `Android_Clipboard_Hijacker` — its second group is regex-only, and the harness
  does not synthesise a matching wallet address.

The eight new rules self-match, and that check is now a test rather than a
scratch script (`test_emerging_rules_self_match_their_own_strings`).

### 3.3 Sample probe — 89 malware, 99 benign, per dex class

Baseline frozen **before** any existing rule was touched (a copy of
`L1/yara_templates/` at session start), then the same 188 samples re-scanned with
the modified ruleset — same seed, same sample list, per-class buffers via the
scanner's own `_dex_class_buffers` (T2/T21), never a whole-blob scan.

Sources: `testing_apps/good_apps/*.apk` (4), `testing_apps/vuln/*.apk` (4), the
two APKs left in the scratchpad from the L2 work, plus 90 malware members read
one at a time from `corpus/malware_raw/` zips and 90 F-Droid benign APKs (no bulk
extraction, no `extractall`, nothing executed).

**Every row that changed:**

| Rule | Before (mal / ben) | After (mal / ben) |
|---|---|---|
| `Android_Clipboard_Hijacker` | 0/89 · 3/99 | 0/89 · **1/99** |
| `Android_Session_Cookie_Theft` | 3/89 · 3/99 | **2/89** · **1/99** |
| `Android_Suspicious_Command_Execution` | **0**/89 · 0/99 | **2/89** · 1/99 |
| `Android_Spyware_Generic_GPS_Surveillance` | **0**/89 · 0/99 | **1/89** · 0/99 |
| `Android_Spyware_SMS_Call_Log_Harvester` | **0**/89 · 0/99 | **1/89** · 0/99 |
| `Android_Ransomware_Generic_File_Encryption` | 0/89 · 0/99 | 0/89 · 2/99 → **0/88 · 0/90 after the `bitcoin address` narrowing** (re-probed separately on the corpus half of the same seed) |

Everything else is byte-identical between the two runs, including all BFSI
primitives and all L0-adjacent structural rules.

Reading of this:

- **Three dead rules came back to life** on malware in a 89-sample probe. At that
  denominator a single hit is 1.1%; this is evidence they are no longer
  *structurally* incapable of firing, not a detection rate.
- The one new benign hit that survives is `Android_Suspicious_Command_Execution`
  on **AdAway**, a hosts-file blocker that genuinely shells out as root. That is
  a correct behavioural match on a benign app — the exact hard-negative class T27
  says F-Droid cannot cover properly.
- **Both ransomware rules are still dead** — 0/88 malware after repair. Their
  condition is no longer the blocker; the ransom-note text they key on is UI
  string data in `resources.arsc`, which the scanner does not extract (§5). This
  item is therefore *partially* addressed and is split accordingly in `todo.md`.
- **Five of the eight new rules did not fire on anything**, malware or benign:
  ATS, VNC, MQTT, USSD, DoH. The corpus vintage is 2020–2022 (`malware_raw`
  caveat in the A4 report) and these are 2024–2026 techniques, so a zero here is
  expected and is *not* evidence the rules work. They are forward-looking
  coverage, and until a 2024+ sample set exists they stay unmeasured.

### 3.4 End-to-end through the real scan path

`L1/engines/yara_scan.py::scan_apk` (the function `L1/l1.py` calls — container
pass with the apk-scoped ruleset, then decompressed members per dex class) run
directly on three local samples:

| Sample | Rules fired |
|---|---|
| `testing_apps/good_apps/org.diekaiju.duckassist_245.apk` | `APK_Valid_Structure_Check`, `Android_WebView_JavaScriptEnabled`, `Android_WebView_JavascriptInterface` — and **not** `Android_Session_Cookie_Theft`, which it matched before the token narrowing |
| `scratchpad/l2test/benign.apk` | `APK_Valid_Structure_Check`, `APK_Anomalous_Multiple_DEX_Files`, `Android_Crypto_WeakAlgorithm`, `Android_SSL_TrustAll` |
| `scratchpad/l2test/sbi_malware.apk` (SBI Quick Support) | `APK_Valid_Structure_Check` only — unchanged by this work; this sample is caught by L0 impersonation, not by L1 |

No new rule fired on either benign APK.

### 3.5 What was NOT run

- **No full corpus run.** `tools/corpus_run.py` over 640 malware + 604 benign is
  a multi-hour job and was deliberately not started.
- **No fresh A4 / weights / calibration.** The A4 run used here reads existing
  spines; it therefore describes the ruleset *before* these changes. No weight in
  `L5/weights/` reflects any rule in this document.
- **`ruleset_version` has moved** (the `.yar` files changed), so `corpus_run`
  will *not* skip samples on resume — which is correct, and also means every
  existing spine is now stamped with a superseded ruleset.
- **No benign false-positive rate is claimed** for any rule here.

### 3.6 Test suite

```
$SENTINEL_PYTHON -m pytest tests/ -q
285 passed in 2.65s
```

276 before this session's tests were added (the "269" in the task brief is
stale), 9 added, 0 failures, 0 skips introduced. The 9 new tests are structural
guards, in `tests/test_yara_emerging_rules.py`:

| Test | Guards against |
|---|---|
| `test_emerging_file_is_included_in_the_index` | a rule file that exists but is never compiled |
| `test_all_three_rulesets_still_compile` | the `unreferenced string` class of breakage |
| `test_emerging_rules_never_reach_the_container_pass` | T28 — behaviour rules at container scope |
| `test_emerging_rules_declare_capitalised_severity_and_known_category` | T11 + T12 |
| `test_no_emerging_rule_fires_on_a_single_primitive` | T6/T23 — exactly two groups required |
| `test_emerging_strings_match_both_dex_and_java_representations` | T22 |
| `test_emerging_rules_self_match_their_own_strings` | T25 |
| `test_repaired_rules_use_at_most_two_token_groups` | B29 regressing back to over-conjunction |
| `test_clipboard_upi_regex_is_anchored_to_a_real_psp_handle` | the −2.97 regex coming back |

---

## 4. L4 knowledge base

`L4/knowledge/build_kb.py` gains a fourth source, `emerging_techniques_2026()`,
with **8 entries** (`source: "emerging_2026"`). The entry schema is unchanged —
`id`, `source`, `title`, `description`, `code_indicators`, `severity`,
`mitre_techniques`, `families` — because `retriever.py` indexes those fields and
nothing else; only the `source` value is new, and `source_counts` gained a key.

Each entry carries the family names from the research report (RatOn, Xenomorph,
SharkBot, Vultur, Hydra, TeaBot/Anatsa, Pegasus-Android, Cookiethief,
Youzicheng, Crocodilus, TrickMo, BankBot YNRK, Flubot, PsiXBot, Godlua,
KYCShadow), the concrete API/library indicators, MITRE Mobile technique ids, and
— deliberately — **the false-positive caveat in the description text**, so a
retrieved entry tells the reasoning trail why the primitive alone means nothing.

KB rebuilt:

```
[build_kb] wrote L4/knowledge/kb.json — 216 entries
(mitre=122, yara=59, curated=27, emerging=8)
```

200 → 216: +8 emerging, +8 `yara_rule` entries auto-parsed from the new rule file.

Retrieval spot-check (`retrieve(query, top_k=3, min_sim=0.15)`), every category
resolves to its own entry:

| Query | Top matches |
|---|---|
| `MediaProjection createVirtualDisplay vnc remote screen control` | `yara:Android_Screen_Recording_RAT` 0.49, `emerging:vnc_remote_control` 0.46 |
| `CookieManager getCookie session token exfiltration` | `yara:Android_Session_Cookie_Theft` 0.41, `emerging:cookie_session_theft` 0.41 |
| `mqtt broker paho subscribe command control` | `emerging:mqtt_c2` 0.43 |
| `ussd short code tel dial getSimOperator` | `emerging:ussd_abuse` 0.45 |
| `DnsOverHttps dns-query cloudflare resolver c2` | `yara:Android_C2_DNS_Over_HTTPS` 0.60, `emerging:doh_c2` 0.53 |
| `accessibility performAction setText transfer beneficiary` | `emerging:ats_on_device_fraud` 0.31 |

Unchanged by design: L4 contributes **zero points** to the score, and retrieval
grounds claims about the threat landscape only — never about this sample's bytes
(T26).

---

## 5. Left undone, on purpose

- **`resources.arsc` string extraction** (`L1/engines/yara_scan.py`). Bank names,
  KYC lures and ransom notes are UI text and live in the resource table, which
  the scanner never opens. `Android_India_FakeBank_App` and both ransomware rules
  are still reading only what a dex class happens to hold. Repairing the
  condition does not repair that; it is a scanner change and its own task.
- **`Android_Banking_TaxiSpy_RAT`, `Android_Banking_Zanubis_AccessibilityOverlay`
  and `Android_Banking_Ankara_Stealer` remain family rules.** Their conditions are
  no longer over-conjunctive, but they are anchored on family-unique IOCs (a
  package name, a C2 IP, `/api/v1/injections/`), and those families are not in
  this corpus. Expect them to stay at 0 hits and do **not** read that as a
  defect — that is what a family rule looks like when the family is absent.
- **No re-fit of weights.** Nothing here may be quoted as a weight or a score.

---

## 6. To actually validate this (recommended follow-up)

In order, roughly 3–4 hours of machine time:

```bash
source source_env.sh

# 1. Re-run both populations under the new ruleset_version. Resume, never --force.
$SENTINEL_PYTHON tools/corpus_run.py --dry-run                      # confirm remaining
$SENTINEL_PYTHON tools/corpus_run.py
$SENTINEL_PYTHON tools/corpus_run.py --corpus-root "$SENTINEL_DATA_ROOT/fdroid/apks" \
                                     --source loose --label benign_fdroid
$SENTINEL_PYTHON tools/corpus_run.py --dry-run                      # remaining must be 0 (T30)

# 2. Re-price every signal, including the 8 new rules and the 16 repaired ones.
$SENTINEL_PYTHON tools/corpus_labels.py build \
    --benign-root "$SENTINEL_DATA_ROOT/fdroid/apks" --benign-id benign_fdroid
$SENTINEL_PYTHON tools/rule_firing_report.py

# 3. Diff against the frozen baseline rather than recollecting.
$SENTINEL_PYTHON tools/compare_measurements.py weights \
    tests/baseline/pre_T28/rule_weights_B604_precontainerfix.json \
    L5/weights/rule_weights_<new>.json
```

Falsifiable predictions, recorded now so the result is a diff:

1. `dead rules` in the A4 report drops from **16** to **at most 12** — the three
   already revived in the probe (command execution, GPS surveillance, SMS/call-log
   harvester) plus, at corpus scale, some of the India rules. The two ransomware
   rules and the three family rules are predicted to stay dead.
2. `Android_Clipboard_Hijacker` moves from **−2.97** to above **−1.0**; its benign
   rate falls from 16.6% to under 5%.
3. `Android_Suspicious_Command_Execution` acquires a **positive** weight, with a
   benign rate under 5% (AdAway-class root utilities are the risk).
4. The four pure-2024+ rules (ATS, VNC, MQTT, DoH) fire on **0** samples of this
   2020–2022 corpus, and that is not a defect.
5. No BFSI primitive's rate moves at all — none of their text changed.

If (1) or (2) miss, the relax-in-place approach was the wrong call for those
rules and the split proposed in `decision_yara_improvement.md` should be tried
instead.

---

## 7. Files touched

```
L1/yara_templates/apk_emerging_techniques_2026.yar   new — 8 rules
L1/yara_templates/index.yar                          + include
L1/yara_templates/apk_ransomware.yar                 2 rules repaired, note strings narrowed
L1/yara_templates/apk_spyware_stalkware.yar          2 rules repaired, 3 column-name tokens removed
L1/yara_templates/apk_suspicious_behaviors.yar       1 rule repaired, $hex_elf removed
L1/yara_templates/apk_adware_fraud.yar               2 rules repaired, digit-prefix tokens replaced
L1/yara_templates/apk_persistence_evasion.yar        1 rule repaired
L1/yara_templates/apk_droppers_loaders.yar           1 rule repaired, $path* removed
L1/yara_templates/apk_banking_trojans.yar            3 family rules repaired
L1/yara_templates/apk_india_banking.yar              4 rules repaired, $upi*/$upi_str* prefix collision fixed
L1/yara_templates/apk_clipboard_notification.yar     UPI/wallet regexes anchored
L4/knowledge/build_kb.py                             + emerging_techniques_2026() source
L4/knowledge/kb.json                                 rebuilt, 200 -> 216 entries
tests/test_yara_emerging_rules.py                    new — 9 structural tests
todo.md                                              YARA section updated to real state
```

Nothing was committed. `corpus/malware_raw/` was read one member at a time and
never extracted in bulk.
